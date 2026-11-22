package keybox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newEnvBox(t *testing.T) (*Box, []byte) {
	t.Helper()
	k := testKey(t)
	t.Setenv("GW_MASTER_KEY", base64.StdEncoding.EncodeToString(k))
	p, err := Open(context.Background(), "env", Config{})
	if err != nil {
		t.Fatal(err)
	}
	return New(p), k
}

// spec: KEY-001
func TestSealOpenRoundTrip(t *testing.T) {
	b, _ := newEnvBox(t)
	ctx := context.Background()
	blob, err := b.Seal(ctx, []byte("ghp_secret_token"), []byte("user1|github"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := b.Open(ctx, blob, []byte("user1|github"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "ghp_secret_token" {
		t.Fatalf("got %q", pt)
	}
	if bytes.Contains(blob, []byte("ghp_secret_token")) {
		t.Fatal("ciphertext contains plaintext")
	}
}

// spec: KEY-002
func TestFreshDEKAndNonce(t *testing.T) {
	b, _ := newEnvBox(t)
	ctx := context.Background()
	a, _ := b.Seal(ctx, []byte("same"), nil)
	c, _ := b.Seal(ctx, []byte("same"), nil)
	if bytes.Equal(a, c) {
		t.Fatal("two seals of the same plaintext must differ")
	}
	wa, _, _, _ := parse(a)
	wc, _, _, _ := parse(c)
	if bytes.Equal(wa, wc) {
		t.Fatal("each seal must use a fresh DEK")
	}
}

// spec: KEY-003
func TestTamperDetection(t *testing.T) {
	b, _ := newEnvBox(t)
	ctx := context.Background()
	blob, _ := b.Seal(ctx, []byte("secret"), []byte("alice|github"))
	if _, err := b.Open(ctx, blob, []byte("bob|github")); err == nil {
		t.Fatal("opening with another owner's AAD must fail")
	}
	for i := 0; i < len(blob); i++ {
		c := bytes.Clone(blob)
		c[i] ^= 0x01
		if _, err := b.Open(ctx, c, []byte("alice|github")); err == nil {
			t.Fatalf("flipping byte %d went undetected", i)
		}
	}
	if _, err := b.Open(ctx, blob[:5], nil); err == nil {
		t.Fatal("truncated blob must fail")
	}
}

// spec: KEY-004
func TestRegistry(t *testing.T) {
	names := Providers()
	for _, want := range []string{"env", "file", "passphrase", "macos-keychain", "auto"} {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Errorf("provider %q not registered (have %v)", want, names)
		}
	}
	Register("test-fake", func(ctx context.Context, c Config) (Provider, error) {
		return newAEADProvider("test-fake", StrengthLow, testKey(t))
	})
	p, err := Open(context.Background(), "test-fake", Config{})
	if err != nil || p.Name() != "test-fake" || p.Strength() != StrengthLow {
		t.Fatalf("custom provider: %v %v", p, err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), "does-not-exist", Config{}); err == nil {
		t.Fatal("unknown provider must error")
	}
}

// spec: KEY-005
func TestPassphraseProvider(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	p, err := Open(ctx, "passphrase", Config{DataDir: dir, Passphrase: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Strength() != StrengthMedium {
		t.Errorf("strength %s", p.Strength())
	}
	box := New(p)
	blob, _ := box.Seal(ctx, []byte("s3cret"), nil)

	// Same passphrase in a later process works.
	p2, err := Open(ctx, "passphrase", Config{DataDir: dir, Passphrase: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := New(p2).Open(ctx, blob, nil); err != nil || string(pt) != "s3cret" {
		t.Fatalf("reopen: %q %v", pt, err)
	}
	// Wrong passphrase fails health and unwrap.
	p3, err := Open(ctx, "passphrase", Config{DataDir: dir, Passphrase: "wrong"})
	if err == nil {
		if p3.Health(ctx) == nil {
			t.Fatal("wrong passphrase must fail health")
		}
		if _, err := New(p3).Open(ctx, blob, nil); err == nil {
			t.Fatal("wrong passphrase must fail to open")
		}
	}
	// Salt is stored, key is not.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if bytes.Contains(data, []byte("correct horse")) {
			t.Fatalf("passphrase leaked into %s", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "keybox.salt")); err != nil {
		t.Fatal("salt file missing")
	}
	if _, err := Open(ctx, "passphrase", Config{DataDir: dir}); err == nil {
		t.Fatal("empty passphrase must be rejected")
	}
}

// spec: KEY-006
func TestFileProvider(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	k := testKey(t)
	path := filepath.Join(dir, "master.key")
	if err := os.WriteFile(path, k, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Open(ctx, "file", Config{KeyFile: path})
	if err != nil {
		t.Fatal(err)
	}
	box := New(p)
	blob, _ := box.Seal(ctx, []byte("x"), nil)
	if _, err := box.Open(ctx, blob, nil); err != nil {
		t.Fatal(err)
	}
	// base64-encoded key files are accepted too.
	b64 := filepath.Join(dir, "b64.key")
	_ = os.WriteFile(b64, []byte(base64.StdEncoding.EncodeToString(k)+"\n"), 0o600)
	if _, err := Open(ctx, "file", Config{KeyFile: b64}); err != nil {
		t.Fatalf("base64 key file: %v", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o644)
		if _, err := Open(ctx, "file", Config{KeyFile: path}); err == nil {
			t.Fatal("world-readable key file must be refused")
		}
	}
	short := filepath.Join(dir, "short.key")
	_ = os.WriteFile(short, []byte("tooshort"), 0o600)
	if _, err := Open(ctx, "file", Config{KeyFile: short}); err == nil {
		t.Fatal("short key must be refused")
	}
}

// spec: KEY-007
func TestEnvProvider(t *testing.T) {
	_, _ = newEnvBox(t)
	p, _ := Open(context.Background(), "env", Config{})
	if p.Strength() != StrengthMedium {
		t.Errorf("env strength = %s, want medium", p.Strength())
	}
	t.Setenv("GW_MASTER_KEY", "not-base64!")
	if _, err := Open(context.Background(), "env", Config{}); err == nil {
		t.Fatal("invalid key must be rejected")
	}
}

// spec: KEY-008
func TestMacOSKeychainProvider(t *testing.T) {
	ctx := context.Background()
	if runtime.GOOS != "darwin" {
		if _, err := Open(ctx, "macos-keychain", Config{}); err == nil {
			t.Fatal("macos-keychain must be unavailable off macOS")
		}
		return
	}
	if os.Getenv("GW_TEST_KEYCHAIN") != "1" {
		t.Skip("set GW_TEST_KEYCHAIN=1 to touch the real login keychain")
	}
	account := "test-" + hex.EncodeToString(testKey(t)[:4])
	t.Cleanup(func() { _ = deleteKeychainItem(account) })
	p, err := Open(ctx, "macos-keychain", Config{KeychainAccount: account})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := New(p).Seal(ctx, []byte("kc"), nil)
	p2, err := Open(ctx, "macos-keychain", Config{KeychainAccount: account})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := New(p2).Open(ctx, blob, nil); err != nil || string(pt) != "kc" {
		t.Fatalf("second open did not reuse the stored KEK: %q %v", pt, err)
	}
	if p.Strength() != StrengthStrong {
		t.Errorf("strength %s", p.Strength())
	}
}

// spec: KEY-009
func TestAutoSelection(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GW_MASTER_KEY", "")
	t.Setenv("GW_MASTER_KEY_FILE", "")
	t.Setenv("GW_PASSPHRASE", "")
	cfg := Config{DataDir: t.TempDir(), DisableKeychain: true}
	if _, err := Open(ctx, "auto", cfg); err == nil {
		t.Fatal("auto with nothing available must fail clearly")
	} else if !strings.Contains(err.Error(), "no key provider") {
		t.Errorf("unclear error: %v", err)
	}
	t.Setenv("GW_PASSPHRASE", "pw-pw-pw")
	if p, err := Open(ctx, "auto", cfg); err != nil || p.Name() != "passphrase" {
		t.Fatalf("want passphrase, got %v %v", p, err)
	}
	t.Setenv("GW_MASTER_KEY", base64.StdEncoding.EncodeToString(testKey(t)))
	if p, err := Open(ctx, "auto", cfg); err != nil || p.Name() != "env" {
		t.Fatalf("want env, got %v %v", p, err)
	}
	kf := filepath.Join(t.TempDir(), "k")
	_ = os.WriteFile(kf, testKey(t), 0o600)
	t.Setenv("GW_MASTER_KEY_FILE", kf)
	if p, err := Open(ctx, "auto", cfg); err != nil || p.Name() != "file" {
		t.Fatalf("want file, got %v %v", p, err)
	}
}

// spec: KEY-010
func TestNoKeyMaterialInErrors(t *testing.T) {
	b, k := newEnvBox(t)
	ctx := context.Background()
	blob, _ := b.Seal(ctx, []byte("pt"), []byte("a"))
	_, err := b.Open(ctx, blob, []byte("b"))
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, enc := range []string{hex.EncodeToString(k), base64.StdEncoding.EncodeToString(k), string(k)} {
		if strings.Contains(msg, enc) {
			t.Fatal("error message leaks key material")
		}
	}
	if strings.Contains(msg, "pt") && len(msg) < 4 {
		t.Fatal("suspicious error")
	}
}

// spec: KEY-011
func TestRewrap(t *testing.T) {
	ctx := context.Background()
	oldBox, _ := newEnvBox(t)
	blob, _ := oldBox.Seal(ctx, []byte("rotate me"), []byte("aad"))

	newP, _ := newAEADProvider("new", StrengthStrong, testKey(t))
	newBox := New(newP)
	re, err := oldBox.Rewrap(ctx, blob, newBox)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, ctOld := parse(blob)
	_, _, _, ctNew := parse(re)
	if !bytes.Equal(ctOld, ctNew) {
		t.Fatal("rewrap must not re-encrypt the payload, only the DEK")
	}
	if pt, err := newBox.Open(ctx, re, []byte("aad")); err != nil || string(pt) != "rotate me" {
		t.Fatalf("new box cannot open: %q %v", pt, err)
	}
	if _, err := oldBox.Open(ctx, re, []byte("aad")); err == nil {
		t.Fatal("old KEK must no longer open the rewrapped blob")
	}
}

func BenchmarkSealOpen(b *testing.B) {
	p, _ := newAEADProvider("bench", StrengthStrong, make([]byte, 32))
	box := New(p)
	ctx := context.Background()
	pt := []byte("ghp_0123456789abcdefghijklmnopqrstuvwxyz")
	for i := 0; i < b.N; i++ {
		blob, _ := box.Seal(ctx, pt, nil)
		_, _ = box.Open(ctx, blob, nil)
	}
}

// spec: KEY-012
func TestLinuxTPMProvider(t *testing.T) {
	ctx := context.Background()
	if runtime.GOOS != "linux" {
		if _, err := Open(ctx, "linux-tpm", Config{DataDir: t.TempDir()}); err == nil {
			t.Fatal("linux-tpm must be unavailable off Linux")
		}
		return
	}
	if os.Getenv("GW_TEST_TPM") != "1" {
		t.Skip("set GW_TEST_TPM=1 on a machine with a TPM2 and systemd-creds")
	}
	dir := t.TempDir()
	p, err := Open(ctx, "linux-tpm", Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := New(p).Seal(ctx, []byte("tpm"), nil)
	p2, err := Open(ctx, "linux-tpm", Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := New(p2).Open(ctx, blob, nil); err != nil || string(pt) != "tpm" || p.Strength() != StrengthStrong {
		t.Fatalf("%q %v", pt, err)
	}
}

// spec: KEY-013
func TestWindowsDPAPIProvider(t *testing.T) {
	ctx := context.Background()
	if runtime.GOOS != "windows" {
		if _, err := Open(ctx, "windows-dpapi", Config{DataDir: t.TempDir()}); err == nil {
			t.Fatal("windows-dpapi must be unavailable off Windows")
		}
		return
	}
	dir := t.TempDir()
	p, err := Open(ctx, "windows-dpapi", Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := New(p).Seal(ctx, []byte("dpapi"), nil)
	p2, err := Open(ctx, "windows-dpapi", Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := New(p2).Open(ctx, blob, nil); err != nil || string(pt) != "dpapi" || p.Strength() != StrengthStrong {
		t.Fatalf("%q %v", pt, err)
	}
}
