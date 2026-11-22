package keybox

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Strength describes how well a provider protects the master key.
type Strength string

const (
	StrengthLow    Strength = "low"
	StrengthMedium Strength = "medium"
	StrengthStrong Strength = "strong"
)

// Provider holds a master key and wraps/unwraps data keys with it (KEY-004).
// Cloud KMS or Vault providers implement the same interface and never expose the KEK.
type Provider interface {
	Name() string
	Strength() Strength
	Wrap(ctx context.Context, dek []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
	Health(ctx context.Context) error
}

// Config carries provider settings. Unused fields are ignored by each provider.
type Config struct {
	DataDir         string
	Passphrase      string
	KeyFile         string
	KeychainAccount string
	DisableKeychain bool
}

// Factory builds a provider.
type Factory func(ctx context.Context, cfg Config) (Provider, error)

var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

// Register adds a provider factory under name, replacing any existing one.
func Register(name string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[name] = f
}

// Providers lists registered provider names.
func Providers() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Open builds the named provider.
func Open(ctx context.Context, name string, cfg Config) (Provider, error) {
	regMu.RLock()
	f, ok := registry[name]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("keybox: unknown key provider %q (available: %s)", name, strings.Join(Providers(), ", "))
	}
	return f(ctx, cfg)
}

func init() {
	Register("env", openEnv)
	Register("file", openFile)
	Register("passphrase", openPassphrase)
	Register("macos-keychain", openKeychain)
	Register("linux-tpm", openTPM)
	Register("windows-dpapi", openDPAPI)
	Register("auto", openAuto)
}

// aeadProvider wraps DEKs locally with AES-256-GCM under an in-memory KEK.
type aeadProvider struct {
	name     string
	strength Strength
	kek      []byte
}

var dekWrapAAD = []byte("mcp-gateway/dek/v1")

func newAEADProvider(name string, s Strength, kek []byte) (*aeadProvider, error) {
	if len(kek) != 32 {
		return nil, errors.New("keybox: master key must be 32 bytes")
	}
	return &aeadProvider{name: name, strength: s, kek: append([]byte(nil), kek...)}, nil
}

// NewStaticProvider returns a provider around an in-memory 32-byte KEK.
// Intended for tests and for building custom providers.
func NewStaticProvider(name string, s Strength, kek []byte) (Provider, error) {
	return newAEADProvider(name, s, kek)
}

func (p *aeadProvider) Name() string       { return p.name }
func (p *aeadProvider) Strength() Strength { return p.strength }

func (p *aeadProvider) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	gcm, err := newGCM(p.kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, dekWrapAAD), nil
}

func (p *aeadProvider) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	if len(wrapped) < nonceSize+16 {
		return nil, ErrDecrypt
	}
	gcm, err := newGCM(p.kek)
	if err != nil {
		return nil, ErrDecrypt
	}
	dek, err := gcm.Open(nil, wrapped[:nonceSize], wrapped[nonceSize:], dekWrapAAD)
	if err != nil {
		return nil, ErrDecrypt
	}
	return dek, nil
}

func (p *aeadProvider) Health(ctx context.Context) error {
	probe := make([]byte, dekSize)
	w, err := p.Wrap(ctx, probe)
	if err != nil {
		return err
	}
	_, err = p.Unwrap(ctx, w)
	return err
}

// passphraseProvider adds a verifier so a wrong passphrase is detected (KEY-005).
type passphraseProvider struct {
	*aeadProvider
	check []byte
}

func (p *passphraseProvider) Health(ctx context.Context) error {
	if _, err := p.Unwrap(ctx, p.check); err != nil {
		return errors.New("keybox: passphrase does not match this data directory")
	}
	return nil
}

func decodeKey(raw []byte) ([]byte, error) {
	if len(raw) == 32 {
		return raw, nil
	}
	s := strings.TrimSpace(string(raw))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	return nil, errors.New("keybox: master key must be 32 raw bytes or base64 of 32 bytes")
}

func openEnv(_ context.Context, _ Config) (Provider, error) {
	v := os.Getenv("GW_MASTER_KEY")
	if v == "" {
		return nil, errors.New("keybox: GW_MASTER_KEY is not set")
	}
	k, err := decodeKey([]byte(v))
	if err != nil {
		return nil, err
	}
	return newAEADProvider("env", StrengthMedium, k)
}

func openFile(_ context.Context, cfg Config) (Provider, error) {
	path := cfg.KeyFile
	if path == "" {
		path = os.Getenv("GW_MASTER_KEY_FILE")
	}
	if path == "" {
		return nil, errors.New("keybox: no key file configured (GW_MASTER_KEY_FILE)")
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("keybox: key file: %w", err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("keybox: key file %s is accessible by other users; run: chmod 600 %s", path, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keybox: key file: %w", err)
	}
	k, err := decodeKey(raw)
	if err != nil {
		return nil, err
	}
	return newAEADProvider("file", StrengthMedium, k)
}

// argon2id parameters (OWASP recommended minimums exceeded).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
)

func openPassphrase(ctx context.Context, cfg Config) (Provider, error) {
	pass := cfg.Passphrase
	if pass == "" {
		pass = os.Getenv("GW_PASSPHRASE")
	}
	if pass == "" {
		return nil, errors.New("keybox: passphrase is empty (set GW_PASSPHRASE)")
	}
	if cfg.DataDir == "" {
		return nil, errors.New("keybox: passphrase provider needs a data directory")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	saltPath := filepath.Join(cfg.DataDir, "keybox.salt")
	checkPath := filepath.Join(cfg.DataDir, "keybox.check")
	salt, err := os.ReadFile(saltPath)
	fresh := false
	if errors.Is(err, os.ErrNotExist) {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		if err := os.WriteFile(saltPath, salt, 0o600); err != nil {
			return nil, err
		}
		fresh = true
	} else if err != nil {
		return nil, err
	}
	kek := argon2.IDKey([]byte(pass), salt, argonTime, argonMemory, argonThreads, 32)
	ap, err := newAEADProvider("passphrase", StrengthMedium, kek)
	zero(kek)
	if err != nil {
		return nil, err
	}
	p := &passphraseProvider{aeadProvider: ap}
	if fresh {
		check, err := ap.Wrap(ctx, make([]byte, dekSize))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(checkPath, check, 0o600); err != nil {
			return nil, err
		}
		p.check = check
		return p, nil
	}
	p.check, err = os.ReadFile(checkPath)
	if err != nil {
		return nil, fmt.Errorf("keybox: missing %s: %w", checkPath, err)
	}
	if err := p.Health(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func openAuto(ctx context.Context, cfg Config) (Provider, error) {
	var tried []string
	if runtime.GOOS == "darwin" && !cfg.DisableKeychain {
		if p, err := openKeychain(ctx, cfg); err == nil {
			return p, nil
		} else {
			tried = append(tried, "macos-keychain: "+err.Error())
		}
	}
	if cfg.KeyFile != "" || os.Getenv("GW_MASTER_KEY_FILE") != "" {
		return openFile(ctx, cfg)
	}
	if runtime.GOOS == "windows" && !cfg.DisableKeychain {
		if p, err := openDPAPI(ctx, cfg); err == nil {
			return p, nil
		} else {
			tried = append(tried, "windows-dpapi: "+err.Error())
		}
	}
	if runtime.GOOS == "linux" && os.Getenv("GW_ENABLE_TPM") == "1" {
		if p, err := openTPM(ctx, cfg); err == nil {
			return p, nil
		} else {
			tried = append(tried, "linux-tpm: "+err.Error())
		}
	}
	if os.Getenv("GW_MASTER_KEY") != "" {
		return openEnv(ctx, cfg)
	}
	if cfg.Passphrase != "" || os.Getenv("GW_PASSPHRASE") != "" {
		return openPassphrase(ctx, cfg)
	}
	tried = append(tried, "file: GW_MASTER_KEY_FILE not set", "env: GW_MASTER_KEY not set", "passphrase: GW_PASSPHRASE not set")
	return nil, fmt.Errorf("keybox: no key provider available; tried: %s", strings.Join(tried, "; "))
}
