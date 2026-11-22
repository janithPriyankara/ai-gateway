package tlsx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func clock(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func pool(t *testing.T, ca *LocalCA) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

func verify(t *testing.T, ca *LocalCA, leaf *x509.Certificate, host string, at time.Time) error {
	t.Helper()
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool(t, ca), DNSName: host, CurrentTime: at})
	return err
}

// spec: DEP-010
func TestLocalCAIsCreatedOnceAndPrivate(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA || ca.CertPath != CAPath(dir) {
		t.Fatalf("bad CA: %+v", ca.Cert)
	}
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{filepath.Join(dir, "tls"): 0o700, filepath.Join(dir, "tls", "ca.key"): 0o600} {
			st, err := os.Stat(p)
			if err != nil || st.Mode().Perm() != want {
				t.Errorf("%s: mode %v, want %v (%v)", p, st.Mode().Perm(), want, err)
			}
		}
	}
	again, err := LoadOrCreateCA(dir, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Cert.Raw, ca.Cert.Raw) {
		t.Fatal("second start created a new CA; users would have to trust it again")
	}
}

// spec: DEP-011
func TestLocalCAIsNameConstrained(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir(), t0)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := verify(t, ca, cert.Leaf, h, t0); err != nil {
			t.Errorf("%s should verify: %v", h, err)
		}
	}
	// A certificate for another site, signed with the CA key (as an attacker who stole
	// the key would), must not verify.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "bank.example"},
		DNSNames: []string{"bank.example"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &k.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	evil, _ := x509.ParseCertificate(der)
	if err := verify(t, ca, evil, "bank.example", t0); err == nil {
		t.Fatal("the local CA vouched for a non-local site")
	}
	if IsLocalHost("bank.example") || !IsLocalHost("localhost") || !IsLocalHost("gw.localhost") || !IsLocalHost("127.0.0.1") || !IsLocalHost("::1") {
		t.Fatal("IsLocalHost is wrong")
	}
}

// spec: DEP-012, DEP-014
func TestLocalServerCertificateRenews(t *testing.T) {
	now := t0
	cfg, err := ServerConfig(Options{Mode: ModeLocal, DataDir: t.TempDir(), Now: clock(&now)})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("min version %x", cfg.MinVersion)
	}
	get := func() *x509.Certificate {
		c, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf
	}
	first := get()
	if d := first.NotAfter.Sub(first.NotBefore); d > 91*24*time.Hour {
		t.Fatalf("server certificate lives %v, want about 90 days", d)
	}
	now = t0.Add(50 * 24 * time.Hour)
	if get().SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("renewed too early")
	}
	now = t0.Add(65 * 24 * time.Hour)
	renewed := get()
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 || !renewed.NotAfter.After(first.NotAfter) {
		t.Fatal("certificate was not renewed with 25 days left")
	}
}

func writePair(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	kd, _ := x509.MarshalECPrivateKey(k)
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	return cp, kp
}

// spec: DEP-013
func TestFileCertificateReloads(t *testing.T) {
	dir := t.TempDir()
	cp, kp := writePair(t, dir, "one.example")
	now := time.Now()
	cfg, err := ServerConfig(Options{Mode: ModeFiles, CertFile: cp, KeyFile: kp, Now: clock(&now)})
	if err != nil {
		t.Fatal(err)
	}
	name := func() string {
		c, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		return leaf.Subject.CommonName
	}
	if name() != "one.example" {
		t.Fatal("first certificate not served")
	}
	writePair(t, dir, "two.example")
	future := time.Now().Add(time.Minute)
	os.Chtimes(cp, future, future)
	now = now.Add(10 * time.Second)
	if got := name(); got != "two.example" {
		t.Fatalf("replaced certificate not picked up, still %s", got)
	}
	if _, err := ServerConfig(Options{Mode: ModeFiles, CertFile: filepath.Join(dir, "missing.pem"), KeyFile: kp}); err == nil {
		t.Fatal("a missing certificate should fail at startup")
	}
}
