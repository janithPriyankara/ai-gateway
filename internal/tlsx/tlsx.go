// Package tlsx serves the gateway over HTTPS (DEP-010..015): either with its own
// name-constrained local certificate authority, or with certificate files from disk.
package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TLS modes.
const (
	ModeOff   = "off"
	ModeLocal = "local"
	ModeFiles = "files"
)

const (
	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 90 * 24 * time.Hour
	renewBefore  = 30 * 24 * time.Hour
	reloadEvery  = 5 * time.Second
)

// localNets are the only addresses the local CA may vouch for (DEP-011).
var localNets = []*net.IPNet{
	{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
	{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
}

// IsLocalHost reports whether host is covered by the local CA: localhost, a
// *.localhost name, or a loopback address.
func IsLocalHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CAPath is where the local CA certificate lives; this is the file users trust.
func CAPath(dataDir string) string { return filepath.Join(dataDir, "tls", "ca.crt") }

func caKeyPath(dataDir string) string { return filepath.Join(dataDir, "tls", "ca.key") }

// LocalCA is the gateway's own certificate authority.
type LocalCA struct {
	Cert     *x509.Certificate
	Key      *ecdsa.PrivateKey
	CertPath string
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}

// LoadOrCreateCA loads the CA from dataDir/tls, creating it on first use (DEP-010).
func LoadOrCreateCA(dataDir string, now time.Time) (*LocalCA, error) {
	dir := filepath.Join(dataDir, "tls")
	certPath, keyPath := CAPath(dataDir), caKeyPath(dataDir)
	certPEM, cerr := os.ReadFile(certPath)
	keyPEM, kerr := os.ReadFile(keyPath)
	if cerr == nil && kerr == nil {
		ca, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("local CA in %s is unreadable (%v); delete that folder to create a new one, then run gw trust again", dir, err)
		}
		if now.After(ca.Cert.NotAfter) {
			return nil, fmt.Errorf("local CA in %s expired on %s; delete that folder and run gw trust again", dir, ca.Cert.NotAfter.Format(time.DateOnly))
		}
		ca.CertPath = certPath
		return ca, nil
	}
	if !errors.Is(cerr, os.ErrNotExist) || !errors.Is(kerr, os.ErrNotExist) {
		return nil, fmt.Errorf("local CA in %s is incomplete; delete that folder to create a new one", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "mcp-gateway local CA (" + host + ")", Organization: []string{"mcp-gateway"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// DEP-011: this CA can only ever vouch for local names and addresses.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"localhost"},
		PermittedIPRanges:           localNets,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		return nil, err
	}
	if err := writeFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return &LocalCA{Cert: cert, Key: key, CertPath: certPath}, nil
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func parseCA(certPEM, keyPEM []byte) (*LocalCA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("certificate and key do not match")
	}
	return &LocalCA{Cert: cert, Key: key}, nil
}

// Issue creates a short-lived server certificate for localhost, 127.0.0.1 and ::1 (DEP-012).
func (ca *LocalCA) Issue(now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(leafLifetime)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"mcp-gateway"}},
		DNSNames:     []string{"localhost", "*.localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Options configures ServerConfig.
type Options struct {
	Mode              string
	DataDir           string
	CertFile, KeyFile string
	Now               func() time.Time
}

// ServerConfig returns the TLS configuration for the listener. It fails at startup,
// not at the first handshake, when certificates cannot be loaded.
func ServerConfig(o Options) (*tls.Config, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	switch o.Mode {
	case ModeLocal:
		ca, err := LoadOrCreateCA(o.DataDir, o.Now())
		if err != nil {
			return nil, err
		}
		s := &localSource{ca: ca, now: o.Now}
		if _, err := s.get(); err != nil {
			return nil, err
		}
		cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.get() }
	case ModeFiles:
		s := &fileSource{cert: o.CertFile, key: o.KeyFile, now: o.Now}
		if err := s.load(); err != nil {
			return nil, err
		}
		cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.get() }
	default:
		return nil, fmt.Errorf("unknown TLS mode %q", o.Mode)
	}
	return cfg, nil
}

// localSource issues server certificates and renews them before they expire (DEP-012).
type localSource struct {
	ca   *LocalCA
	now  func() time.Time
	mu   sync.Mutex
	cert *tls.Certificate
}

func (s *localSource) get() (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.cert == nil || now.After(s.cert.Leaf.NotAfter.Add(-renewBefore)) {
		c, err := s.ca.Issue(now)
		if err != nil {
			if s.cert != nil && now.Before(s.cert.Leaf.NotAfter) {
				return s.cert, nil // keep serving the still-valid one
			}
			return nil, err
		}
		s.cert = c
	}
	return s.cert, nil
}

// fileSource serves a certificate from disk and reloads it when the files change (DEP-013).
type fileSource struct {
	cert, key string
	now       func() time.Time
	mu        sync.Mutex
	current   *tls.Certificate
	modTime   time.Time
	checked   time.Time
}

func (s *fileSource) stamp() (time.Time, error) {
	var latest time.Time
	for _, p := range []string{s.cert, s.key} {
		st, err := os.Stat(p)
		if err != nil {
			return time.Time{}, err
		}
		if st.ModTime().After(latest) {
			latest = st.ModTime()
		}
	}
	return latest, nil
}

func (s *fileSource) load() error {
	mt, err := s.stamp()
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	c, err := tls.LoadX509KeyPair(s.cert, s.key)
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	s.current, s.modTime, s.checked = &c, mt, s.now()
	return nil
}

func (s *fileSource) get() (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Sub(s.checked) >= reloadEvery {
		s.checked = s.now()
		if mt, err := s.stamp(); err == nil && !mt.Equal(s.modTime) {
			old := s.current
			if err := s.load(); err != nil {
				s.current = old // a half-written renewal must not take the gateway down
			}
		}
	}
	return s.current, nil
}
