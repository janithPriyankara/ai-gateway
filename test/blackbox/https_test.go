package blackbox

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// spec: DEP-010, DEP-014, DEP-015
func TestLocalHTTPS(t *testing.T) {
	if os.Getenv("GW_BLACKBOX_URL") != "" {
		t.Skip("needs to start its own process")
	}
	dir := t.TempDir()
	addr := freePort()
	_, port, _ := net.SplitHostPort(addr)
	env := append(os.Environ(), "GW_LISTEN="+addr, "GW_DATA_DIR="+dir, "GW_TLS=local", "GW_KEY_PROVIDER=env",
		"GW_MASTER_KEY="+output(binPath, "keygen", "master"))

	cmd := exec.Command(binPath, "serve")
	cmd.Env = env
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() }()
	sc := bufio.NewScanner(stderr)
	setup := ""
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && sc.Scan(); {
		if m := regexp.MustCompile(`url="?(\S+/admin/setup\?token=[^"\s]+)`).FindStringSubmatch(sc.Text()); m != nil {
			setup = m[1]
			break
		}
	}
	go io.Copy(io.Discard, stderr)
	if !strings.HasPrefix(setup, "https://localhost:"+port+"/") {
		t.Fatalf("setup link should use https://localhost: %q", setup)
	}

	// gw trust --print gives the CA file that clients add (DEP-015).
	trust := exec.Command(binPath, "trust", "--print")
	trust.Env = env
	out, err := trust.Output()
	if err != nil {
		t.Fatalf("trust --print: %v", err)
	}
	pemBytes, err := os.ReadFile(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("trust --print did not point at a PEM CA")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	base := "https://localhost:" + port

	var resp *http.Response
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if resp, err = client.Get(base + "/readyz"); err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
	}
	if err != nil {
		t.Fatalf("https readyz: %v", err)
	}
	resp, err = client.Get(base + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Resource string   `json:"resource"`
		AS       []string `json:"authorization_servers"`
	}
	json.NewDecoder(resp.Body).Decode(&meta)
	resp.Body.Close()
	if meta.Resource != base+"/mcp" || len(meta.AS) != 1 || meta.AS[0] != base {
		t.Fatalf("metadata should advertise https URLs: %+v", meta)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatal("not served over TLS 1.2+")
	}

	// A client that does not trust the local CA is refused, and so is TLS 1.1.
	if _, err := http.Get(base + "/healthz"); err == nil {
		t.Fatal("an untrusting client connected")
	}
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MaxVersion: tls.VersionTLS11}}}
	if _, err := old.Get(base + "/healthz"); err == nil {
		t.Fatal("TLS 1.1 was accepted")
	}

	// The container health probe follows the TLS setting (DEP-014).
	hc := exec.Command(binPath, "healthcheck")
	hc.Env = env
	if b, err := hc.CombinedOutput(); err != nil {
		t.Fatalf("healthcheck over https: %v %s", err, b)
	}
}
