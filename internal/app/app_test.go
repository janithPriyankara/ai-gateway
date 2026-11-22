package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mcp-gateway/mcp-gateway/internal/keybox"
	"github.com/mcp-gateway/mcp-gateway/internal/services/auth"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func masterKey(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	t.Setenv("GW_MASTER_KEY", base64.StdEncoding.EncodeToString(k))
}

// spec: DEP-001, DEP-004
func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"defaults on loopback", Config{Listen: "127.0.0.1:8787"}, true},
		{"public listen without public URL", Config{Listen: "0.0.0.0:8787"}, false},
		{"public listen with public URL", Config{Listen: "0.0.0.0:8787", PublicURL: "https://gw.example.com"}, true},
		{"unknown service", Config{Listen: "127.0.0.1:1", Services: []string{"nope"}}, false},
		{"split without token", Config{Listen: "127.0.0.1:1", Services: []string{"vault"}}, false},
		{"split gateway without remote URLs", Config{Listen: "127.0.0.1:1", Services: []string{"gateway"}, InternalToken: strings.Repeat("x", 32)}, false},
		{"split gateway with URLs", Config{Listen: "127.0.0.1:1", Services: []string{"gateway"}, InternalToken: strings.Repeat("x", 32),
			AuthURL: "http://a", VaultURL: "http://v", ControlURL: "http://c"}, true},
		{"bad public url", Config{Listen: "127.0.0.1:1", PublicURL: "ftp://x"}, false},
	}
	for _, c := range cases {
		err := c.cfg.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
	c := Config{Listen: "127.0.0.1:8787"}
	c.Validate()
	if c.PublicURL != "http://localhost:8787" || len(c.Services) != 4 {
		t.Errorf("defaults: %+v", c)
	}
}

func newAllInOne(t *testing.T) (*App, *httptest.Server, string) {
	masterKey(t)
	admin := auth.NewAdminKeyString()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	a, err := New(context.Background(), Config{Listen: addr, DataDir: t.TempDir(), KeyProvider: "env", BootstrapAdminKey: admin, Logger: quietLogger(), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(a.Handler)
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(func() { srv.Close(); a.Close() })
	return a, srv, admin
}

// spec: DEP-005, DEP-003
func TestHealthAndReadiness(t *testing.T) {
	a, srv, _ := newAllInOne(t)
	for _, p := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, err, resp)
		}
		resp.Body.Close()
	}
	a.Vault.Close() // simulate a broken database
	resp, _ := http.Get(srv.URL + "/readyz")
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("readyz with a closed DB: %d", resp.StatusCode)
	}
	for _, f := range []string{"auth.db", "vault.db", "control.db"} {
		if !strings.Contains(strings.Join(dirNames(t, a.cfg.DataDir), ","), f) {
			t.Errorf("%s not created in data dir", f)
		}
	}
}

func dirNames(t *testing.T, dir string) []string {
	ents, _ := readDir(dir)
	return ents
}

// spec: DEP-002
func TestInternalRoutesRequireToken(t *testing.T) {
	masterKey(t)
	tok := strings.Repeat("s", 40)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	a, err := New(context.Background(), Config{Listen: ln.Addr().String(), DataDir: t.TempDir(), KeyProvider: "env", Services: []string{SvcVault}, InternalToken: tok, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	srv := httptest.NewServer(a.Handler)
	defer srv.Close()
	for _, h := range []string{"", "Bearer wrong", "Bearer " + tok} {
		req, _ := http.NewRequest("POST", srv.URL+"/internal/v1/vault/ListCredentials", strings.NewReader(`{"ServerID":""}`))
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		want := 401
		if h == "Bearer "+tok {
			want = 200
		}
		if resp.StatusCode != want {
			t.Errorf("auth %q: got %d want %d", h, resp.StatusCode, want)
		}
	}
}

type upstreamArgs struct {
	Repo string `json:"repo,omitempty"`
}

func fixtureUpstream(t *testing.T) *httptest.Server {
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		s := mcp.NewServer(&mcp.Implementation{Name: "fixture"}, nil)
		mcp.AddTool(s, &mcp.Tool{Name: "list_issues", Description: "Lists issues.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
			func(ctx context.Context, r *mcp.CallToolRequest, a upstreamArgs) (*mcp.CallToolResult, any, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "issues for " + a.Repo + " auth=" + r.Extra.Header.Get("Authorization")}}}, nil, nil
			})
		return s
	}, &mcp.StreamableHTTPOptions{Stateless: true})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func adminCall(t *testing.T, base, key, method, path string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, base+"/admin/api/v1"+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, &m)
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	return m
}

// endToEnd configures a server through the Admin API and calls a tool through /mcp.
func endToEnd(t *testing.T, base, adminKey string) {
	up := fixtureUpstream(t)
	adminCall(t, base, adminKey, "POST", "/servers", map[string]any{"name": "Fixture", "prefix": "fixture", "transport": "http", "url": up.URL, "auth_kind": "bearer", "enabled": true})
	adminCall(t, base, adminKey, "PUT", "/servers/fixture/credential", map[string]any{"scope": "shared", "kind": "bearer", "token": "upstream-token-xyz"})
	adminCall(t, base, adminKey, "PUT", "/profiles/coding", map[string]any{"servers": []string{"fixture"}, "rules": []map[string]string{{"tool": "*", "action": "allow"}}})
	m := adminCall(t, base, adminKey, "POST", "/clients", map[string]any{"name": "Codex", "profile": "coding"})
	tok := m["token"].(string)

	var cs *mcp.ClientSession
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for {
		c := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil)
		cs, err = c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: base + "/mcp", HTTPClient: &http.Client{Transport: bearer{tok}}, DisableStandaloneSSE: true}, nil)
		if err == nil {
			res, lerr := cs.ListTools(context.Background(), nil)
			if lerr == nil && len(res.Tools) == 1 {
				break
			}
			cs.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway never exposed the tool: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer cs.Close()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "fixture__list_issues", Arguments: map[string]any{"repo": "acme"}})
	if err != nil || res.IsError {
		t.Fatalf("call: %v %+v", err, res)
	}
	txt := res.Content[0].(*mcp.TextContent).Text
	if !strings.HasPrefix(txt, "issues for acme auth=") || strings.Contains(txt, tok) {
		t.Fatalf("result %q", txt)
	}
	// The injected upstream token is redacted from results too.
	if strings.Contains(txt, "upstream-token-xyz") {
		t.Fatalf("injected secret leaked: %q", txt)
	}
	// Audit shows the call.
	deadline = time.Now().Add(3 * time.Second)
	for {
		req, _ := http.NewRequest("GET", base+"/admin/api/v1/audit?kind=call", nil)
		req.Header.Set("Authorization", "Bearer "+adminKey)
		resp, _ := http.DefaultClient.Do(req)
		var evs []map[string]any
		json.NewDecoder(resp.Body).Decode(&evs)
		resp.Body.Close()
		if len(evs) == 1 && evs[0]["tool"] == "fixture__list_issues" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit event missing: %v", evs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// spec: DEP-001
func TestAllInOneEndToEnd(t *testing.T) {
	_, srv, admin := newAllInOne(t)
	endToEnd(t, srv.URL, admin)
}

// spec: DEP-001, DEP-002, DEP-003, DEP-007
func TestMicroservicesModeEndToEnd(t *testing.T) {
	masterKey(t)
	tok := strings.Repeat("i", 40)
	admin := auth.NewAdminKeyString()
	listen := func() net.Listener { l, _ := net.Listen("tcp", "127.0.0.1:0"); return l }
	lnG, lnA, lnV, lnC, lnE := listen(), listen(), listen(), listen(), listen()
	u := func(l net.Listener) string { return "http://" + l.Addr().String() }
	public := u(lnE)
	base := Config{PublicURL: public, KeyProvider: "env", InternalToken: tok, Logger: quietLogger(), Version: "test",
		AuthURL: u(lnA), VaultURL: u(lnV), ControlURL: u(lnC), GatewayURL: u(lnG), BootstrapAdminKey: admin}
	start := func(ln net.Listener, svc string) {
		c := base
		c.Listen, c.Services, c.DataDir = ln.Addr().String(), []string{svc}, t.TempDir()
		a, err := New(context.Background(), c)
		if err != nil {
			t.Fatalf("%s: %v", svc, err)
		}
		s := httptest.NewUnstartedServer(a.Handler)
		s.Listener.Close()
		s.Listener = ln
		s.Start()
		t.Cleanup(func() { s.Close(); a.Close() })
	}
	// Start order matters only for the gateway's first snapshot: control first.
	start(lnV, SvcVault)
	start(lnC, SvcControl)
	start(lnA, SvcAuth)
	start(lnG, SvcGateway)
	// Edge proxy routing public paths, like deploy/Caddyfile.split.
	proxy := func(target string) http.Handler {
		tu, _ := url.Parse(target)
		return httputil.NewSingleHostReverseProxy(tu)
	}
	edgeMux := http.NewServeMux()
	edgeMux.Handle("/mcp", proxy(u(lnG)))
	edgeMux.Handle("/.well-known/", proxy(u(lnA)))
	edgeMux.Handle("/oauth/", proxy(u(lnA)))
	edgeMux.Handle("/admin/api/v1/auth/", proxy(u(lnA)))
	edgeMux.Handle("/admin/", proxy(u(lnC)))
	edge := httptest.NewUnstartedServer(edgeMux)
	edge.Listener.Close()
	edge.Listener = lnE
	edge.Start()
	defer edge.Close()

	endToEnd(t, public, admin)

	// Each service has its own database (database per service).
	resp, _ := http.Get(u(lnG) + "/readyz")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("gateway readiness in split mode: %d %s", resp.StatusCode, body)
	}
}

var _ = keybox.StrengthStrong

func readDir(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out, err
}
