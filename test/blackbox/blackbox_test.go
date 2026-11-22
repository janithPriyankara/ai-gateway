// Package blackbox drives a real mcp-gateway only through its public surface.
//
// By default it builds ./cmd/gw and runs it. To test another deployment (for
// example docker compose), set:
//
//	GW_BLACKBOX_URL        base URL of the deployment, e.g. http://127.0.0.1:8787
//	GW_BLACKBOX_ADMIN_KEY  its bootstrap owner key (GW_BOOTSTRAP_ADMIN_KEY)
//	GW_BLACKBOX_FIXTURE_HOST  host name the deployment uses to reach this test process
//	                          (default 127.0.0.1; use host.docker.internal for Docker)
package blackbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mcp-gateway/mcp-gateway/internal/testutil"
)

var (
	binPath     string
	baseURL     string
	adminKey    string
	fixtureHost = "127.0.0.1"
)

func TestMain(m *testing.M) {
	if h := os.Getenv("GW_BLACKBOX_FIXTURE_HOST"); h != "" {
		fixtureHost = h
	}
	dir, err := os.MkdirTemp("", "gw-blackbox-*")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "gw")
	build := exec.Command("go", "build", "-o", binPath, "../../cmd/gw")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		panic("building gw: " + err.Error())
	}
	var stop func()
	if u := os.Getenv("GW_BLACKBOX_URL"); u != "" {
		baseURL, adminKey = strings.TrimRight(u, "/"), os.Getenv("GW_BLACKBOX_ADMIN_KEY")
		waitReady(baseURL, 60*time.Second)
	} else {
		var err error
		baseURL, adminKey, stop, err = startGateway(dir)
		if err != nil {
			panic(err)
		}
	}
	code := m.Run()
	if stop != nil {
		stop()
	}
	os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() string {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	return l.Addr().String()
}

func output(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(out))
}

func startGateway(dir string) (string, string, func(), error) {
	addr := freePort()
	key := output(binPath, "keygen", "admin")
	cmd := exec.Command(binPath, "serve")
	cmd.Dir = dir // proves the binary needs nothing but its data dir (DEP-008)
	cmd.Env = append(os.Environ(), "GW_LISTEN="+addr, "GW_DATA_DIR="+filepath.Join(dir, "data"), "GW_KEY_PROVIDER=env",
		"GW_MASTER_KEY="+output(binPath, "keygen", "master"), "GW_BOOTSTRAP_ADMIN_KEY="+key, "GW_LOG_LEVEL=warn")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return "", "", nil, err
	}
	_, port, _ := net.SplitHostPort(addr)
	u := "http://localhost:" + port // the default public URL on loopback
	if err := waitReady(u, 20*time.Second); err != nil {
		cmd.Process.Kill()
		return "", "", nil, err
	}
	return u, key, func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() }, nil
}

func waitReady(u string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(u + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("gateway at %s not ready after %v", u, d)
}

func admin(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if s, ok := body.(string); ok {
		rd = strings.NewReader(s)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, baseURL+"/admin/api/v1"+path, rd)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func mustAdmin(t *testing.T, method, path string, body any) map[string]any {
	t.Helper()
	st, raw := admin(t, method, path, body)
	if st >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, st, raw)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	return m
}

type issueArgs struct {
	Repo string `json:"repo,omitempty"`
}

// fixture is an upstream MCP server reachable by the gateway.
func fixture(t *testing.T) string {
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		s := mcp.NewServer(&mcp.Implementation{Name: "bb-fixture"}, nil)
		mcp.AddTool(s, &mcp.Tool{Name: "list_issues", Description: "Lists issues.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
			func(ctx context.Context, r *mcp.CallToolRequest, a issueArgs) (*mcp.CallToolResult, any, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "issues for " + a.Repo}}}, nil, nil
			})
		mcp.AddTool(s, &mcp.Tool{Name: "delete_repo", Description: "Deletes a repo."},
			func(ctx context.Context, r *mcp.CallToolRequest, a issueArgs) (*mcp.CallToolResult, any, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deleted"}}}, nil, nil
			})
		return s
	}, &mcp.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true})
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return fmt.Sprintf("http://%s:%d/mcp", fixtureHost, ln.Addr().(*net.TCPAddr).Port)
}

var counter int

// setupServer registers a fixture server and a profile with a unique prefix.
func setupServer(t *testing.T) (prefix, profile string) {
	counter++
	prefix = fmt.Sprintf("bb%d%d", time.Now().UnixNano()%100000, counter)
	profile = prefix + "-profile"
	mustAdmin(t, "POST", "/servers", map[string]any{"name": "Fixture " + prefix, "prefix": prefix, "transport": "http", "url": fixture(t), "auth_kind": "none", "enabled": true})
	mustAdmin(t, "PUT", "/profiles/"+profile, map[string]any{"servers": []string{prefix}, "rules": []map[string]string{
		{"tool": "*__delete_*", "action": "deny"}, {"tool": "*", "action": "allow"}}})
	return prefix, profile
}

type bearerRT struct{ tok string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func mcpSession(t *testing.T, tok string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "blackbox"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: baseURL + "/mcp", HTTPClient: &http.Client{Transport: bearerRT{tok}}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func callText(t *testing.T, cs *mcp.ClientSession, name string, args any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

// spec: GW-001, GW-003, GW-005, GW-006, DEP-008
func TestStaticTokenClientFlow(t *testing.T) {
	prefix, profile := setupServer(t)
	m := mustAdmin(t, "POST", "/clients", map[string]any{"name": "Codex", "profile": profile})
	cs := mcpSession(t, m["token"].(string))
	if cs.InitializeResult().ServerInfo.Name != "mcp-gateway" {
		t.Fatal("server info")
	}
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != prefix+"__list_issues" {
		t.Fatalf("tools: %+v %v", tools, err)
	}
	if out, isErr := callText(t, cs, prefix+"__list_issues", map[string]any{"repo": "acme"}); isErr || out != "issues for acme" {
		t.Fatalf("call: %q", out)
	}
	if out, isErr := callText(t, cs, prefix+"__delete_repo", map[string]any{}); !isErr || !strings.Contains(out, "policy") {
		t.Fatalf("denied call: %q", out)
	}
}

// spec: AUTH-020, AUTH-021, AUTH-022, AUTH-023, AUTH-024, AUTH-026, AUTH-027, AUTH-031, UI-002
func TestOAuthClientFlowWithPasskeyLogin(t *testing.T) {
	_, profile := setupServer(t)
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 1. An MCP client discovers the authorization server from a 401.
	resp, _ := http.Post(baseURL+"/mcp", "application/json", strings.NewReader("{}"))
	resp.Body.Close()
	re := regexp.MustCompile(`resource_metadata="([^"]+)"`)
	mm := re.FindStringSubmatch(resp.Header.Get("WWW-Authenticate"))
	if resp.StatusCode != 401 || mm == nil {
		t.Fatalf("401 discovery: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	getJSON := func(u string) map[string]any {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return m
	}
	prm := getJSON(mm[1])
	asBase := prm["authorization_servers"].([]any)[0].(string)
	asm := getJSON(asBase + "/.well-known/oauth-authorization-server")

	// 2. Dynamic client registration.
	redirect := "http://127.0.0.1:53682/callback"
	regBody, _ := json.Marshal(map[string]any{"client_name": "Claude Code", "redirect_uris": []string{redirect}})
	resp, _ = http.Post(asm["registration_endpoint"].(string), "application/json", bytes.NewReader(regBody))
	var reg map[string]any
	json.NewDecoder(resp.Body).Decode(&reg)
	resp.Body.Close()
	clientID := reg["client_id"].(string)

	// 3. The user signs in to the dashboard with a passkey (invited by the owner).
	inv := mustAdmin(t, "POST", "/users/invites", map[string]any{"role": "member"})
	pu, _ := url.Parse(baseURL)
	authn := testutil.NewSoftAuthenticator(t, pu.Scheme+"://"+pu.Host, pu.Hostname())
	post := func(path string, body any) map[string]any {
		b, _ := json.Marshal(body)
		resp, err := browser.Post(baseURL+"/admin/api/v1/auth"+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %v", path, resp.StatusCode, m)
		}
		return m
	}
	begin := post("/invite/begin", map[string]string{"token": inv["token"].(string), "name": "Dev"})
	post("/register/finish", map[string]any{"ceremony": begin["ceremony"], "credential": json.RawMessage(authn.Register(begin["options"]))})
	// Fresh login with the passkey, as a returning user would.
	jar2, _ := cookiejar.New(nil)
	browser.Jar = jar2
	lb := post("/login/begin", map[string]any{})
	post("/login/finish", map[string]any{"ceremony": lb["ceremony"], "credential": json.RawMessage(authn.Login(lb["options"]))})

	// 4. Authorization request with PKCE → consent page → approve.
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {"st8"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "resource": {prm["resource"].(string)}}
	resp, err := browser.Get(asm["authorization_endpoint"].(string) + "?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(page), profile) {
		t.Fatalf("consent page: %d", resp.StatusCode)
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(string(page))[1]
	resp, _ = browser.PostForm(baseURL+"/oauth/authorize", url.Values{"query": {q.Encode()}, "csrf": {csrf}, "decision": {"approve"}, "profile": {profile}})
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "st8" {
		t.Fatalf("authorization redirect: %s", loc)
	}

	// 5. Token exchange, MCP call with the access token, refresh rotation.
	tokResp := func(form url.Values) map[string]any {
		resp, err := http.PostForm(asm["token_endpoint"].(string), form)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		if resp.StatusCode != 200 {
			t.Fatalf("token: %d %v", resp.StatusCode, m)
		}
		return m
	}
	tk := tokResp(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "redirect_uri": {redirect}, "code_verifier": {verifier}})
	cs := mcpSession(t, tk["access_token"].(string))
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(tools.Tools) != 1 {
		t.Fatalf("tools with OAuth token: %+v %v", tools, err)
	}
	tk2 := tokResp(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk["refresh_token"].(string)}, "client_id": {clientID}})
	if tk2["access_token"] == "" || tk2["refresh_token"] == tk["refresh_token"] {
		t.Fatal("refresh did not rotate")
	}
	// The OAuth client now shows up as an AI tool for the user.
	_, raw := admin(t, "GET", "/clients", nil)
	if !strings.Contains(string(raw), `"kind":"oauth"`) || !strings.Contains(string(raw), "Claude Code") {
		t.Fatalf("OAuth client not listed: %s", raw)
	}
}

// spec: CTL-004, CTL-031
func TestExportImportAndAuditChain(t *testing.T) {
	setupServer(t)
	st, y := admin(t, "GET", "/config/export", nil)
	if st != 200 || !strings.Contains(string(y), "version: 1") {
		t.Fatalf("export: %d", st)
	}
	if st, raw := admin(t, "POST", "/config/import", string(y)); st != 200 {
		t.Fatalf("import: %d %s", st, raw)
	}
	m := mustAdmin(t, "GET", "/audit/verify", nil)
	if m["ok"] != true {
		t.Fatalf("audit chain: %v", m)
	}
}

// spec: DEP-009
func TestVersionAndDoctor(t *testing.T) {
	out := output(binPath, "version")
	if !strings.HasPrefix(out, "mcp-gateway ") || !strings.Contains(out, "commit") {
		t.Fatalf("version: %q", out)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	cmd := exec.Command(binPath, "doctor")
	cmd.Env = append(os.Environ(), "GW_DATA_DIR="+dir, "GW_KEY_PROVIDER=passphrase", "GW_PASSPHRASE=doctor-test", "GW_LISTEN="+freePort())
	b, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(b), "All checks passed") || !strings.Contains(string(b), `master key provider "passphrase"`) {
		t.Fatalf("doctor: %v\n%s", err, b)
	}
	cmd = exec.Command(binPath, "doctor")
	cmd.Env = append(os.Environ(), "GW_DATA_DIR="+dir, "GW_KEY_PROVIDER=nope", "GW_LISTEN="+freePort())
	b, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(b), "FAIL") {
		t.Fatalf("doctor should fail with a bad provider:\n%s", b)
	}
}

// spec: AUTH-030
func TestFirstRunPrintsSetupLink(t *testing.T) {
	if os.Getenv("GW_BLACKBOX_URL") != "" {
		t.Skip("needs to start its own process")
	}
	dir := t.TempDir()
	addr := freePort()
	cmd := exec.Command(binPath, "serve")
	cmd.Env = append(os.Environ(), "GW_LISTEN="+addr, "GW_DATA_DIR="+dir, "GW_KEY_PROVIDER=env", "GW_MASTER_KEY="+output(binPath, "keygen", "master"))
	stderr, _ := cmd.StderrPipe()
	cmd.Start()
	defer func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() }()
	sc := bufio.NewScanner(stderr)
	found := ""
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && sc.Scan() {
		if m := regexp.MustCompile(`(http://\S+/admin/setup\?token=setup_\S+)`).FindStringSubmatch(sc.Text()); m != nil {
			found = strings.Trim(m[1], `"`)
			break
		}
	}
	if found == "" {
		t.Fatal("no setup link in the log")
	}
	go io.Copy(io.Discard, stderr)
	waitReady("http://"+addr, 10*time.Second)
	resp, err := http.Get("http://" + addr + "/admin/api/v1/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]bool
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if !st["setup_required"] {
		t.Fatal("setup should be required on first run")
	}
}
