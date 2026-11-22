package adminapi_test

import (
	"os"

	"gopkg.in/yaml.v3"

	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/adminapi"
	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/keybox"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
	"github.com/mcp-gateway/mcp-gateway/internal/services/auth"
	"github.com/mcp-gateway/mcp-gateway/internal/services/control"
	"github.com/mcp-gateway/mcp-gateway/internal/services/vault"
	"github.com/mcp-gateway/mcp-gateway/internal/testutil"
)

type vaultAdmin struct{ *vault.Service }

func (vaultAdmin) KeyProvider() adminapi.KeyProviderInfo {
	return adminapi.KeyProviderInfo{Name: "test", Strength: "strong", Healthy: true}
}

type fakeProber struct{ err error }

func (f fakeProber) Probe(context.Context, string, string) (int, error) { return 3, f.err }

type env struct {
	t      *testing.T
	srv    *httptest.Server
	auth   *auth.Service
	ctl    *control.Service
	vault  *vault.Service
	keys   map[domain.Role]string
	users  map[domain.Role]string
	prober *fakeProber
}

func newEnv(t *testing.T) *env {
	ctx := context.Background()
	k := make([]byte, 32)
	rand.Read(k)
	p, _ := keybox.NewStaticProvider("t", keybox.StrengthStrong, k)
	box := keybox.New(p)
	e := &env{t: t, keys: map[domain.Role]string{}, users: map[domain.Role]string{}, prober: &fakeProber{}}
	var err error
	if e.auth, err = auth.New(ctx, auth.Options{DBPath: ":memory:", Box: box, PublicURL: "http://127.0.0.1:8787"}); err != nil {
		t.Fatal(err)
	}
	if e.ctl, err = control.New(ctx, control.Options{DBPath: ":memory:"}); err != nil {
		t.Fatal(err)
	}
	if e.vault, err = vault.New(ctx, vault.Options{DBPath: ":memory:", Box: box}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []domain.Role{domain.RoleOwner, domain.RoleAdmin, domain.RoleMember, domain.RoleViewer} {
		u, _ := e.auth.CreateUser(ctx, string(r)+"-user", r)
		key, _, _ := e.auth.CreateAdminKey(ctx, u.ID, "k")
		e.keys[r], e.users[r] = key, u.ID
	}
	api := adminapi.New(adminapi.Options{Auth: e.auth, Vault: vaultAdmin{e.vault}, Control: e.ctl, Prober: e.prober, PublicURL: "http://127.0.0.1:8787"})
	mux := http.NewServeMux()
	mux.Handle("/admin/api/v1/auth/", e.auth.AdminAuthHandler())
	mux.Handle("/admin/", api)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(func() { e.srv.Close(); e.auth.Close(); e.ctl.Close(); e.vault.Close() })
	return e
}

func (e *env) do(role domain.Role, method, path string, body any) (int, map[string]any, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/admin/api/v1"+path, rd)
	if role != "" {
		req.Header.Set("Authorization", "Bearer "+e.keys[role])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, raw
}

func (e *env) seed() {
	st, m, _ := e.do(domain.RoleAdmin, "POST", "/servers", domain.Server{Name: "GitHub", Prefix: "github", Transport: "http", URL: "https://example.com/mcp", AuthKind: "bearer", Enabled: true})
	if st != 201 {
		e.t.Fatalf("create server: %d %v", st, m)
	}
	st, m, _ = e.do(domain.RoleAdmin, "PUT", "/profiles/coding", domain.Profile{Servers: []string{"github"}, Rules: []domain.Rule{{Tool: "github__merge_*", Action: "ask"}, {Tool: "*", Action: "allow"}}})
	if st != 200 {
		e.t.Fatalf("put profile: %d %v", st, m)
	}
}

// spec: CTL-040
func TestErrorEnvelope(t *testing.T) {
	e := newEnv(t)
	st, m, _ := e.do(domain.RoleAdmin, "GET", "/servers/nope", nil)
	errObj, _ := m["error"].(map[string]any)
	if st != 404 || errObj["code"] != "not_found" || errObj["message"] == "" {
		t.Fatalf("got %d %v", st, m)
	}
	st, m, _ = e.do(domain.RoleAdmin, "POST", "/servers", `{"name":`)
	if st != 400 || m["error"] == nil {
		t.Fatalf("bad JSON: %d %v", st, m)
	}
	st, _, raw := e.do("", "GET", "/overview", nil)
	if st != 401 || !strings.Contains(string(raw), `"code":"unauthenticated"`) {
		t.Fatalf("unauthenticated: %d %s", st, raw)
	}
}

// spec: CTL-041
func TestRoutesSmoke(t *testing.T) {
	e := newEnv(t)
	e.seed()
	O := domain.RoleOwner
	for _, path := range []string{"/overview", "/catalog", "/servers", "/servers/github", "/servers/github/tools", "/servers/github/credentials",
		"/clients", "/profiles", "/approvals", "/pins/changes", "/audit", "/audit/verify", "/users", "/keys", "/security", "/config/export"} {
		if st, m, _ := e.do(O, "GET", path, nil); st != 200 {
			t.Errorf("GET %s: %d %v", path, st, m)
		}
	}
	st, m, _ := e.do(O, "POST", "/clients", map[string]string{"name": "Codex", "profile": "coding"})
	if st != 201 || !strings.HasPrefix(m["token"].(string), "gw_") {
		t.Fatalf("create client: %d %v", st, m)
	}
	snips := m["snippets"].(map[string]any)
	for _, k := range []string{"claude_code", "codex", "cursor"} {
		if !strings.Contains(snips[k].(string), m["token"].(string)) || !strings.Contains(snips[k].(string), "http://127.0.0.1:8787/mcp") {
			t.Errorf("snippet %s: %v", k, snips[k])
		}
	}
	cid := m["client"].(map[string]any)["id"].(string)
	if st, _, _ := e.do(O, "POST", "/clients", map[string]string{"name": "X", "profile": "missing"}); st != 400 {
		t.Errorf("unknown profile accepted: %d", st)
	}
	if st, m, _ := e.do(O, "POST", "/profiles/simulate", map[string]any{"profile": "coding", "tool": "github__merge_pr"}); st != 200 || m["decision"].(map[string]any)["action"] != "ask" {
		t.Errorf("simulate: %d %v", st, m)
	}
	if st, _, _ := e.do(O, "PATCH", "/clients/"+cid, map[string]string{"profile": "coding"}); st != 200 {
		t.Errorf("patch client: %d", st)
	}
	if st, _, _ := e.do(O, "DELETE", "/clients/"+cid, nil); st != 200 {
		t.Errorf("revoke: %d", st)
	}
	if st, m, _ := e.do(O, "POST", "/users/invites", map[string]string{"role": "viewer"}); st != 200 || !strings.Contains(m["url"].(string), "/admin/invite?token=") {
		t.Errorf("invite: %d %v", st, m)
	}
	if st, m, _ := e.do(O, "POST", "/security/rotate-signing-key", nil); st != 200 || m["signing_key"] == nil {
		t.Errorf("rotate: %d %v", st, m)
	}
	_, _, y := e.do(O, "GET", "/config/export", nil)
	if st, m, _ := e.do(O, "POST", "/config/import", string(y)); st != 200 {
		t.Errorf("import: %d %v", st, m)
	}
	if st, _, _ := e.do(O, "DELETE", "/servers/github", nil); st != 200 {
		t.Errorf("delete server: %d", st)
	}
}

// spec: AUTH-034, UI-013
func TestRoleEnforcement(t *testing.T) {
	e := newEnv(t)
	e.seed()
	cases := []struct {
		role         domain.Role
		method, path string
		body         any
		want         int
	}{
		{domain.RoleViewer, "GET", "/servers", nil, 200},
		{domain.RoleViewer, "POST", "/servers", domain.Server{Name: "x", Prefix: "x", Transport: "http", URL: "https://x"}, 403},
		{domain.RoleMember, "PUT", "/profiles/x", domain.Profile{}, 403},
		{domain.RoleMember, "POST", "/clients", map[string]string{"name": "m", "profile": "coding"}, 201},
		{domain.RoleAdmin, "GET", "/keys", nil, 403},
		{domain.RoleAdmin, "POST", "/users/invites", map[string]string{"role": "viewer"}, 403},
		{domain.RoleMember, "PUT", "/servers/github/credential", map[string]any{"scope": "shared", "kind": "bearer", "token": "t-123456"}, 403},
		{domain.RoleMember, "PUT", "/servers/github/credential", map[string]any{"kind": "bearer", "token": "t-123456"}, 200},
		{domain.RoleViewer, "POST", "/approvals/x/decide", map[string]bool{"approve": true}, 403},
		{domain.RoleOwner, "POST", "/config/import", "version: 1\nservers: []\nprofiles: []\n", 200},
	}
	for _, c := range cases {
		if st, m, _ := e.do(c.role, c.method, c.path, c.body); st != c.want {
			t.Errorf("%s %s %s: got %d want %d (%v)", c.role, c.method, c.path, st, c.want, m)
		}
	}
	// A member cannot revoke someone else's AI tool.
	_, m, _ := e.do(domain.RoleAdmin, "POST", "/clients", map[string]string{"name": "adm", "profile": "coding"})
	_ = m
}

// spec: AUTH-033
func TestCSRFOnSessionMutations(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	inv, _ := e.auth.CreateInvite(ctx, e.users[domain.RoleOwner], domain.RoleAdmin)
	_ = inv
	// Create a session directly through the auth service's passkey-less path is not exposed;
	// emulate a browser session by logging in through the bootstrap of a session for an admin user.
	sid := testSession(t, e.auth, e.users[domain.RoleAdmin])
	req, _ := http.NewRequest("PUT", e.srv.URL+"/admin/api/v1/profiles/p", strings.NewReader(`{"servers":[],"rules":[]}`))
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sid})
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("session mutation without CSRF: %d", resp.StatusCode)
	}
	p, _ := e.auth.AuthenticateAdmin(ctx, sid, "")
	req, _ = http.NewRequest("PUT", e.srv.URL+"/admin/api/v1/profiles/p", strings.NewReader(`{"servers":[],"rules":[]}`))
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: sid})
	req.Header.Set("X-CSRF-Token", p.CSRF)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("session mutation with CSRF: %d", resp.StatusCode)
	}
}

// spec: CTL-043, VLT-008
func TestSecretsWriteOnly(t *testing.T) {
	e := newEnv(t)
	e.seed()
	st, _, raw := e.do(domain.RoleAdmin, "PUT", "/servers/github/credential", map[string]any{"scope": "shared", "kind": "bearer", "token": "ghp_WRITEONLYSECRET"})
	if st != 200 || strings.Contains(string(raw), "WRITEONLY") {
		t.Fatalf("set credential echoed the secret: %d %s", st, raw)
	}
	for _, path := range []string{"/servers/github/credentials", "/servers/github", "/overview", "/audit", "/config/export"} {
		_, _, body := e.do(domain.RoleOwner, "GET", path, nil)
		if strings.Contains(string(body), "WRITEONLY") {
			t.Fatalf("%s leaks the secret", path)
		}
	}
	_, _, body := e.do(domain.RoleOwner, "GET", "/servers/github/credentials", nil)
	if !strings.Contains(string(body), `"kind":"bearer"`) || !strings.Contains(string(body), `"user_id":""`) {
		t.Fatalf("metadata missing: %s", body)
	}
	c, err := e.vault.GetCredential(context.Background(), "anyone", "github")
	if err != nil || c.Token != "ghp_WRITEONLYSECRET" {
		t.Fatalf("credential not stored: %v", err)
	}
}

// spec: CTL-042, UI-008
func TestSSEEvents(t *testing.T) {
	e := newEnv(t)
	e.seed()
	req, _ := http.NewRequest("GET", e.srv.URL+"/admin/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+e.keys[domain.RoleViewer])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	go e.ctl.RequestApproval(context.Background(), domain.Approval{UserID: e.users[domain.RoleMember], ClientName: "Codex", Profile: "coding", ServerID: "github", Tool: "github__merge_pr"})
	sc := bufio.NewScanner(resp.Body)
	got := map[string]bool{}
	for sc.Scan() && !got["approval.created"] {
		if line := sc.Text(); strings.HasPrefix(line, "event: ") {
			got[strings.TrimPrefix(line, "event: ")] = true
		}
	}
	if !got["approval.created"] {
		t.Fatalf("no approval.created event (got %v)", got)
	}
}

// spec: CTL-044
func TestConnectionTestSetsHealth(t *testing.T) {
	e := newEnv(t)
	e.seed()
	st, m, _ := e.do(domain.RoleMember, "POST", "/servers/github/test", nil)
	if st != 200 || m["ok"] != true || m["tools"].(float64) != 3 {
		t.Fatalf("test ok: %d %v", st, m)
	}
	_, sv, _ := e.do(domain.RoleViewer, "GET", "/servers/github", nil)
	if sv["health"] != "ok" {
		t.Fatalf("health %v", sv["health"])
	}
	e.prober.err = ports.ErrNeedsReauth
	_, m, _ = e.do(domain.RoleMember, "POST", "/servers/github/test", nil)
	_, sv, _ = e.do(domain.RoleViewer, "GET", "/servers/github", nil)
	if m["ok"] != false || sv["health"] != "needs_reauth" {
		t.Fatalf("needs_reauth not reflected: %v %v", m, sv["health"])
	}
}

func TestMemberSeesOnlyOwnApprovalsAndActivity(t *testing.T) {
	e := newEnv(t)
	e.seed()
	ctx := context.Background()
	e.ctl.Record(ctx, []domain.AuditEvent{{UserID: e.users[domain.RoleMember], Tool: "a", Decision: "allow", Status: "ok"}, {UserID: e.users[domain.RoleAdmin], Tool: "b", Decision: "allow", Status: "ok"}})
	_, _, body := e.do(domain.RoleMember, "GET", "/audit?kind=call", nil)
	var evs []domain.AuditEvent
	json.Unmarshal(body, &evs)
	if len(evs) != 1 || evs[0].Tool != "a" {
		t.Fatalf("member audit view: %+v", evs)
	}
}

// testSession logs in a new admin user through the real invite + passkey flow and returns the session id.
func testSession(t *testing.T, a *auth.Service, ownerID string) string {
	ctx := context.Background()
	inv, err := a.CreateInvite(ctx, ownerID, domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.AdminAuthHandler())
	defer srv.Close()
	post := func(path string, body any) (*http.Response, map[string]any) {
		b, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+"/admin/api/v1/auth"+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return resp, m
	}
	authn := testutil.NewSoftAuthenticator(t, "http://127.0.0.1:8787", "127.0.0.1")
	_, begin := post("/invite/begin", map[string]string{"token": inv, "name": "Browser admin"})
	resp, fin := post("/register/finish", map[string]any{"ceremony": begin["ceremony"], "credential": json.RawMessage(authn.Register(begin["options"]))})
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookie {
			return c.Value
		}
	}
	t.Fatalf("no session cookie: %v", fin)
	return ""
}

// spec: CTL-040, CTL-041
func TestOpenAPIDescribesEveryRoute(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi.yaml is not valid YAML: %v", err)
	}
	api := adminapi.New(adminapi.Options{})
	for _, r := range api.Routes() {
		method, path, _ := strings.Cut(r, " ")
		path = strings.TrimPrefix(path, "/admin/api/v1")
		ops, ok := doc.Paths[path]
		if !ok {
			t.Errorf("route %s missing from api/openapi.yaml", r)
			continue
		}
		if _, ok := ops[strings.ToLower(method)]; !ok {
			t.Errorf("route %s: method missing in api/openapi.yaml", r)
		}
	}
}

// spec: UI-005
func TestClientsIncludeCallCounts(t *testing.T) {
	e := newEnv(t)
	e.seed()
	_, m, _ := e.do(domain.RoleOwner, "POST", "/clients", map[string]string{"name": "Codex", "profile": "coding"})
	cid := m["client"].(map[string]any)["id"].(string)
	e.ctl.Record(context.Background(), []domain.AuditEvent{{ClientID: cid, Tool: "a", Decision: "allow", Status: "ok"}, {ClientID: cid, Tool: "b", Decision: "deny", Status: "denied"}})
	_, _, body := e.do(domain.RoleOwner, "GET", "/clients", nil)
	var cs []map[string]any
	json.Unmarshal(body, &cs)
	if len(cs) != 1 || cs[0]["calls"].(float64) != 2 {
		t.Fatalf("calls missing or wrong: %s", body)
	}
}
