package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/keybox"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

type fakeProvider struct{ keybox.Provider }

func newTestVault(t *testing.T) *Service {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	keybox.Register("vault-test", func(context.Context, keybox.Config) (keybox.Provider, error) {
		return keybox.NewStaticProvider("vault-test", keybox.StrengthStrong, k)
	})
	p, err := keybox.Open(context.Background(), "vault-test", keybox.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(context.Background(), Options{DBPath: ":memory:", Box: keybox.New(p)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// spec: VLT-001, VLT-003
func TestUserThenSharedCredential(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()
	if _, err := v.GetCredential(ctx, "alice", "github"); !errors.Is(err, ports.ErrNoCredential) {
		t.Fatalf("want ErrNoCredential, got %v", err)
	}
	must(t, v.SetCredential(ctx, "", "github", ports.Credential{Kind: ports.CredBearer, Token: "shared-token"}))
	c, err := v.GetCredential(ctx, "alice", "github")
	if err != nil || c.Token != "shared-token" {
		t.Fatalf("shared fallback: %+v %v", c, err)
	}
	must(t, v.SetCredential(ctx, "alice", "github", ports.Credential{Kind: ports.CredBearer, Token: "alice-token"}))
	if c, _ := v.GetCredential(ctx, "alice", "github"); c.Token != "alice-token" {
		t.Fatalf("user credential must win, got %q", c.Token)
	}
	if c, _ := v.GetCredential(ctx, "bob", "github"); c.Token != "shared-token" {
		t.Fatalf("bob gets shared, got %q", c.Token)
	}
}

// spec: VLT-002
func TestNoPlaintextInDB(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()
	must(t, v.SetCredential(ctx, "alice", "github", ports.Credential{Kind: ports.CredBearer, Token: "ghp_SUPERSECRET123"}))
	rows, err := v.db.Query(`SELECT * FROM credentials`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		rows.Scan(ptrs...)
		for _, val := range vals {
			var b []byte
			switch x := val.(type) {
			case []byte:
				b = x
			case string:
				b = []byte(x)
			}
			if bytes.Contains(b, []byte("SUPERSECRET")) {
				t.Fatal("plaintext secret found in database")
			}
		}
	}
}

// spec: VLT-004
func TestCredentialKinds(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()
	creds := map[string]ports.Credential{
		"s1": {Kind: ports.CredBearer, Token: "tok123456"},
		"s2": {Kind: ports.CredHeader, HeaderName: "X-Api-Key", HeaderValue: "k-123456"},
		"s3": {Kind: ports.CredEnv, Env: map[string]string{"PGPASSWORD": "pw123456"}},
	}
	for s, c := range creds {
		must(t, v.SetCredential(ctx, "u", s, c))
	}
	for s, want := range creds {
		got, err := v.GetCredential(ctx, "u", s)
		if err != nil {
			t.Fatal(err)
		}
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		if string(gj) != string(wj) {
			t.Errorf("%s: got %s want %s", s, gj, wj)
		}
	}
	bad := []ports.Credential{
		{Kind: "nope"},
		{Kind: ports.CredBearer},
		{Kind: ports.CredHeader, HeaderName: "", HeaderValue: "x"},
		{Kind: ports.CredHeader, HeaderName: "Bad Header", HeaderValue: "x"},
		{Kind: ports.CredEnv},
	}
	for i, c := range bad {
		if err := v.SetCredential(ctx, "u", "s", c); err == nil {
			t.Errorf("bad credential %d accepted: %+v", i, c)
		}
	}
}

type tokenServer struct {
	srv      *httptest.Server
	calls    atomic.Int32
	mu       sync.Mutex
	fail     string // "" or an OAuth error code
	lastForm url.Values
}

func newTokenServer(t *testing.T) *tokenServer {
	ts := &tokenServer{}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.calls.Add(1)
		r.ParseForm()
		ts.mu.Lock()
		ts.lastForm = r.PostForm
		fail := ts.fail
		ts.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		if fail != "" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": fail})
			return
		}
		n := ts.calls.Load()
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-" + string(rune('A'+n)),
			"refresh_token": "refresh-" + string(rune('A'+n)),
			"expires_in":    3600,
			"token_type":    "Bearer",
		})
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func setupOAuth(t *testing.T, v *Service, ts *tokenServer) {
	ctx := context.Background()
	must(t, v.SetOAuthApp(ctx, OAuthApp{
		ServerID: "notion", AuthURL: ts.srv.URL + "/authorize", TokenURL: ts.srv.URL + "/token",
		ClientID: "cid", ClientSecret: "csecret", Scopes: []string{"read", "write"},
		RedirectURL: "http://127.0.0.1:8787/admin/oauth/callback",
	}))
}

// spec: VLT-005
func TestOAuthRefreshNearExpirySingleFlight(t *testing.T) {
	v := newTestVault(t)
	ts := newTokenServer(t)
	setupOAuth(t, v, ts)
	ctx := context.Background()
	now := time.Now()
	v.now = func() time.Time { return now }
	must(t, v.storeOAuth(ctx, "alice", "notion", oauthTokens{
		AccessToken: "old-access", RefreshToken: "old-refresh",
		IssuedAt: now.Add(-55 * time.Minute), ExpiresAt: now.Add(5 * time.Minute), // < 20% left
	}))
	var wg sync.WaitGroup
	results := make([]string, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := v.GetCredential(ctx, "alice", "notion")
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = c.Token
		}(i)
	}
	wg.Wait()
	if n := ts.calls.Load(); n != 1 {
		t.Fatalf("token endpoint called %d times, want 1 (single-flight)", n)
	}
	for _, r := range results {
		if r == "old-access" || r == "" {
			t.Fatalf("got stale token %q", r)
		}
	}
	if ts.lastForm.Get("grant_type") != "refresh_token" || ts.lastForm.Get("refresh_token") != "old-refresh" {
		t.Fatalf("bad refresh form: %v", ts.lastForm)
	}
	// Fresh token: no further calls.
	v.GetCredential(ctx, "alice", "notion")
	if ts.calls.Load() != 1 {
		t.Fatal("fresh token must not be refreshed")
	}
}

// spec: VLT-006
func TestInvalidGrantMarksNeedsReauth(t *testing.T) {
	v := newTestVault(t)
	ts := newTokenServer(t)
	ts.fail = "invalid_grant"
	setupOAuth(t, v, ts)
	ctx := context.Background()
	now := time.Now()
	must(t, v.storeOAuth(ctx, "alice", "notion", oauthTokens{
		AccessToken: "a", RefreshToken: "r", IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Minute),
	}))
	if _, err := v.GetCredential(ctx, "alice", "notion"); !errors.Is(err, ports.ErrNeedsReauth) {
		t.Fatalf("want ErrNeedsReauth, got %v", err)
	}
	calls := ts.calls.Load()
	if _, err := v.GetCredential(ctx, "alice", "notion"); !errors.Is(err, ports.ErrNeedsReauth) {
		t.Fatalf("still needs reauth, got %v", err)
	}
	if ts.calls.Load() != calls {
		t.Fatal("must not keep hammering the token endpoint once marked needs_reauth")
	}
	list, _ := v.ListCredentials(ctx, "notion")
	if len(list) != 1 || list[0].Status != StatusNeedsReauth {
		t.Fatalf("status not recorded: %+v", list)
	}
}

// spec: VLT-007
func TestOAuthConnectFlow(t *testing.T) {
	v := newTestVault(t)
	ts := newTokenServer(t)
	setupOAuth(t, v, ts)
	ctx := context.Background()
	authURL, err := v.StartConnect(ctx, "alice", "notion")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	for _, k := range []string{"state", "code_challenge", "client_id", "redirect_uri", "scope"} {
		if q.Get(k) == "" {
			t.Fatalf("authorize URL missing %s: %s", k, authURL)
		}
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
		t.Fatalf("bad authorize params: %v", q)
	}
	if _, err := v.CompleteConnect(ctx, "wrong-state", "code"); err == nil {
		t.Fatal("unknown state must fail")
	}
	srv, err := v.CompleteConnect(ctx, q.Get("state"), "the-code")
	if err != nil || srv != "notion" {
		t.Fatalf("complete: %v %v", srv, err)
	}
	if ts.lastForm.Get("code_verifier") == "" || ts.lastForm.Get("code") != "the-code" || ts.lastForm.Get("grant_type") != "authorization_code" {
		t.Fatalf("token exchange form: %v", ts.lastForm)
	}
	if _, err := v.CompleteConnect(ctx, q.Get("state"), "the-code"); err == nil {
		t.Fatal("state must be single use")
	}
	c, err := v.GetCredential(ctx, "alice", "notion")
	if err != nil || !strings.HasPrefix(c.Token, "access-") {
		t.Fatalf("credential after connect: %+v %v", c, err)
	}
	// Expired state
	authURL, _ = v.StartConnect(ctx, "alice", "notion")
	u, _ = url.Parse(authURL)
	v.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if _, err := v.CompleteConnect(ctx, u.Query().Get("state"), "c"); err == nil {
		t.Fatal("expired state must fail")
	}
}

// spec: VLT-008
func TestListReturnsMetadataOnly(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()
	must(t, v.SetCredential(ctx, "alice", "github", ports.Credential{Kind: ports.CredBearer, Token: "ghp_LISTSECRET"}))
	list, err := v.ListCredentials(ctx, "github")
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	b, _ := json.Marshal(list)
	if bytes.Contains(b, []byte("LISTSECRET")) {
		t.Fatal("listing leaks secret")
	}
	if list[0].Kind != ports.CredBearer || list[0].UserID != "alice" || list[0].Status != StatusOK {
		t.Fatalf("metadata: %+v", list[0])
	}
}

// spec: VLT-009
func TestDeleteServerDeletesCredentials(t *testing.T) {
	v := newTestVault(t)
	ctx := context.Background()
	must(t, v.SetCredential(ctx, "alice", "github", ports.Credential{Kind: ports.CredBearer, Token: "t-123456"}))
	must(t, v.SetCredential(ctx, "", "github", ports.Credential{Kind: ports.CredBearer, Token: "t-654321"}))
	must(t, v.SetCredential(ctx, "alice", "other", ports.Credential{Kind: ports.CredBearer, Token: "t-999999"}))
	must(t, v.DeleteServer(ctx, "github"))
	if _, err := v.GetCredential(ctx, "alice", "github"); !errors.Is(err, ports.ErrNoCredential) {
		t.Fatal("credentials survived server deletion")
	}
	if _, err := v.GetCredential(ctx, "alice", "other"); err != nil {
		t.Fatal("unrelated credential deleted")
	}
}

// spec: GW-009
func TestForceRefresh(t *testing.T) {
	v := newTestVault(t)
	ts := newTokenServer(t)
	setupOAuth(t, v, ts)
	ctx := context.Background()
	now := time.Now()
	must(t, v.storeOAuth(ctx, "alice", "notion", oauthTokens{AccessToken: "a", RefreshToken: "r", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}))
	c, err := v.ForceRefresh(ctx, "alice", "notion")
	if err != nil || c.Token == "a" {
		t.Fatalf("force refresh: %+v %v", c, err)
	}
	// Non-OAuth credential cannot be refreshed: marked needs_reauth.
	must(t, v.SetCredential(ctx, "alice", "gh", ports.Credential{Kind: ports.CredBearer, Token: "static-1"}))
	if _, err := v.ForceRefresh(ctx, "alice", "gh"); !errors.Is(err, ports.ErrNeedsReauth) {
		t.Fatalf("want ErrNeedsReauth, got %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
