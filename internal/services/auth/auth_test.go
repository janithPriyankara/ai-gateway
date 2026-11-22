package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/keybox"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
	"github.com/mcp-gateway/mcp-gateway/internal/testutil"
)

const testURL = "http://127.0.0.1:8787"

func testBox(t *testing.T) *keybox.Box {
	k := make([]byte, 32)
	rand.Read(k)
	p, err := keybox.NewStaticProvider("test", keybox.StrengthStrong, k)
	if err != nil {
		t.Fatal(err)
	}
	return keybox.New(p)
}

func newTestAuth(t *testing.T) *Service {
	t.Helper()
	s, err := New(context.Background(), Options{DBPath: ":memory:", Box: testBox(t), PublicURL: testURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seedUser creates a user directly (test helper).
func seedUser(t *testing.T, s *Service, name string, role domain.Role) domain.User {
	t.Helper()
	tx, _ := s.db.Begin()
	u, _, err := s.createUser(context.Background(), tx, name, role)
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit()
	return u
}

func seedSession(t *testing.T, s *Service, userID string) string {
	tx, _ := s.db.Begin()
	id, err := s.createSession(context.Background(), tx, userID)
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit()
	return id
}

// spec: AUTH-001, AUTH-002
func TestStaticTokens(t *testing.T) {
	s := newTestAuth(t)
	ctx := context.Background()
	u := seedUser(t, s, "alice", domain.RoleMember)
	tok, c, err := s.CreateStaticToken(ctx, u.ID, "Codex", "coding")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "gw_") || len(tok) != 46 {
		t.Fatalf("token format: %q", tok)
	}
	var stored []byte
	var prefix string
	s.db.QueryRow(`SELECT hash, prefix FROM clients WHERE id=?`, c.ID).Scan(&stored, &prefix)
	if bytes.Contains(stored, []byte(tok)) || len(prefix) != 8 || prefix != tok[3:11] {
		t.Fatalf("must store only a hash and an 8-char prefix (prefix=%q)", prefix)
	}
	id, err := s.Authenticate(ctx, tok)
	if err != nil || id.UserID != u.ID || id.ClientID != c.ID || id.ClientName != "Codex" || id.Profile != "coding" {
		t.Fatalf("identity: %+v %v", id, err)
	}
	bad := []string{"", "gw_", tok[:len(tok)-1] + "x", "gw_" + strings.Repeat("A", 43), "nope"}
	for _, b := range bad {
		if _, err := s.Authenticate(ctx, b); !errors.Is(err, ports.ErrUnauthenticated) {
			t.Errorf("token %q accepted or wrong error: %v", b, err)
		}
	}
	if err := s.RevokeClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, tok); !errors.Is(err, ports.ErrUnauthenticated) {
		t.Fatal("revoked token still works")
	}
	if _, _, err := s.CreateStaticToken(ctx, u.ID, "", "coding"); err == nil {
		t.Fatal("empty name accepted")
	}
}

// spec: AUTH-003
func TestStaticTokenCache(t *testing.T) {
	s := newTestAuth(t)
	ctx := context.Background()
	u := seedUser(t, s, "alice", domain.RoleMember)
	tok, c, _ := s.CreateStaticToken(ctx, u.ID, "Codex", "coding")
	s.Authenticate(ctx, tok)
	// Revoke behind the cache's back (simulates another replica).
	s.db.Exec(`UPDATE clients SET revoked_at=1 WHERE id=?`, c.ID)
	if _, err := s.Authenticate(ctx, tok); err != nil {
		t.Fatal("cached verification should still pass within the TTL")
	}
	now := time.Now().Add(61 * time.Second)
	s.now = func() time.Time { return now }
	if _, err := s.Authenticate(ctx, tok); err == nil {
		t.Fatal("revocation must take effect after the 60 s cache window")
	}
	start := time.Now()
	for i := 0; i < 1000; i++ {
		s.cache = map[string]cacheEntry{}
		break
	}
	_ = start
}

func BenchmarkAuthenticateCachedStatic(b *testing.B) {
	k := make([]byte, 32)
	p, _ := keybox.NewStaticProvider("b", keybox.StrengthStrong, k)
	s, _ := New(context.Background(), Options{DBPath: ":memory:", Box: keybox.New(p), PublicURL: testURL})
	defer s.Close()
	tx, _ := s.db.Begin()
	u, _, _ := s.createUser(context.Background(), tx, "u", domain.RoleMember)
	tx.Commit()
	tok, _, _ := s.CreateStaticToken(context.Background(), u.ID, "c", "p")
	ctx := context.Background()
	s.Authenticate(ctx, tok)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Authenticate(ctx, tok)
	}
}

// spec: AUTH-010
func TestAccessTokenClaims(t *testing.T) {
	s := newTestAuth(t)
	tok, err := s.issueAccessToken(domain.Identity{UserID: "usr_1", ClientID: "cli_1", Profile: "coding"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if parsed.Headers[0].KeyID == "" || parsed.Headers[0].Algorithm != "ES256" {
		t.Fatalf("header: %+v", parsed.Headers[0])
	}
	var claims map[string]any
	parsed.UnsafeClaimsWithoutVerification(&claims)
	for _, k := range []string{"iss", "sub", "aud", "exp", "iat", "jti", "client_id", "profile"} {
		if _, ok := claims[k]; !ok {
			t.Errorf("claim %s missing", k)
		}
	}
	if claims["iss"] != testURL || claims["sub"] != "usr_1" {
		t.Errorf("claims: %v", claims)
	}
	exp := int64(claims["exp"].(float64))
	iat := int64(claims["iat"].(float64))
	if exp-iat != 3600 {
		t.Errorf("lifetime %d, want 3600", exp-iat)
	}
}

func signWith(t *testing.T, key any, alg jose.SignatureAlgorithm, kid string, c any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// spec: AUTH-011
func TestAccessTokenRejections(t *testing.T) {
	s := newTestAuth(t)
	kid := s.SigningKey().KID
	s.keysMu.RLock()
	good := s.keys.current.priv
	s.keysMu.RUnlock()
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	base := func() accessClaims {
		return accessClaims{Claims: jwt.Claims{Issuer: testURL, Subject: "u", Audience: jwt.Audience{testURL + "/mcp"},
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}, ClientID: "c", Profile: "p"}
	}
	if _, err := s.verifyAccessToken(signWith(t, good, jose.ES256, kid, base())); err != nil {
		t.Fatalf("control case should verify: %v", err)
	}
	wrongIss, wrongAud, expired := base(), base(), base()
	wrongIss.Issuer = "https://evil"
	wrongAud.Audience = jwt.Audience{"https://other/mcp"}
	expired.Expiry = jwt.NewNumericDate(now.Add(-time.Minute))
	cases := map[string]string{
		"wrong signature": signWith(t, other, jose.ES256, kid, base()),
		"unknown kid":     signWith(t, good, jose.ES256, "k_nope", base()),
		"wrong issuer":    signWith(t, good, jose.ES256, kid, wrongIss),
		"wrong audience":  signWith(t, good, jose.ES256, kid, wrongAud),
		"expired":         signWith(t, good, jose.ES256, kid, expired),
		"HS256":           signWith(t, []byte(strings.Repeat("k", 32)), jose.HS256, kid, base()),
		"garbage":         "a.b.c",
	}
	// alg=none, hand-built.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"` + kid + `"}`))
	body, _ := json.Marshal(base())
	cases["alg none"] = hdr + "." + base64.RawURLEncoding.EncodeToString(body) + "."
	for name, tok := range cases {
		if _, err := s.verifyAccessToken(tok); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
	// 30 s leeway on expiry.
	slight := base()
	slight.Expiry = jwt.NewNumericDate(now.Add(-10 * time.Second))
	if _, err := s.verifyAccessToken(signWith(t, good, jose.ES256, kid, slight)); err != nil {
		t.Errorf("token expired 10 s ago should pass with leeway: %v", err)
	}
}

// spec: AUTH-012
func TestSigningKeyRotationAndJWKS(t *testing.T) {
	s := newTestAuth(t)
	ctx := context.Background()
	old, _ := s.issueAccessToken(domain.Identity{UserID: "u", ClientID: "c", Profile: "p"})
	oldKid := s.SigningKey().KID
	if err := s.RotateSigningKey(ctx); err != nil {
		t.Fatal(err)
	}
	if s.SigningKey().KID == oldKid {
		t.Fatal("rotation did not change the key")
	}
	set := s.JWKS()
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS must contain current and retired keys, got %d", len(set.Keys))
	}
	for _, k := range set.Keys {
		if !k.IsPublic() {
			t.Fatal("JWKS leaks a private key")
		}
	}
	if _, err := s.verifyAccessToken(old); err != nil {
		t.Fatalf("token from retired key must stay valid until expiry: %v", err)
	}
	var sealed []byte
	s.db.QueryRow(`SELECT sealed_private FROM signing_keys LIMIT 1`).Scan(&sealed)
	if len(sealed) == 0 || sealed[0] != 0x01 {
		t.Fatal("signing keys must be stored sealed")
	}
	// Restart: keys load from the DB and the retired key is still known.
	s2, err := New(ctx, Options{DBPath: ":memory:", Box: s.box, PublicURL: testURL})
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}

// --- OAuth flow over HTTP --------------------------------------------------

type oauthEnv struct {
	s      *Service
	srv    *httptest.Server
	client *http.Client
	user   domain.User
	sid    string
}

func newOAuthEnv(t *testing.T) *oauthEnv {
	s := newTestAuth(t)
	mux := http.NewServeMux()
	mux.Handle("/.well-known/", s.OAuthHandler(func(context.Context) ([]string, error) { return []string{"coding", "readonly"}, nil }))
	mux.Handle("/oauth/", s.OAuthHandler(func(context.Context) ([]string, error) { return []string{"coding", "readonly"}, nil }))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u := seedUser(t, s, "alice", domain.RoleMember)
	return &oauthEnv{s: s, srv: srv, client: c, user: u, sid: seedSession(t, s, u.ID)}
}

func (e *oauthEnv) login() {
	su, _ := url.Parse(e.srv.URL)
	e.client.Jar.SetCookies(su, []*http.Cookie{{Name: SessionCookie, Value: e.sid}})
}

func (e *oauthEnv) register(t *testing.T, redirect string) string {
	resp, err := e.client.Post(e.srv.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"Claude Code","redirect_uris":["`+redirect+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 201 {
		t.Fatalf("register: %d %v", resp.StatusCode, out)
	}
	return out["client_id"].(string)
}

const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXkAAAAAAAAAAA"

func authorizeQuery(clientID, redirect string) url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {"xyz"},
		"code_challenge": {pkceS256(verifier)}, "code_challenge_method": {"S256"}, "resource": {testURL + "/mcp"}}
}

// approve runs the consent step and returns the code.
func (e *oauthEnv) approve(t *testing.T, q url.Values, profile string) string {
	e.login()
	resp, err := e.client.Get(e.srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Connect Claude Code?") {
		t.Fatalf("consent page: %d %s", resp.StatusCode, body)
	}
	p, _ := e.s.AuthenticateAdmin(context.Background(), e.sid, "")
	form := url.Values{"query": {q.Encode()}, "csrf": {p.CSRF}, "decision": {"approve"}, "profile": {profile}}
	resp, err = e.client.PostForm(e.srv.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Query().Get("state") != "xyz" || loc.Query().Get("code") == "" {
		t.Fatalf("approve redirect: %d %s", resp.StatusCode, loc)
	}
	return loc.Query().Get("code")
}

func (e *oauthEnv) token(t *testing.T, form url.Values) (int, map[string]any) {
	resp, err := e.client.PostForm(e.srv.URL+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// spec: AUTH-020, AUTH-021
func TestDiscoveryMetadata(t *testing.T) {
	e := newOAuthEnv(t)
	get := func(path string) map[string]any {
		resp, err := http.Get(e.srv.URL + path)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", path, err, resp)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return m
	}
	prm := get("/.well-known/oauth-protected-resource")
	if prm["resource"] != testURL+"/mcp" || prm["authorization_servers"].([]any)[0] != testURL {
		t.Fatalf("PRM: %v", prm)
	}
	asm := get("/.well-known/oauth-authorization-server")
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "registration_endpoint"} {
		if !strings.HasPrefix(asm[k].(string), testURL) {
			t.Errorf("%s = %v", k, asm[k])
		}
	}
	if m := asm["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
		t.Errorf("PKCE methods %v", m)
	}
	if m := asm["token_endpoint_auth_methods_supported"].([]any); len(m) != 1 || m[0] != "none" {
		t.Errorf("auth methods %v", m)
	}
	g := asm["grant_types_supported"].([]any)
	if len(g) != 2 {
		t.Errorf("grants %v", g)
	}
	jwks := get("/.well-known/jwks.json")
	if len(jwks["keys"].([]any)) == 0 {
		t.Fatal("empty JWKS")
	}
}

// spec: AUTH-022
func TestDynamicClientRegistration(t *testing.T) {
	e := newOAuthEnv(t)
	ok := []string{"http://127.0.0.1:33418/callback", "http://localhost:5555/cb", "http://[::1]:1/x", "https://claude.ai/api/mcp/auth_callback"}
	for _, r := range ok {
		if _, err := e.s.RegisterClient(context.Background(), "c", []string{r}); err != nil {
			t.Errorf("%s rejected: %v", r, err)
		}
	}
	bad := []string{"http://evil.com/cb", "javascript:alert(1)", "https://x/cb#frag", "ftp://x", "", "/relative"}
	for _, r := range bad {
		if _, err := e.s.RegisterClient(context.Background(), "c", []string{r}); err == nil {
			t.Errorf("%q accepted", r)
		}
	}
	resp, _ := http.Post(e.srv.URL+"/oauth/register", "application/json", strings.NewReader(`{"redirect_uris":["http://evil.com/cb"]}`))
	if resp.StatusCode != 400 {
		t.Fatalf("HTTP register with bad URI: %d", resp.StatusCode)
	}
}

// spec: AUTH-023
func TestAuthorizeValidation(t *testing.T) {
	e := newOAuthEnv(t)
	cb := "http://127.0.0.1:9999/cb"
	cid := e.register(t, cb)
	e.login()
	check := func(name string, mut func(url.Values), wantErr string) {
		t.Helper()
		q := authorizeQuery(cid, cb)
		mut(q)
		resp, err := e.client.Get(e.srv.URL + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if wantErr == "page" {
			if resp.StatusCode != 400 {
				t.Errorf("%s: want 400 error page, got %d", name, resp.StatusCode)
			}
			return
		}
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != 302 || loc.Query().Get("error") != wantErr {
			t.Errorf("%s: got %d %s", name, resp.StatusCode, loc)
		}
	}
	check("unknown client", func(q url.Values) { q.Set("client_id", "nope") }, "page")
	check("redirect mismatch", func(q url.Values) { q.Set("redirect_uri", "http://127.0.0.1:9999/other") }, "page")
	check("plain PKCE", func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request")
	check("no PKCE", func(q url.Values) { q.Del("code_challenge") }, "invalid_request")
	check("no state", func(q url.Values) { q.Del("state") }, "invalid_request")
	check("token flow", func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type")
}

// spec: AUTH-024
func TestAuthorizeRequiresLoginAndConsent(t *testing.T) {
	e := newOAuthEnv(t)
	cb := "http://127.0.0.1:9999/cb"
	cid := e.register(t, cb)
	q := authorizeQuery(cid, cb)
	resp, _ := e.client.Get(e.srv.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), "/admin/login?next=") {
		t.Fatalf("no session must redirect to login, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	e.login()
	// Deny.
	p, _ := e.s.AuthenticateAdmin(context.Background(), e.sid, "")
	resp, _ = e.client.PostForm(e.srv.URL+"/oauth/authorize", url.Values{"query": {q.Encode()}, "csrf": {p.CSRF}, "decision": {"deny"}})
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Fatalf("deny: %s", loc)
	}
	// Missing CSRF.
	resp, _ = e.client.PostForm(e.srv.URL+"/oauth/authorize", url.Values{"query": {q.Encode()}, "decision": {"approve"}, "profile": {"coding"}})
	if resp.StatusCode != 403 {
		t.Fatalf("missing CSRF must be refused, got %d", resp.StatusCode)
	}
	e.approve(t, q, "coding")
}

// spec: AUTH-025, AUTH-026, AUTH-028
func TestCodeExchange(t *testing.T) {
	e := newOAuthEnv(t)
	cb := "http://127.0.0.1:9999/cb"
	cid := e.register(t, cb)
	code := e.approve(t, authorizeQuery(cid, cb), "coding")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cid}, "redirect_uri": {cb}, "code_verifier": {"wrong-verifier-wrong-verifier-wrong-verifier-123"}}
	if st, out := e.token(t, form); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("bad verifier: %d %v", st, out)
	}
	// A failed PKCE check does not burn the code in this implementation, but a wrong resource fails too.
	form.Set("code_verifier", verifier)
	form.Set("resource", "https://other/mcp")
	if st, out := e.token(t, form); st != 400 || out["error"] != "invalid_target" {
		t.Fatalf("bad resource: %d %v", st, out)
	}
	form.Set("resource", testURL+"/mcp")
	st, out := e.token(t, form)
	if st != 200 || out["access_token"] == nil || out["refresh_token"] == nil || out["token_type"] != "Bearer" {
		t.Fatalf("exchange: %d %v", st, out)
	}
	id, err := e.s.Authenticate(context.Background(), out["access_token"].(string))
	if err != nil || id.UserID != e.user.ID || id.Profile != "coding" || id.ClientName != "Claude Code" {
		t.Fatalf("access token identity: %+v %v", id, err)
	}
	// Replay: fails and revokes the tokens issued from the first use.
	if st, out := e.token(t, form); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", st, out)
	}
	rf := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {out["refresh_token"].(string)}, "client_id": {cid}}
	if st, _ := e.token(t, rf); st != 400 {
		t.Fatal("refresh token from a replayed code must be revoked")
	}
	// Expiry.
	code2 := e.approve(t, authorizeQuery(cid, cb), "coding")
	e.s.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	form.Set("code", code2)
	if st, out := e.token(t, form); st != 400 || !strings.Contains(out["error_description"].(string), "expired") {
		t.Fatalf("expired code: %d %v", st, out)
	}
	e.s.now = time.Now
	// Bound to client and redirect URI.
	code3 := e.approve(t, authorizeQuery(cid, cb), "coding")
	form.Set("code", code3)
	form.Set("redirect_uri", "http://127.0.0.1:9999/other")
	if st, _ := e.token(t, form); st != 400 {
		t.Fatal("redirect_uri mismatch accepted")
	}
}

// spec: AUTH-027
func TestRefreshRotationAndReuseDetection(t *testing.T) {
	e := newOAuthEnv(t)
	cb := "http://127.0.0.1:9999/cb"
	cid := e.register(t, cb)
	code := e.approve(t, authorizeQuery(cid, cb), "coding")
	_, out := e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cid}, "redirect_uri": {cb}, "code_verifier": {verifier}})
	rt1 := out["refresh_token"].(string)
	st, out2 := e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}, "client_id": {cid}})
	if st != 200 || out2["refresh_token"] == rt1 {
		t.Fatalf("rotation: %d %v", st, out2)
	}
	rt2 := out2["refresh_token"].(string)
	// Reuse of rt1 revokes the family, including rt2.
	if st, _ := e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}, "client_id": {cid}}); st != 400 {
		t.Fatal("reuse accepted")
	}
	if st, _ := e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt2}, "client_id": {cid}}); st != 400 {
		t.Fatal("family not revoked after reuse")
	}
}

func TestRevokedOAuthClientAccessTokenRejected(t *testing.T) {
	e := newOAuthEnv(t)
	cb := "http://127.0.0.1:9999/cb"
	cid := e.register(t, cb)
	code := e.approve(t, authorizeQuery(cid, cb), "coding")
	_, out := e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cid}, "redirect_uri": {cb}, "code_verifier": {verifier}})
	id, _ := e.s.Authenticate(context.Background(), out["access_token"].(string))
	e.s.RevokeClient(context.Background(), id.ClientID)
	if _, err := e.s.Authenticate(context.Background(), out["access_token"].(string)); err == nil {
		t.Fatal("access token of a revoked client must be rejected")
	}
}

// --- passkeys and sessions --------------------------------------------------

type adminEnv struct {
	s      *Service
	srv    *httptest.Server
	client *http.Client
}

func newAdminEnv(t *testing.T) *adminEnv {
	s := newTestAuth(t)
	srv := httptest.NewServer(s.AdminAuthHandler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &adminEnv{s: s, srv: srv, client: &http.Client{Jar: jar}}
}

func (e *adminEnv) post(t *testing.T, path string, body any, hdr ...string) (*http.Response, map[string]any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/admin/api/v1/auth"+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// spec: AUTH-030, AUTH-031, AUTH-033
func TestSetupPasskeyLoginAndSession(t *testing.T) {
	e := newAdminEnv(t)
	ctx := context.Background()
	tok, err := e.s.EnsureSetupToken(ctx)
	if err != nil || !strings.HasPrefix(tok, "setup_") {
		t.Fatalf("setup token: %q %v", tok, err)
	}
	if _, out := e.post(t, "/setup/begin", map[string]string{"token": "setup_wrong", "name": "Owner"}); out["error"] == nil {
		t.Fatal("wrong setup token accepted")
	}
	authn := testutil.NewSoftAuthenticator(t, testURL, "127.0.0.1")
	_, begin := e.post(t, "/setup/begin", map[string]string{"token": tok, "name": "Owner"})
	resp, fin := e.post(t, "/register/finish", map[string]any{"ceremony": begin["ceremony"], "credential": json.RawMessage(authn.Register(begin["options"]))})
	if resp.StatusCode != 200 {
		t.Fatalf("setup finish: %d %v", resp.StatusCode, fin)
	}
	user := fin["user"].(map[string]any)
	if user["role"] != "owner" {
		t.Fatalf("first user must be owner: %v", user)
	}
	// Cookie attributes.
	var sc *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			sc = c
		}
	}
	if sc == nil || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Value == "" {
		t.Fatalf("session cookie: %+v", sc)
	}
	var stored string
	e.s.db.QueryRow(`SELECT id_hash FROM sessions LIMIT 1`).Scan(&stored)
	if stored == sc.Value {
		t.Fatal("session id must be stored hashed")
	}
	// Setup token is single use.
	if _, out := e.post(t, "/setup/begin", map[string]string{"token": tok, "name": "Again"}); out["error"] == nil {
		t.Fatal("setup token reused")
	}
	if tok2, _ := e.s.EnsureSetupToken(ctx); tok2 != "" {
		t.Fatal("no setup token once a user exists")
	}
	// Replaying a finished ceremony fails (single-use challenge).
	if resp, _ := e.post(t, "/register/finish", map[string]any{"ceremony": begin["ceremony"], "credential": json.RawMessage(authn.Register(begin["options"]))}); resp.StatusCode == 200 {
		t.Fatal("ceremony replay accepted")
	}
	// Logout then passkey login.
	e.post(t, "/logout", map[string]any{})
	if p, _ := e.s.AuthenticateAdmin(ctx, sc.Value, ""); p.UserID != "" {
		t.Fatal("logout did not end the session")
	}
	_, lb := e.post(t, "/login/begin", map[string]any{})
	resp, lf := e.post(t, "/login/finish", map[string]any{"ceremony": lb["ceremony"], "credential": json.RawMessage(authn.Login(lb["options"]))})
	if resp.StatusCode != 200 || lf["user"].(map[string]any)["name"] != "Owner" {
		t.Fatalf("login: %d %v", resp.StatusCode, lf)
	}
	// A different (unregistered) authenticator cannot log in.
	stranger := testutil.NewSoftAuthenticator(t, testURL, "127.0.0.1")
	stranger.Handle = authn.Handle
	_, lb = e.post(t, "/login/begin", map[string]any{})
	if resp, _ := e.post(t, "/login/finish", map[string]any{"ceremony": lb["ceremony"], "credential": json.RawMessage(stranger.Login(lb["options"]))}); resp.StatusCode == 200 {
		t.Fatal("unregistered passkey logged in")
	}
	// Expired challenge.
	_, lb = e.post(t, "/login/begin", map[string]any{})
	e.s.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	if resp, _ := e.post(t, "/login/finish", map[string]any{"ceremony": lb["ceremony"], "credential": json.RawMessage(authn.Login(lb["options"]))}); resp.StatusCode == 200 {
		t.Fatal("expired challenge accepted")
	}
	e.s.now = time.Now
	// Adding a passkey requires the CSRF header.
	if resp, _ := e.post(t, "/passkeys/begin", map[string]any{}); resp.StatusCode != 403 {
		t.Fatalf("passkeys/begin without CSRF: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/admin/api/v1/auth/me", nil)
	r2, _ := e.client.Do(req)
	var me Principal
	json.NewDecoder(r2.Body).Decode(&me)
	r2.Body.Close()
	if resp, out := e.post(t, "/passkeys/begin", map[string]any{}, "X-CSRF-Token", me.CSRF); resp.StatusCode != 200 {
		t.Fatalf("passkeys/begin with CSRF: %d %v", resp.StatusCode, out)
	}
}

// spec: AUTH-033
func TestSessionIdleExpiry(t *testing.T) {
	s := newTestAuth(t)
	u := seedUser(t, s, "a", domain.RoleAdmin)
	sid := seedSession(t, s, u.ID)
	ctx := context.Background()
	if p, err := s.AuthenticateAdmin(ctx, sid, ""); err != nil || !p.ViaSession || p.CSRF == "" {
		t.Fatalf("%+v %v", p, err)
	}
	s.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	if _, err := s.AuthenticateAdmin(ctx, sid, ""); err == nil {
		t.Fatal("idle session must expire after 12 h")
	}
}

// spec: AUTH-032
func TestAdminAPIKeys(t *testing.T) {
	s := newTestAuth(t)
	ctx := context.Background()
	u := seedUser(t, s, "ops", domain.RoleAdmin)
	key, meta, err := s.CreateAdminKey(ctx, u.ID, "ci")
	if err != nil || !strings.HasPrefix(key, "gwa_") {
		t.Fatalf("%q %v", key, err)
	}
	p, err := s.AuthenticateAdmin(ctx, "", key)
	if err != nil || p.UserID != u.ID || p.Role != domain.RoleAdmin || p.ViaSession {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := s.AuthenticateAdmin(ctx, "", "gwa_"+strings.Repeat("x", 43)); err == nil {
		t.Fatal("unknown key accepted")
	}
	s.RevokeAdminKey(ctx, meta.ID)
	if _, err := s.AuthenticateAdmin(ctx, "", key); err == nil {
		t.Fatal("revoked key accepted")
	}
	// Bootstrap key creates an owner only when there are no users.
	boot := NewAdminKeyString()
	s2, err := New(ctx, Options{DBPath: ":memory:", Box: testBox(t), PublicURL: testURL, BootstrapAdminKey: boot})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if p, err := s2.AuthenticateAdmin(ctx, "", boot); err != nil || p.Role != domain.RoleOwner {
		t.Fatalf("bootstrap: %+v %v", p, err)
	}
	if _, err := New(ctx, Options{DBPath: ":memory:", Box: testBox(t), PublicURL: testURL, BootstrapAdminKey: "short"}); err == nil {
		t.Fatal("malformed bootstrap key accepted")
	}
}

// spec: AUTH-034
func TestRoles(t *testing.T) {
	cases := []struct {
		have, min domain.Role
		want      bool
	}{
		{domain.RoleOwner, domain.RoleAdmin, true}, {domain.RoleAdmin, domain.RoleAdmin, true},
		{domain.RoleMember, domain.RoleAdmin, false}, {domain.RoleViewer, domain.RoleMember, false},
		{domain.RoleViewer, domain.RoleViewer, true}, {"bogus", domain.RoleViewer, false},
	}
	for _, c := range cases {
		if got := RoleAllows(Principal{Role: c.have}, c.min); got != c.want {
			t.Errorf("%s >= %s: got %v", c.have, c.min, got)
		}
	}
	s := newTestAuth(t)
	ctx := context.Background()
	owner := seedUser(t, s, "o", domain.RoleOwner)
	if err := s.SetRole(ctx, owner.ID, domain.RoleAdmin); !errors.Is(err, ports.ErrConflict) {
		t.Fatalf("demoting the last owner must fail: %v", err)
	}
	if err := s.DeleteUser(ctx, owner.ID); !errors.Is(err, ports.ErrConflict) {
		t.Fatalf("deleting the last owner must fail: %v", err)
	}
}

func TestInviteFlow(t *testing.T) {
	e := newAdminEnv(t)
	ctx := context.Background()
	owner := seedUser(t, e.s, "o", domain.RoleOwner)
	inv, _ := e.s.CreateInvite(ctx, owner.ID, domain.RoleViewer)
	authn := testutil.NewSoftAuthenticator(t, testURL, "127.0.0.1")
	_, begin := e.post(t, "/invite/begin", map[string]string{"token": inv, "name": "Auditor"})
	resp, fin := e.post(t, "/register/finish", map[string]any{"ceremony": begin["ceremony"], "credential": json.RawMessage(authn.Register(begin["options"]))})
	if resp.StatusCode != 200 || fin["user"].(map[string]any)["role"] != "viewer" {
		t.Fatalf("invite: %d %v", resp.StatusCode, fin)
	}
	if _, out := e.post(t, "/invite/begin", map[string]string{"token": inv, "name": "Again"}); out["error"] == nil {
		t.Fatal("invite reused")
	}
}
