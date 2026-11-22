package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

// errUpstreamUnauthorized is returned when the upstream rejected the credential twice.
var errUpstreamUnauthorized = errors.New("the server rejected the stored credential; reconnect it in the dashboard")

// errCircuitOpen is returned while an upstream's circuit breaker is open (GW-013).
var errCircuitOpen = errors.New("server is temporarily unavailable after repeated failures; retrying automatically in a few seconds")

// stdioEnvAllowList are the only parent environment variables passed to stdio servers (GW-014).
var stdioEnvAllowList = []string{"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "USER", "SYSTEMROOT", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"}

// configHash identifies a server configuration; sessions are rebuilt when it changes.
func configHash(s domain.Server) string {
	b, _ := json.Marshal(struct {
		T    domain.Transport
		U, C string
		A    []string
		K    string
	}{s.Transport, s.URL, s.Command, s.Args, s.AuthKind})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// breaker is a consecutive-failure circuit breaker (GW-013).
type breaker struct {
	mu        sync.Mutex
	failures  int
	openUntil time.Time
}

const (
	breakerThreshold = 5
	breakerCooldown  = 30 * time.Second
)

func (b *breaker) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !now.Before(b.openUntil)
}

func (b *breaker) record(ok bool, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= breakerThreshold {
		b.openUntil = now.Add(breakerCooldown)
		b.failures = 0
	}
}

// session is one upstream MCP client session for (server, user).
type session struct {
	cs       *mcp.ClientSession
	lastUsed time.Time
	secrets  []string // injected secret values, for redaction
}

// pool manages upstream sessions and per-server breakers.
type pool struct {
	creds   ports.CredentialProvider
	version string
	now     func() time.Time

	mu         sync.Mutex
	sessions   map[string]*session
	connecting map[string]*sync.Mutex
	breakers   map[string]*breaker

	credMu    sync.Mutex
	credCache map[string]credEntry
}

type credEntry struct {
	cred  ports.Credential
	until time.Time
}

const (
	credCacheTTL    = 30 * time.Second
	sessionIdleTime = 10 * time.Minute
)

func newPool(creds ports.CredentialProvider, version string) *pool {
	return &pool{creds: creds, version: version, now: time.Now,
		sessions: map[string]*session{}, connecting: map[string]*sync.Mutex{}, breakers: map[string]*breaker{}, credCache: map[string]credEntry{}}
}

func (p *pool) breakerFor(serverID string) *breaker {
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.breakers[serverID]
	if b == nil {
		b = &breaker{}
		p.breakers[serverID] = b
	}
	return b
}

// credential returns a (cached) upstream credential. Servers with auth_kind none get an empty credential.
func (p *pool) credential(ctx context.Context, sv domain.Server, userID string) (ports.Credential, error) {
	if sv.AuthKind == "" || sv.AuthKind == "none" {
		return ports.Credential{}, nil
	}
	key := userID + "\x00" + sv.ID
	p.credMu.Lock()
	e, ok := p.credCache[key]
	p.credMu.Unlock()
	if ok && p.now().Before(e.until) && (e.cred.ExpiresAt.IsZero() || p.now().Before(e.cred.ExpiresAt.Add(-time.Minute))) {
		return e.cred, nil
	}
	c, err := p.creds.GetCredential(ctx, userID, sv.ID)
	if err != nil {
		return c, err
	}
	p.credMu.Lock()
	p.credCache[key] = credEntry{cred: c, until: p.now().Add(credCacheTTL)}
	p.credMu.Unlock()
	return c, nil
}

func (p *pool) dropCredential(sv domain.Server, userID string) {
	p.credMu.Lock()
	delete(p.credCache, userID+"\x00"+sv.ID)
	p.credMu.Unlock()
}

// credTransport injects the upstream credential on every request and handles one
// refresh-and-retry on 401 (GW-007, GW-009). Nothing from the client request is forwarded.
type credTransport struct {
	base     http.RoundTripper
	pool     *pool
	server   domain.Server
	userID   string
	onSecret func(string)
}

func applyCred(req *http.Request, c ports.Credential) {
	switch c.Kind {
	case ports.CredBearer, ports.CredOAuth:
		req.Header.Set("Authorization", "Bearer "+c.Token)
	case ports.CredHeader:
		req.Header.Set(c.HeaderName, c.HeaderValue)
	}
}

func (t *credTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	c, err := t.pool.credential(ctx, t.server, t.userID)
	if err != nil {
		return nil, err
	}
	for _, s := range c.Secrets() {
		t.onSecret(s)
	}
	r1 := req.Clone(ctx)
	applyCred(r1, c)
	resp, err := t.base.RoundTrip(r1)
	if err != nil || resp.StatusCode != http.StatusUnauthorized || c.Kind == "" {
		return resp, err
	}
	// 401: refresh once and retry once (GW-009).
	resp.Body.Close()
	t.pool.dropCredential(t.server, t.userID)
	nc, err := t.pool.creds.ForceRefresh(ctx, t.userID, t.server.ID)
	if err != nil {
		return nil, err
	}
	for _, s := range nc.Secrets() {
		t.onSecret(s)
	}
	r2 := req.Clone(ctx)
	if req.GetBody != nil {
		if r2.Body, err = req.GetBody(); err != nil {
			return nil, err
		}
	}
	applyCred(r2, nc)
	resp, err = t.base.RoundTrip(r2)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		_ = t.pool.creds.MarkNeedsReauth(context.WithoutCancel(ctx), t.userID, t.server.ID)
		t.pool.dropCredential(t.server, t.userID)
		return nil, errUpstreamUnauthorized
	}
	return resp, err
}

var sharedHTTPTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 256
	t.MaxIdleConnsPerHost = 64
	t.IdleConnTimeout = 90 * time.Second
	return t
}()

// get returns a connected session for (server, user), connecting if needed.
func (p *pool) get(ctx context.Context, sv domain.Server, userID string) (*session, error) {
	key := sv.ID + "\x00" + configHash(sv) + "\x00" + userID
	p.mu.Lock()
	if s := p.sessions[key]; s != nil {
		s.lastUsed = p.now()
		p.mu.Unlock()
		return s, nil
	}
	lock := p.connecting[key]
	if lock == nil {
		lock = &sync.Mutex{}
		p.connecting[key] = lock
	}
	p.mu.Unlock()

	lock.Lock() // one connect per key at a time
	defer lock.Unlock()
	p.mu.Lock()
	if s := p.sessions[key]; s != nil {
		p.mu.Unlock()
		return s, nil
	}
	p.mu.Unlock()

	s := &session{lastUsed: p.now()}
	var secMu sync.Mutex
	addSecret := func(v string) {
		secMu.Lock()
		defer secMu.Unlock()
		for _, x := range s.secrets {
			if x == v {
				return
			}
		}
		s.secrets = append(s.secrets, v)
	}
	var transport mcp.Transport
	switch sv.Transport {
	case domain.TransportHTTP:
		transport = &mcp.StreamableClientTransport{
			Endpoint:             sv.URL,
			HTTPClient:           &http.Client{Transport: &credTransport{base: sharedHTTPTransport, pool: p, server: sv, userID: userID, onSecret: addSecret}},
			MaxRetries:           1,
			DisableStandaloneSSE: true,
		}
	case domain.TransportStdio:
		c, err := p.credential(ctx, sv, userID)
		if err != nil {
			return nil, err
		}
		for _, v := range c.Secrets() {
			addSecret(v)
		}
		cmd := exec.Command(sv.Command, sv.Args...)
		cmd.Env = stdioEnv(c)
		transport = &mcp.CommandTransport{Command: cmd, TerminateDuration: 3 * time.Second}
	default:
		return nil, fmt.Errorf("unsupported transport %q", sv.Transport)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-gateway", Version: p.version}, nil)
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	cs, err := client.Connect(cctx, transport, nil)
	if err != nil {
		return nil, unwrapCredErr(err)
	}
	s.cs = cs
	p.mu.Lock()
	p.sessions[key] = s
	p.mu.Unlock()
	return s, nil
}

// unwrapCredErr surfaces credential errors that the SDK wrapped while connecting.
func unwrapCredErr(err error) error {
	for _, e := range []error{ports.ErrNoCredential, ports.ErrNeedsReauth, errUpstreamUnauthorized} {
		if errors.Is(err, e) || strings.Contains(err.Error(), e.Error()) {
			return e
		}
	}
	return err
}

func stdioEnv(c ports.Credential) []string {
	env := make([]string, 0, len(stdioEnvAllowList)+len(c.Env))
	for _, k := range stdioEnvAllowList {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for k, v := range c.Env {
		env = append(env, k+"="+v)
	}
	return env
}

// drop closes and forgets a session (after transport errors).
func (p *pool) drop(sv domain.Server, userID string) {
	key := sv.ID + "\x00" + configHash(sv) + "\x00" + userID
	p.mu.Lock()
	s := p.sessions[key]
	delete(p.sessions, key)
	p.mu.Unlock()
	if s != nil && s.cs != nil {
		go s.cs.Close()
	}
}

// reap closes idle sessions and sessions for configs that no longer exist.
func (p *pool) reap(valid map[string]bool) {
	now := p.now()
	p.mu.Lock()
	var closing []*session
	for k, s := range p.sessions {
		parts := strings.SplitN(k, "\x00", 3)
		if now.Sub(s.lastUsed) > sessionIdleTime || (valid != nil && !valid[parts[0]+"\x00"+parts[1]]) {
			closing = append(closing, s)
			delete(p.sessions, k)
		}
	}
	p.mu.Unlock()
	for _, s := range closing {
		if s.cs != nil {
			s.cs.Close()
		}
	}
}

func (p *pool) closeAll() {
	p.mu.Lock()
	all := p.sessions
	p.sessions = map[string]*session{}
	p.mu.Unlock()
	for _, s := range all {
		if s.cs != nil {
			s.cs.Close()
		}
	}
}
