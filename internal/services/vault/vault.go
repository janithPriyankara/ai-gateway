// Package vault stores upstream credentials sealed with the key box and keeps
// OAuth tokens fresh. It is the only service that ever sees upstream secrets.
package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/mcp-gateway/mcp-gateway/internal/keybox"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
	"github.com/mcp-gateway/mcp-gateway/internal/store"
)

// Credential statuses.
const (
	StatusOK          = "ok"
	StatusNeedsReauth = "needs_reauth"
)

var migrations = []string{
	`CREATE TABLE credentials (
		user_id    TEXT NOT NULL,
		server_id  TEXT NOT NULL,
		kind       TEXT NOT NULL,
		sealed     BLOB NOT NULL,
		status     TEXT NOT NULL DEFAULT 'ok',
		expires_at INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (user_id, server_id)
	);
	CREATE TABLE oauth_apps (
		server_id     TEXT PRIMARY KEY,
		auth_url      TEXT NOT NULL,
		token_url     TEXT NOT NULL,
		client_id     TEXT NOT NULL,
		scopes        TEXT NOT NULL DEFAULT '',
		redirect_url  TEXT NOT NULL,
		sealed_secret BLOB
	);
	CREATE TABLE oauth_states (
		state           TEXT PRIMARY KEY,
		user_id         TEXT NOT NULL,
		server_id       TEXT NOT NULL,
		sealed_verifier BLOB NOT NULL,
		expires_at      INTEGER NOT NULL
	);`,
}

// Options configures the vault.
type Options struct {
	DBPath     string
	Box        *keybox.Box
	HTTPClient *http.Client
}

// Service is the vault.
type Service struct {
	db  *sql.DB
	box *keybox.Box
	hc  *http.Client
	sf  singleflight.Group
	now func() time.Time
}

// New opens the vault database.
func New(ctx context.Context, o Options) (*Service, error) {
	if o.Box == nil {
		return nil, errors.New("vault: key box is required")
	}
	db, err := store.Open(ctx, o.DBPath, migrations)
	if err != nil {
		return nil, err
	}
	hc := o.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	return &Service{db: db, box: o.Box, hc: hc, now: time.Now}, nil
}

// Close closes the database.
func (s *Service) Close() error { return s.db.Close() }

// Ping checks the database (readiness).
func (s *Service) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Box exposes the key box (for health reporting).
func (s *Service) Box() *keybox.Box { return s.box }

// payload is what gets sealed.
type payload struct {
	ports.Credential
	OAuth *oauthTokens `json:"oauth,omitempty"`
}

type oauthTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

var headerNameRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func validate(c ports.Credential) error {
	switch c.Kind {
	case ports.CredBearer:
		if c.Token == "" {
			return fmt.Errorf("%w: bearer credential needs a token", ports.ErrInvalid)
		}
	case ports.CredHeader:
		if !headerNameRE.MatchString(c.HeaderName) || c.HeaderValue == "" {
			return fmt.Errorf("%w: header credential needs a valid header name and a value", ports.ErrInvalid)
		}
		switch strings.ToLower(c.HeaderName) {
		case "host", "content-length", "mcp-session-id", "connection":
			return fmt.Errorf("%w: header %q cannot be set", ports.ErrInvalid, c.HeaderName)
		}
	case ports.CredEnv:
		if len(c.Env) == 0 {
			return fmt.Errorf("%w: env credential needs at least one variable", ports.ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unknown credential kind %q", ports.ErrInvalid, c.Kind)
	}
	return nil
}

func aad(user, server string) []byte { return []byte("cred|" + user + "|" + server) }

// SetCredential stores a static credential (bearer, header or env). Empty user = shared.
func (s *Service) SetCredential(ctx context.Context, user, server string, c ports.Credential) error {
	if err := validate(c); err != nil {
		return err
	}
	return s.put(ctx, user, server, payload{Credential: c})
}

func (s *Service) put(ctx context.Context, user, server string, p payload) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	sealed, err := s.box.Seal(ctx, raw, aad(user, server))
	if err != nil {
		return err
	}
	var exp int64
	if p.OAuth != nil {
		exp = p.OAuth.ExpiresAt.Unix()
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO credentials(user_id, server_id, kind, sealed, status, expires_at, updated_at)
		VALUES (?, ?, ?, ?, 'ok', ?, ?)
		ON CONFLICT(user_id, server_id) DO UPDATE SET kind=excluded.kind, sealed=excluded.sealed,
		status='ok', expires_at=excluded.expires_at, updated_at=excluded.updated_at`,
		user, server, p.Kind, sealed, exp, s.now().Unix())
	return err
}

func (s *Service) storeOAuth(ctx context.Context, user, server string, t oauthTokens) error {
	return s.put(ctx, user, server, payload{Credential: ports.Credential{Kind: ports.CredOAuth}, OAuth: &t})
}

// DeleteCredential removes one credential.
func (s *Service) DeleteCredential(ctx context.Context, user, server string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE user_id=? AND server_id=?`, user, server)
	return err
}

// DeleteServer removes every credential and the OAuth app of a server (VLT-009).
func (s *Service) DeleteServer(ctx context.Context, server string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM credentials WHERE server_id=?`, `DELETE FROM oauth_apps WHERE server_id=?`, `DELETE FROM oauth_states WHERE server_id=?`} {
		if _, err := tx.ExecContext(ctx, q, server); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CredentialInfo is credential metadata, safe to show (VLT-008).
type CredentialInfo struct {
	UserID    string    `json:"user_id"`
	ServerID  string    `json:"server_id"`
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListCredentials lists credential metadata, optionally for one server.
func (s *Service) ListCredentials(ctx context.Context, server string) ([]CredentialInfo, error) {
	q := `SELECT user_id, server_id, kind, status, expires_at, updated_at FROM credentials`
	var args []any
	if server != "" {
		q += ` WHERE server_id=?`
		args = append(args, server)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY server_id, user_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CredentialInfo
	for rows.Next() {
		var ci CredentialInfo
		var exp, upd int64
		if err := rows.Scan(&ci.UserID, &ci.ServerID, &ci.Kind, &ci.Status, &exp, &upd); err != nil {
			return nil, err
		}
		ci.ExpiresAt, ci.UpdatedAt = store.TimeOrZero(exp), store.TimeOrZero(upd)
		out = append(out, ci)
	}
	return out, rows.Err()
}

func (s *Service) load(ctx context.Context, user, server string) (payload, string, error) {
	var sealed []byte
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT sealed, status FROM credentials WHERE user_id=? AND server_id=?`, user, server).Scan(&sealed, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return payload{}, "", ports.ErrNoCredential
	}
	if err != nil {
		return payload{}, "", err
	}
	raw, err := s.box.Open(ctx, sealed, aad(user, server))
	if err != nil {
		return payload{}, "", err
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return payload{}, "", err
	}
	return p, status, nil
}

// resolveOwner returns the user id whose credential applies: the user's own, else shared ("").
func (s *Service) resolveOwner(ctx context.Context, user, server string) (string, error) {
	var owner string
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM credentials WHERE server_id=? AND user_id IN (?, '') ORDER BY user_id DESC LIMIT 1`, server, user).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ports.ErrNoCredential
	}
	return owner, err
}

// GetCredential implements ports.CredentialProvider (VLT-003, VLT-005).
func (s *Service) GetCredential(ctx context.Context, user, server string) (ports.Credential, error) {
	owner, err := s.resolveOwner(ctx, user, server)
	if err != nil {
		return ports.Credential{}, err
	}
	p, status, err := s.load(ctx, owner, server)
	if err != nil {
		return ports.Credential{}, err
	}
	if status == StatusNeedsReauth {
		return ports.Credential{}, ports.ErrNeedsReauth
	}
	if p.Kind != ports.CredOAuth || p.OAuth == nil {
		return p.Credential, nil
	}
	if !s.needsRefresh(*p.OAuth) {
		return oauthCred(*p.OAuth), nil
	}
	return s.refresh(ctx, owner, server)
}

// ForceRefresh implements ports.CredentialProvider (GW-009).
func (s *Service) ForceRefresh(ctx context.Context, user, server string) (ports.Credential, error) {
	owner, err := s.resolveOwner(ctx, user, server)
	if err != nil {
		return ports.Credential{}, err
	}
	p, _, err := s.load(ctx, owner, server)
	if err != nil {
		return ports.Credential{}, err
	}
	if p.Kind != ports.CredOAuth || p.OAuth == nil || p.OAuth.RefreshToken == "" {
		s.markNeedsReauth(ctx, owner, server)
		return ports.Credential{}, ports.ErrNeedsReauth
	}
	return s.refresh(ctx, owner, server)
}

// MarkNeedsReauth implements ports.CredentialProvider (GW-009).
func (s *Service) MarkNeedsReauth(ctx context.Context, user, server string) error {
	owner, err := s.resolveOwner(ctx, user, server)
	if err != nil {
		return err
	}
	s.markNeedsReauth(ctx, owner, server)
	return nil
}
func (s *Service) needsRefresh(t oauthTokens) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	life := t.ExpiresAt.Sub(t.IssuedAt)
	left := t.ExpiresAt.Sub(s.now())
	return left < life/5
}

func oauthCred(t oauthTokens) ports.Credential {
	return ports.Credential{Kind: ports.CredOAuth, Token: t.AccessToken, ExpiresAt: t.ExpiresAt}
}

func (s *Service) markNeedsReauth(ctx context.Context, user, server string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE credentials SET status='needs_reauth', updated_at=? WHERE user_id=? AND server_id=?`, s.now().Unix(), user, server)
}

// refresh exchanges the refresh token once per (user, server) at a time (single-flight).
func (s *Service) refresh(ctx context.Context, owner, server string) (ports.Credential, error) {
	v, err, _ := s.sf.Do(owner+"\x00"+server, func() (any, error) {
		// Re-read inside the flight: another flight may have just refreshed.
		p, status, err := s.load(ctx, owner, server)
		if err != nil {
			return nil, err
		}
		if status == StatusNeedsReauth {
			return nil, ports.ErrNeedsReauth
		}
		app, err := s.getOAuthApp(ctx, server)
		if err != nil {
			s.markNeedsReauth(ctx, owner, server)
			return nil, ports.ErrNeedsReauth
		}
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {p.OAuth.RefreshToken}, "client_id": {app.ClientID}}
		tok, err := s.tokenRequest(ctx, app, form)
		if err != nil {
			var oe *oauthError
			if errors.As(err, &oe) && (oe.Code == "invalid_grant" || oe.Code == "invalid_client" || oe.Code == "unauthorized_client") {
				s.markNeedsReauth(ctx, owner, server)
				return nil, ports.ErrNeedsReauth
			}
			return nil, err
		}
		if tok.RefreshToken == "" {
			tok.RefreshToken = p.OAuth.RefreshToken // servers may omit it when not rotating
		}
		if err := s.storeOAuth(ctx, owner, server, tok); err != nil {
			return nil, err
		}
		return oauthCred(tok), nil
	})
	if err != nil {
		return ports.Credential{}, err
	}
	return v.(ports.Credential), nil
}

// OAuthApp is the gateway's OAuth client registration at an upstream server.
type OAuthApp struct {
	ServerID     string   `json:"server_id"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes"`
	RedirectURL  string   `json:"redirect_url"`
}

// SetOAuthApp stores the OAuth client configuration for a server.
func (s *Service) SetOAuthApp(ctx context.Context, a OAuthApp) error {
	for _, u := range []string{a.AuthURL, a.TokenURL, a.RedirectURL} {
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" {
			return fmt.Errorf("%w: invalid URL %q", ports.ErrInvalid, u)
		}
	}
	if a.ClientID == "" {
		return fmt.Errorf("%w: client_id is required", ports.ErrInvalid)
	}
	var sealed []byte
	if a.ClientSecret != "" {
		var err error
		if sealed, err = s.box.Seal(ctx, []byte(a.ClientSecret), []byte("oauthapp|"+a.ServerID)); err != nil {
			return err
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_apps(server_id, auth_url, token_url, client_id, scopes, redirect_url, sealed_secret)
		VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(server_id) DO UPDATE SET auth_url=excluded.auth_url, token_url=excluded.token_url,
		client_id=excluded.client_id, scopes=excluded.scopes, redirect_url=excluded.redirect_url, sealed_secret=excluded.sealed_secret`,
		a.ServerID, a.AuthURL, a.TokenURL, a.ClientID, strings.Join(a.Scopes, " "), a.RedirectURL, sealed)
	return err
}

func (s *Service) getOAuthApp(ctx context.Context, server string) (OAuthApp, error) {
	var a OAuthApp
	var scopes string
	var sealed []byte
	err := s.db.QueryRowContext(ctx, `SELECT server_id, auth_url, token_url, client_id, scopes, redirect_url, sealed_secret FROM oauth_apps WHERE server_id=?`, server).
		Scan(&a.ServerID, &a.AuthURL, &a.TokenURL, &a.ClientID, &scopes, &a.RedirectURL, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return a, fmt.Errorf("%w: no OAuth app configured for server %q", ports.ErrNotFound, server)
	}
	if err != nil {
		return a, err
	}
	if scopes != "" {
		a.Scopes = strings.Fields(scopes)
	}
	if len(sealed) > 0 {
		sec, err := s.box.Open(ctx, sealed, []byte("oauthapp|"+server))
		if err != nil {
			return a, err
		}
		a.ClientSecret = string(sec)
	}
	return a, nil
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// StartConnect begins the upstream OAuth flow (VLT-007) and returns the URL to send the user to.
func (s *Service) StartConnect(ctx context.Context, user, server string) (string, error) {
	app, err := s.getOAuthApp(ctx, server)
	if err != nil {
		return "", err
	}
	state := randomString(24)
	verifier := randomString(48)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	sealed, err := s.box.Seal(ctx, []byte(verifier), []byte("state|"+state))
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO oauth_states(state, user_id, server_id, sealed_verifier, expires_at) VALUES (?, ?, ?, ?, ?)`,
		state, user, server, sealed, s.now().Add(10*time.Minute).Unix()); err != nil {
		return "", err
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE expires_at < ?`, s.now().Unix())
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {app.ClientID},
		"redirect_uri":          {app.RedirectURL},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if len(app.Scopes) > 0 {
		q.Set("scope", strings.Join(app.Scopes, " "))
	}
	sep := "?"
	if strings.Contains(app.AuthURL, "?") {
		sep = "&"
	}
	return app.AuthURL + sep + q.Encode(), nil
}

// CompleteConnect finishes the upstream OAuth flow and stores the tokens. It returns the server id.
func (s *Service) CompleteConnect(ctx context.Context, state, code string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var user, server string
	var sealed []byte
	var exp int64
	err = tx.QueryRowContext(ctx, `SELECT user_id, server_id, sealed_verifier, expires_at FROM oauth_states WHERE state=?`, state).Scan(&user, &server, &sealed, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: unknown or already used OAuth state", ports.ErrInvalid)
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oauth_states WHERE state=?`, state); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	if s.now().Unix() > exp {
		return "", fmt.Errorf("%w: OAuth state expired; start the connection again", ports.ErrInvalid)
	}
	verifier, err := s.box.Open(ctx, sealed, []byte("state|"+state))
	if err != nil {
		return "", err
	}
	app, err := s.getOAuthApp(ctx, server)
	if err != nil {
		return "", err
	}
	tok, err := s.tokenRequest(ctx, app, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {app.RedirectURL},
		"client_id": {app.ClientID}, "code_verifier": {string(verifier)},
	})
	if err != nil {
		return "", err
	}
	if err := s.storeOAuth(ctx, user, server, tok); err != nil {
		return "", err
	}
	return server, nil
}

type oauthError struct {
	Code   string
	Status int
}

func (e *oauthError) Error() string {
	return fmt.Sprintf("upstream token endpoint: %s (HTTP %d)", e.Code, e.Status)
}

func (s *Service) tokenRequest(ctx context.Context, app OAuthApp, form url.Values) (oauthTokens, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, app.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauthTokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if app.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(app.ClientID), url.QueryEscape(app.ClientSecret))
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return oauthTokens{}, fmt.Errorf("upstream token endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&body); err != nil {
		return oauthTokens{}, &oauthError{Code: "invalid_response", Status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		code := body.Error
		if code == "" {
			code = "invalid_response"
		}
		return oauthTokens{}, &oauthError{Code: code, Status: resp.StatusCode}
	}
	now := s.now()
	t := oauthTokens{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken, IssuedAt: now}
	if body.ExpiresIn > 0 {
		t.ExpiresAt = now.Add(time.Duration(body.ExpiresIn) * time.Second)
	}
	return t, nil
}
