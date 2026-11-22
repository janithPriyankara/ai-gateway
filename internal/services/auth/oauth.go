package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

const (
	codeTTL         = 60 * time.Second
	refreshTokenTTL = 90 * 24 * time.Hour
)

// OAuthError is an RFC 6749 error.
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	Status      int    `json:"-"`
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

func oerr(status int, code, desc string) *OAuthError {
	return &OAuthError{Code: code, Description: desc, Status: status}
}

// OAuthClient is a dynamically registered public client (AUTH-022).
type OAuthClient struct {
	ClientID     string    `json:"client_id"`
	Name         string    `json:"client_name"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"-"`
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLoopbackHost(u.Hostname())
	}
	return false
}

// RegisterClient implements Dynamic Client Registration (AUTH-022).
func (s *Service) RegisterClient(ctx context.Context, name string, redirectURIs []string) (OAuthClient, error) {
	if len(redirectURIs) == 0 || len(redirectURIs) > 10 {
		return OAuthClient{}, oerr(400, "invalid_redirect_uri", "between 1 and 10 redirect_uris are required")
	}
	for _, r := range redirectURIs {
		if !validRedirectURI(r) {
			return OAuthClient{}, oerr(400, "invalid_redirect_uri", "redirect URIs must be https, or http on a loopback address: "+r)
		}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "MCP client"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	c := OAuthClient{ClientID: "mcp_" + randomToken(16), Name: name, RedirectURIs: redirectURIs, CreatedAt: s.now()}
	uris, _ := json.Marshal(redirectURIs)
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_clients(client_id, name, redirect_uris, created_at) VALUES (?, ?, ?, ?)`, c.ClientID, c.Name, string(uris), c.CreatedAt.Unix())
	return c, err
}

func (s *Service) getOAuthClient(ctx context.Context, id string) (OAuthClient, error) {
	var c OAuthClient
	var uris string
	err := s.db.QueryRowContext(ctx, `SELECT client_id, name, redirect_uris FROM oauth_clients WHERE client_id=?`, id).Scan(&c.ClientID, &c.Name, &uris)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal([]byte(uris), &c.RedirectURIs)
	return c, err
}

// AuthorizeRequest is a validated /oauth/authorize request.
type AuthorizeRequest struct {
	Client      OAuthClient
	RedirectURI string
	State       string
	Challenge   string
	Resource    string
	Scope       string
}

// ValidateAuthorize checks an authorization request (AUTH-023, AUTH-028).
// If the error is an *OAuthError with redirect=true, it may be sent to the redirect URI;
// otherwise it must be shown to the user (unknown client / bad redirect URI).
func (s *Service) ValidateAuthorize(ctx context.Context, q url.Values) (AuthorizeRequest, error, bool) {
	c, err := s.getOAuthClient(ctx, q.Get("client_id"))
	if err != nil {
		return AuthorizeRequest{}, oerr(400, "invalid_client", "unknown client_id"), false
	}
	ru := q.Get("redirect_uri")
	match := false
	for _, r := range c.RedirectURIs {
		if r == ru {
			match = true
		}
	}
	if !match {
		return AuthorizeRequest{}, oerr(400, "invalid_request", "redirect_uri does not exactly match a registered URI"), false
	}
	r := AuthorizeRequest{Client: c, RedirectURI: ru, State: q.Get("state"), Challenge: q.Get("code_challenge"), Resource: q.Get("resource"), Scope: q.Get("scope")}
	switch {
	case q.Get("response_type") != "code":
		return r, oerr(400, "unsupported_response_type", "only response_type=code is supported"), true
	case r.State == "":
		return r, oerr(400, "invalid_request", "state is required"), true
	case r.Challenge == "" || len(r.Challenge) < 43 || len(r.Challenge) > 128:
		return r, oerr(400, "invalid_request", "a code_challenge (PKCE) is required"), true
	case q.Get("code_challenge_method") != "S256":
		return r, oerr(400, "invalid_request", "code_challenge_method must be S256"), true
	case r.Resource != "" && r.Resource != s.resource:
		return r, oerr(400, "invalid_target", "resource must be "+s.resource), true
	}
	return r, nil, true
}

// IssueCode creates a single-use authorization code after the user consented (AUTH-024, AUTH-025).
func (s *Service) IssueCode(ctx context.Context, r AuthorizeRequest, userID, profile string) (string, error) {
	if strings.TrimSpace(profile) == "" {
		return "", fmt.Errorf("%w: profile is required", ports.ErrInvalid)
	}
	code := randomToken(32)
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_codes(code_hash, oauth_client_id, user_id, profile, redirect_uri, challenge, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sha(code), r.Client.ClientID, userID, profile, r.RedirectURI, r.Challenge, r.Resource, s.now().Add(codeTTL).Unix())
	if err != nil {
		return "", err
	}
	q := url.Values{"code": {code}, "state": {r.State}, "iss": {s.issuer}}
	sep := "?"
	if strings.Contains(r.RedirectURI, "?") {
		sep = "&"
	}
	return r.RedirectURI + sep + q.Encode(), nil
}

// TokenResponse is the /oauth/token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ExchangeCode implements grant_type=authorization_code (AUTH-025, AUTH-026).
func (s *Service) ExchangeCode(ctx context.Context, code, verifier, clientID, redirectURI, resource string) (TokenResponse, error) {
	client, cerr := s.getOAuthClient(ctx, clientID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TokenResponse{}, err
	}
	defer tx.Rollback()
	var oc, userID, profile, ru, challenge, res, family string
	var exp int64
	var used int
	err = tx.QueryRowContext(ctx, `SELECT oauth_client_id, user_id, profile, redirect_uri, challenge, resource, expires_at, used, family_id FROM auth_codes WHERE code_hash=?`, sha(code)).
		Scan(&oc, &userID, &profile, &ru, &challenge, &res, &exp, &used, &family)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenResponse{}, oerr(400, "invalid_grant", "unknown authorization code")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if used != 0 {
		// Code replay: revoke everything issued from the first use (AUTH-025).
		if family != "" {
			_, _ = tx.ExecContext(ctx, `UPDATE token_families SET revoked=1 WHERE id=?`, family)
			_ = tx.Commit()
			s.flushCache()
		}
		return TokenResponse{}, oerr(400, "invalid_grant", "authorization code already used")
	}
	switch {
	case s.now().Unix() > exp:
		return TokenResponse{}, oerr(400, "invalid_grant", "authorization code expired")
	case oc != clientID:
		return TokenResponse{}, oerr(400, "invalid_grant", "code was issued to another client")
	case ru != redirectURI:
		return TokenResponse{}, oerr(400, "invalid_grant", "redirect_uri mismatch")
	case verifier == "" || pkceS256(verifier) != challenge:
		return TokenResponse{}, oerr(400, "invalid_grant", "PKCE verification failed")
	case resource != "" && resource != s.resource:
		return TokenResponse{}, oerr(400, "invalid_target", "resource must be "+s.resource)
	}
	if cerr != nil {
		return TokenResponse{}, oerr(400, "invalid_client", "unknown client")
	}
	// One client record per (user, OAuth client): reuse it across re-authorizations.
	var recID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM clients WHERE user_id=? AND oauth_client_id=? AND revoked_at=0`, userID, clientID).Scan(&recID)
	now := s.now()
	if errors.Is(err, sql.ErrNoRows) {
		recID = newID("cli_")
		if _, err := tx.ExecContext(ctx, `INSERT INTO clients(id, user_id, name, profile, kind, oauth_client_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			recID, userID, client.Name, profile, clientKindOAuth, clientID, now.Unix()); err != nil {
			return TokenResponse{}, err
		}
	} else if err != nil {
		return TokenResponse{}, err
	} else if _, err := tx.ExecContext(ctx, `UPDATE clients SET profile=? WHERE id=?`, profile, recID); err != nil {
		return TokenResponse{}, err
	}
	family = newID("fam_")
	if _, err := tx.ExecContext(ctx, `INSERT INTO token_families(id, client_rec_id, created_at) VALUES (?, ?, ?)`, family, recID, now.Unix()); err != nil {
		return TokenResponse{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_codes SET used=1, family_id=? WHERE code_hash=?`, family, sha(code)); err != nil {
		return TokenResponse{}, err
	}
	resp, err := s.issueTokens(ctx, tx, family, domain.Identity{UserID: userID, ClientID: recID, ClientName: client.Name, Profile: profile})
	if err != nil {
		return TokenResponse{}, err
	}
	if err := tx.Commit(); err != nil {
		return TokenResponse{}, err
	}
	s.flushCache()
	return resp, nil
}

func (s *Service) issueTokens(ctx context.Context, tx *sql.Tx, family string, id domain.Identity) (TokenResponse, error) {
	at, err := s.issueAccessToken(id)
	if err != nil {
		return TokenResponse{}, err
	}
	rt := "gwr_" + randomToken(32)
	if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_tokens(token_hash, family_id, expires_at) VALUES (?, ?, ?)`, sha(rt), family, s.now().Add(refreshTokenTTL).Unix()); err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: at, TokenType: "Bearer", ExpiresIn: int(accessTokenTTL.Seconds()), RefreshToken: rt}, nil
}

// Refresh implements grant_type=refresh_token with rotation and reuse detection (AUTH-027).
func (s *Service) Refresh(ctx context.Context, refreshToken, clientID string) (TokenResponse, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TokenResponse{}, err
	}
	defer tx.Rollback()
	var family, recID, userID, profile, name, oc string
	var used, famRevoked int
	var exp, cliRevoked int64
	err = tx.QueryRowContext(ctx, `SELECT r.family_id, r.used, r.expires_at, f.revoked, c.id, c.user_id, c.profile, c.name, c.oauth_client_id, c.revoked_at
		FROM refresh_tokens r JOIN token_families f ON f.id = r.family_id JOIN clients c ON c.id = f.client_rec_id WHERE r.token_hash=?`, sha(refreshToken)).
		Scan(&family, &used, &exp, &famRevoked, &recID, &userID, &profile, &name, &oc, &cliRevoked)
	if err != nil {
		return TokenResponse{}, oerr(400, "invalid_grant", "unknown refresh token")
	}
	if oc != clientID {
		return TokenResponse{}, oerr(400, "invalid_grant", "refresh token was issued to another client")
	}
	if used != 0 {
		_, _ = tx.ExecContext(ctx, `UPDATE token_families SET revoked=1 WHERE id=?`, family)
		_ = tx.Commit()
		s.flushCache()
		s.log.Warn("refresh token reuse detected; token family revoked", "client", recID)
		return TokenResponse{}, oerr(400, "invalid_grant", "refresh token already used; all tokens for this grant were revoked")
	}
	if famRevoked != 0 || cliRevoked != 0 || s.now().Unix() > exp {
		return TokenResponse{}, oerr(400, "invalid_grant", "refresh token revoked or expired")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET used=1 WHERE token_hash=?`, sha(refreshToken)); err != nil {
		return TokenResponse{}, err
	}
	resp, err := s.issueTokens(ctx, tx, family, domain.Identity{UserID: userID, ClientID: recID, ClientName: name, Profile: profile})
	if err != nil {
		return TokenResponse{}, err
	}
	return resp, tx.Commit()
}
