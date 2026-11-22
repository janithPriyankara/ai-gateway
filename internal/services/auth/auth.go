// Package auth authenticates AI clients (static tokens, OAuth 2.1 access tokens)
// and dashboard users (passkeys, sessions, admin API keys). It is the gateway's
// OAuth 2.1 authorization server.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/argon2"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/keybox"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
	"github.com/mcp-gateway/mcp-gateway/internal/store"
)

var migrations = []string{
	`CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, webauthn_id BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL);
	CREATE TABLE passkeys (id BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, data TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE sessions (id_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL);
	CREATE TABLE ceremonies (id TEXT PRIMARY KEY, kind TEXT NOT NULL, user_id TEXT NOT NULL, data TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL);
	CREATE TABLE admin_keys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, prefix TEXT NOT NULL UNIQUE, hash BLOB NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE setup (id INTEGER PRIMARY KEY CHECK (id = 1), token_hash TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE invites (token_hash TEXT PRIMARY KEY, role TEXT NOT NULL, created_by TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE clients (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, profile TEXT NOT NULL, kind TEXT NOT NULL,
		prefix TEXT UNIQUE, hash BLOB, oauth_client_id TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL DEFAULT 0, revoked_at INTEGER NOT NULL DEFAULT 0);
	CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, created_at INTEGER NOT NULL);
	CREATE TABLE auth_codes (code_hash TEXT PRIMARY KEY, oauth_client_id TEXT NOT NULL, user_id TEXT NOT NULL, profile TEXT NOT NULL, redirect_uri TEXT NOT NULL,
		challenge TEXT NOT NULL, resource TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, family_id TEXT NOT NULL DEFAULT '');
	CREATE TABLE token_families (id TEXT PRIMARY KEY, client_rec_id TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
	CREATE TABLE refresh_tokens (token_hash TEXT PRIMARY KEY, family_id TEXT NOT NULL REFERENCES token_families(id) ON DELETE CASCADE, used INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL);
	CREATE TABLE signing_keys (kid TEXT PRIMARY KEY, sealed_private BLOB NOT NULL, public_jwk TEXT NOT NULL, created_at INTEGER NOT NULL, retired_at INTEGER NOT NULL DEFAULT 0);`,
}

// Options configures the auth service.
type Options struct {
	DBPath    string
	Box       *keybox.Box
	PublicURL string // e.g. http://127.0.0.1:8787 — issuer and resource base
	Logger    *slog.Logger
	// BootstrapAdminKey, if set and no users exist, creates an owner with this admin API key (CI/automation).
	BootstrapAdminKey string
}

// Service is the auth service.
type Service struct {
	db        *sql.DB
	box       *keybox.Box
	publicURL string
	issuer    string
	resource  string
	log       *slog.Logger
	wa        *webauthn.WebAuthn
	now       func() time.Time

	keysMu sync.RWMutex
	keys   *keySet

	cacheMu sync.Mutex
	cache   map[string]cacheEntry // token hash -> identity (AUTH-003), client id -> revoked
	seen    map[string]time.Time
}

type cacheEntry struct {
	id      domain.Identity
	revoked bool
	until   time.Time
}

// New opens the auth database and loads (or creates) signing keys.
func New(ctx context.Context, o Options) (*Service, error) {
	if o.Box == nil {
		return nil, errors.New("auth: key box is required")
	}
	pu, err := url.Parse(strings.TrimRight(o.PublicURL, "/"))
	if err != nil || pu.Host == "" {
		return nil, fmt.Errorf("auth: invalid public URL %q", o.PublicURL)
	}
	db, err := store.Open(ctx, o.DBPath, migrations)
	if err != nil {
		return nil, err
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	base := pu.String()
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "mcp-gateway",
		RPID:          pu.Hostname(),
		RPOrigins:     []string{pu.Scheme + "://" + pu.Host},
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	s := &Service{db: db, box: o.Box, publicURL: base, issuer: base, resource: base + "/mcp", log: log, wa: wa, now: time.Now,
		cache: map[string]cacheEntry{}, seen: map[string]time.Time{}}
	if err := s.loadKeys(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if o.BootstrapAdminKey != "" {
		if err := s.bootstrapAdmin(ctx, o.BootstrapAdminKey); err != nil {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close closes the database.
func (s *Service) Close() error { return s.db.Close() }

// Ping checks the database (readiness).
func (s *Service) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Resource is the MCP resource URL (token audience).
func (s *Service) Resource() string { return s.resource }

// Issuer is the OAuth issuer URL.
func (s *Service) Issuer() string { return s.issuer }

// --- helpers ---------------------------------------------------------------

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newID(prefix string) string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Argon2id parameters for high-entropy secrets (tokens). Light, because the
// input already has 256 bits of entropy; the hash protects against DB theft.
const (
	tokArgonTime   = 1
	tokArgonMemory = 8 * 1024
	tokArgonPar    = 2
)

func hashSecret(secret string) []byte {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	h := argon2.IDKey([]byte(secret), salt, tokArgonTime, tokArgonMemory, tokArgonPar, 32)
	return append(salt, h...)
}

func checkSecret(secret string, stored []byte) bool {
	if len(stored) != 48 {
		return false
	}
	h := argon2.IDKey([]byte(secret), stored[:16], tokArgonTime, tokArgonMemory, tokArgonPar, 32)
	return subtle.ConstantTimeCompare(h, stored[16:]) == 1
}

// splitToken splits "gw_XXXXXXXX..." into its lookup prefix. ok=false if malformed.
func splitToken(tok, kind string) (prefix string, ok bool) {
	if !strings.HasPrefix(tok, kind) || len(tok) != len(kind)+43 {
		return "", false
	}
	return tok[len(kind) : len(kind)+8], true
}

// --- users -----------------------------------------------------------------

// waUser adapts a user to webauthn.User.
type waUser struct {
	domain.User
	handle []byte
	creds  []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.handle }
func (u *waUser) WebAuthnName() string                       { return u.Name }
func (u *waUser) WebAuthnDisplayName() string                { return u.Name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Service) createUser(ctx context.Context, tx *sql.Tx, name string, role domain.Role) (domain.User, []byte, error) {
	if !role.Valid() {
		return domain.User{}, nil, fmt.Errorf("%w: unknown role %q", ports.ErrInvalid, role)
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return domain.User{}, nil, fmt.Errorf("%w: name must be 1-80 characters", ports.ErrInvalid)
	}
	u := domain.User{ID: newID("usr_"), Name: name, Role: role, CreatedAt: s.now().UTC().Truncate(time.Second)}
	handle := make([]byte, 32)
	_, _ = rand.Read(handle)
	_, err := tx.ExecContext(ctx, `INSERT INTO users(id, name, role, webauthn_id, created_at) VALUES (?, ?, ?, ?, ?)`, u.ID, u.Name, u.Role, handle, u.CreatedAt.Unix())
	return u, handle, err
}

// CreateUser creates a user without a passkey (CLI and tests). Such a user can own
// AI-tool tokens and admin API keys, and can add a passkey later via an invite.
func (s *Service) CreateUser(ctx context.Context, name string, role domain.Role) (domain.User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.User{}, err
	}
	defer tx.Rollback()
	u, _, err := s.createUser(ctx, tx, name, role)
	if err != nil {
		return u, err
	}
	return u, tx.Commit()
}

// GetUser returns one user.
func (s *Service) GetUser(ctx context.Context, id string) (domain.User, error) {
	var u domain.User
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, role, created_at FROM users WHERE id=?`, id).Scan(&u.ID, &u.Name, &u.Role, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return u, fmt.Errorf("%w: user", ports.ErrNotFound)
	}
	u.CreatedAt = store.TimeOrZero(created)
	return u, err
}

// ListUsers lists users.
func (s *Service) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, role, created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.User{}
	for rows.Next() {
		var u domain.User
		var created int64
		if err := rows.Scan(&u.ID, &u.Name, &u.Role, &created); err != nil {
			return nil, err
		}
		u.CreatedAt = store.TimeOrZero(created)
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers returns the number of users.
func (s *Service) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// SetRole changes a user's role. The last owner cannot be demoted.
func (s *Service) SetRole(ctx context.Context, userID string, role domain.Role) error {
	if !role.Valid() {
		return fmt.Errorf("%w: unknown role %q", ports.ErrInvalid, role)
	}
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.Role == domain.RoleOwner && role != domain.RoleOwner {
		var owners int
		s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='owner'`).Scan(&owners)
		if owners <= 1 {
			return fmt.Errorf("%w: cannot demote the last owner", ports.ErrConflict)
		}
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET role=? WHERE id=?`, role, userID)
	return err
}

// DeleteUser removes a user, their sessions, passkeys and keys, and revokes their clients.
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.Role == domain.RoleOwner {
		var owners int
		s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='owner'`).Scan(&owners)
		if owners <= 1 {
			return fmt.Errorf("%w: cannot delete the last owner", ports.ErrConflict)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE clients SET revoked_at=? WHERE user_id=? AND revoked_at=0`, s.now().Unix(), userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, userID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.flushCache()
	return nil
}

func (s *Service) flushCache() {
	s.cacheMu.Lock()
	s.cache = map[string]cacheEntry{}
	s.cacheMu.Unlock()
}

// --- setup token, invites, bootstrap ---------------------------------------

// EnsureSetupToken returns a fresh one-time setup token if no users exist (AUTH-030).
// It returns "" when setup is already complete.
func (s *Service) EnsureSetupToken(ctx context.Context) (string, error) {
	n, err := s.CountUsers(ctx)
	if err != nil || n > 0 {
		return "", err
	}
	tok := "setup_" + randomToken(24)
	_, err = s.db.ExecContext(ctx, `INSERT INTO setup(id, token_hash, used) VALUES (1, ?, 0) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash, used=0`, sha(tok))
	return tok, err
}

func (s *Service) consumeSetupToken(ctx context.Context, tx *sql.Tx, tok string) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: setup is already complete", ports.ErrForbidden)
	}
	res, err := tx.ExecContext(ctx, `UPDATE setup SET used=1 WHERE id=1 AND used=0 AND token_hash=?`, sha(tok))
	if err != nil {
		return err
	}
	if c, _ := res.RowsAffected(); c == 0 {
		return fmt.Errorf("%w: invalid setup token", ports.ErrForbidden)
	}
	return nil
}

// CreateInvite creates a one-time invite link token for a new user with role.
func (s *Service) CreateInvite(ctx context.Context, by string, role domain.Role) (string, error) {
	if !role.Valid() {
		return "", fmt.Errorf("%w: unknown role %q", ports.ErrInvalid, role)
	}
	tok := "inv_" + randomToken(24)
	_, err := s.db.ExecContext(ctx, `INSERT INTO invites(token_hash, role, created_by, expires_at) VALUES (?, ?, ?, ?)`, sha(tok), role, by, s.now().Add(7*24*time.Hour).Unix())
	return tok, err
}

func (s *Service) consumeInvite(ctx context.Context, tx *sql.Tx, tok string) (domain.Role, error) {
	var role string
	err := tx.QueryRowContext(ctx, `SELECT role FROM invites WHERE token_hash=? AND used=0 AND expires_at>?`, sha(tok), s.now().Unix()).Scan(&role)
	if err != nil {
		return "", fmt.Errorf("%w: invalid or expired invite", ports.ErrForbidden)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE invites SET used=1 WHERE token_hash=?`, sha(tok)); err != nil {
		return "", err
	}
	return domain.Role(role), nil
}

func (s *Service) bootstrapAdmin(ctx context.Context, key string) error {
	prefix, ok := splitToken(key, "gwa_")
	if !ok {
		return errors.New("auth: bootstrap admin key must look like gwa_ followed by 43 characters (use `gw keygen admin`)")
	}
	n, err := s.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	u, _, err := s.createUser(ctx, tx, "bootstrap", domain.RoleOwner)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_keys(id, user_id, name, prefix, hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		newID("key_"), u.ID, "bootstrap", prefix, hashSecret(key), s.now().Unix()); err != nil {
		return err
	}
	s.log.Info("bootstrap owner created from GW_BOOTSTRAP_ADMIN_KEY", "user", u.ID)
	return tx.Commit()
}

// NewAdminKeyString generates a well-formed admin key (for `gw keygen admin`).
func NewAdminKeyString() string { return "gwa_" + randomToken(32) }

// AdminKey is admin API key metadata.
type AdminKey struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"`
	CreatedAt time.Time `json:"created_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

// CreateAdminKey creates an admin API key for a user (AUTH-032). The key is returned once.
func (s *Service) CreateAdminKey(ctx context.Context, userID, name string) (string, AdminKey, error) {
	if _, err := s.GetUser(ctx, userID); err != nil {
		return "", AdminKey{}, err
	}
	key := NewAdminKeyString()
	prefix, _ := splitToken(key, "gwa_")
	k := AdminKey{ID: newID("key_"), UserID: userID, Name: strings.TrimSpace(name), Prefix: prefix, CreatedAt: s.now().UTC().Truncate(time.Second)}
	if k.Name == "" {
		k.Name = "api key"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_keys(id, user_id, name, prefix, hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		k.ID, userID, k.Name, prefix, hashSecret(key), k.CreatedAt.Unix())
	return key, k, err
}

// RevokeAdminKey revokes an admin key.
func (s *Service) RevokeAdminKey(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admin_keys SET revoked_at=? WHERE id=? AND revoked_at=0`, s.now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: admin key", ports.ErrNotFound)
	}
	s.flushCache()
	return nil
}

// ListAdminKeys lists admin keys.
func (s *Service) ListAdminKeys(ctx context.Context) ([]AdminKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, prefix, created_at, revoked_at FROM admin_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminKey{}
	for rows.Next() {
		var k AdminKey
		var c, r int64
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &c, &r); err != nil {
			return nil, err
		}
		k.CreatedAt, k.RevokedAt = store.TimeOrZero(c), store.TimeOrZero(r)
		out = append(out, k)
	}
	return out, rows.Err()
}

// --- sessions and admin principals -----------------------------------------

// Principal is an authenticated dashboard / Admin API caller.
type Principal struct {
	UserID     string      `json:"user_id"`
	Name       string      `json:"name"`
	Role       domain.Role `json:"role"`
	CSRF       string      `json:"csrf,omitempty"`
	ViaSession bool        `json:"via_session"`
}

const sessionIdle = 12 * time.Hour

func (s *Service) createSession(ctx context.Context, tx *sql.Tx, userID string) (string, error) {
	id := randomToken(32)
	now := s.now().Unix()
	_, err := tx.ExecContext(ctx, `INSERT INTO sessions(id_hash, user_id, csrf, created_at, last_seen) VALUES (?, ?, ?, ?, ?)`, sha(id), userID, randomToken(24), now, now)
	return id, err
}

// Logout deletes a session.
func (s *Service) Logout(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, sha(sessionID))
	return err
}

// AuthenticateAdmin resolves a session cookie or an admin API key (AUTH-032, AUTH-033).
func (s *Service) AuthenticateAdmin(ctx context.Context, sessionID, bearer string) (Principal, error) {
	if bearer != "" {
		prefix, ok := splitToken(bearer, "gwa_")
		if !ok {
			return Principal{}, ports.ErrUnauthenticated
		}
		ck := "adm:" + sha(bearer)
		s.cacheMu.Lock()
		e, hit := s.cache[ck]
		s.cacheMu.Unlock()
		var userID string
		if hit && s.now().Before(e.until) {
			userID = e.id.UserID
		} else {
			var hash []byte
			err := s.db.QueryRowContext(ctx, `SELECT user_id, hash FROM admin_keys WHERE prefix=? AND revoked_at=0`, prefix).Scan(&userID, &hash)
			if err != nil || !checkSecret(bearer, hash) {
				return Principal{}, ports.ErrUnauthenticated
			}
			s.cacheMu.Lock()
			s.cache[ck] = cacheEntry{id: domain.Identity{UserID: userID}, until: s.now().Add(60 * time.Second)}
			s.cacheMu.Unlock()
		}
		u, err := s.GetUser(ctx, userID)
		if err != nil {
			return Principal{}, ports.ErrUnauthenticated
		}
		return Principal{UserID: u.ID, Name: u.Name, Role: u.Role}, nil
	}
	if sessionID == "" {
		return Principal{}, ports.ErrUnauthenticated
	}
	var p Principal
	var last int64
	err := s.db.QueryRowContext(ctx, `SELECT u.id, u.name, u.role, s.csrf, s.last_seen FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash=?`, sha(sessionID)).
		Scan(&p.UserID, &p.Name, &p.Role, &p.CSRF, &last)
	if err != nil {
		return Principal{}, ports.ErrUnauthenticated
	}
	now := s.now()
	if now.Sub(time.Unix(last, 0)) > sessionIdle {
		_ = s.Logout(ctx, sessionID)
		return Principal{}, ports.ErrUnauthenticated
	}
	if now.Unix()-last > 60 {
		_, _ = s.db.ExecContext(ctx, `UPDATE sessions SET last_seen=? WHERE id_hash=?`, now.Unix(), sha(sessionID))
	}
	p.ViaSession = true
	return p, nil
}
