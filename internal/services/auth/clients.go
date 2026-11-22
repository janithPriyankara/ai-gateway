package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
	"github.com/mcp-gateway/mcp-gateway/internal/store"
)

const (
	staticCacheTTL   = 60 * time.Second
	clientKindStatic = "static"
	clientKindOAuth  = "oauth"
)

// CreateStaticToken registers a client and returns its token exactly once (AUTH-001).
func (s *Service) CreateStaticToken(ctx context.Context, userID, name, profile string) (string, domain.Client, error) {
	name, profile = strings.TrimSpace(name), strings.TrimSpace(profile)
	if name == "" || len(name) > 80 {
		return "", domain.Client{}, fmt.Errorf("%w: client name must be 1-80 characters", ports.ErrInvalid)
	}
	if profile == "" {
		return "", domain.Client{}, fmt.Errorf("%w: profile is required", ports.ErrInvalid)
	}
	if _, err := s.GetUser(ctx, userID); err != nil {
		return "", domain.Client{}, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		tok := "gw_" + randomToken(32)
		prefix, _ := splitToken(tok, "gw_")
		c := domain.Client{ID: newID("cli_"), UserID: userID, Name: name, Profile: profile, Kind: clientKindStatic, Prefix: prefix,
			CreatedAt: s.now().UTC().Truncate(time.Second)}
		_, err := s.db.ExecContext(ctx, `INSERT INTO clients(id, user_id, name, profile, kind, prefix, hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, userID, name, profile, clientKindStatic, prefix, hashSecret(tok), c.CreatedAt.Unix())
		if err == nil {
			return tok, c, nil
		}
		if !strings.Contains(err.Error(), "UNIQUE") {
			return "", domain.Client{}, err
		}
	}
	return "", domain.Client{}, errors.New("auth: could not allocate a unique token prefix")
}

// Authenticate implements ports.Authenticator for the MCP endpoint (AUTH-002, AUTH-011, GW-002).
func (s *Service) Authenticate(ctx context.Context, bearer string) (domain.Identity, error) {
	if strings.HasPrefix(bearer, "gw_") {
		return s.authStatic(ctx, bearer)
	}
	if strings.Count(bearer, ".") != 2 {
		return domain.Identity{}, ports.ErrUnauthenticated
	}
	id, err := s.verifyAccessToken(bearer)
	if err != nil {
		return domain.Identity{}, err
	}
	c, err := s.clientState(ctx, id.ClientID)
	if err != nil || c.revoked {
		return domain.Identity{}, ports.ErrUnauthenticated
	}
	id.ClientName = c.id.ClientName
	id.Profile = c.id.Profile // the client's current profile wins over the one in the token
	s.touch(id.ClientID)
	return id, nil
}

func (s *Service) authStatic(ctx context.Context, tok string) (domain.Identity, error) {
	prefix, ok := splitToken(tok, "gw_")
	if !ok {
		return domain.Identity{}, ports.ErrUnauthenticated
	}
	ck := "tok:" + sha(tok)
	now := s.now()
	s.cacheMu.Lock()
	e, hit := s.cache[ck]
	s.cacheMu.Unlock()
	if hit && now.Before(e.until) {
		s.touch(e.id.ClientID)
		return e.id, nil
	}
	var id domain.Identity
	var hash []byte
	var revoked int64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, name, profile, hash, revoked_at FROM clients WHERE prefix=? AND kind='static'`, prefix).
		Scan(&id.ClientID, &id.UserID, &id.ClientName, &id.Profile, &hash, &revoked)
	// Always run the hash check so timing does not reveal whether the prefix exists.
	if err != nil {
		hash = make([]byte, 48)
	}
	valid := checkSecret(tok, hash)
	if err != nil || !valid || revoked != 0 {
		return domain.Identity{}, ports.ErrUnauthenticated
	}
	s.cacheMu.Lock()
	s.cache[ck] = cacheEntry{id: id, until: now.Add(staticCacheTTL)}
	s.cacheMu.Unlock()
	s.touch(id.ClientID)
	return id, nil
}

// clientState returns a client's revocation state, cached for staticCacheTTL.
func (s *Service) clientState(ctx context.Context, clientID string) (cacheEntry, error) {
	ck := "cli:" + clientID
	now := s.now()
	s.cacheMu.Lock()
	e, hit := s.cache[ck]
	s.cacheMu.Unlock()
	if hit && now.Before(e.until) {
		return e, nil
	}
	var name, profile string
	var revoked int64
	err := s.db.QueryRowContext(ctx, `SELECT name, profile, revoked_at FROM clients WHERE id=?`, clientID).Scan(&name, &profile, &revoked)
	if err != nil {
		return cacheEntry{}, err
	}
	e = cacheEntry{id: domain.Identity{ClientID: clientID, ClientName: name, Profile: profile}, revoked: revoked != 0, until: now.Add(staticCacheTTL)}
	s.cacheMu.Lock()
	s.cache[ck] = e
	s.cacheMu.Unlock()
	return e, nil
}

// touch records last-seen at most once a minute per client, off the hot path.
func (s *Service) touch(clientID string) {
	now := s.now()
	s.cacheMu.Lock()
	last := s.seen[clientID]
	if now.Sub(last) < time.Minute {
		s.cacheMu.Unlock()
		return
	}
	s.seen[clientID] = now
	s.cacheMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = s.db.ExecContext(ctx, `UPDATE clients SET last_seen_at=? WHERE id=?`, now.Unix(), clientID)
	}()
}

// RevokeClient revokes a client and every OAuth token family issued to it.
func (s *Service) RevokeClient(ctx context.Context, clientID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE clients SET revoked_at=? WHERE id=? AND revoked_at=0`, s.now().Unix(), clientID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: client %q", ports.ErrNotFound, clientID)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE token_families SET revoked=1 WHERE client_rec_id=?`, clientID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.flushCache()
	return nil
}

// GetClient returns one client.
func (s *Service) GetClient(ctx context.Context, id string) (domain.Client, error) {
	cs, err := s.listClients(ctx, `WHERE id=?`, id)
	if err != nil {
		return domain.Client{}, err
	}
	if len(cs) == 0 {
		return domain.Client{}, fmt.Errorf("%w: client %q", ports.ErrNotFound, id)
	}
	return cs[0], nil
}

// ListClients lists clients, optionally for one user.
func (s *Service) ListClients(ctx context.Context, userID string) ([]domain.Client, error) {
	if userID != "" {
		return s.listClients(ctx, `WHERE user_id=? ORDER BY created_at DESC`, userID)
	}
	return s.listClients(ctx, `ORDER BY created_at DESC`)
}

func (s *Service) listClients(ctx context.Context, where string, args ...any) ([]domain.Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, profile, kind, COALESCE(prefix, ''), created_at, last_seen_at, revoked_at FROM clients `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Client{}
	for rows.Next() {
		var c domain.Client
		var cr, ls, rv int64
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &c.Profile, &c.Kind, &c.Prefix, &cr, &ls, &rv); err != nil {
			return nil, err
		}
		c.CreatedAt, c.LastSeenAt, c.RevokedAt = store.TimeOrZero(cr), store.TimeOrZero(ls), store.TimeOrZero(rv)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetClientProfile changes the profile of a client (takes effect within the cache TTL).
func (s *Service) SetClientProfile(ctx context.Context, clientID, profile string) error {
	if strings.TrimSpace(profile) == "" {
		return fmt.Errorf("%w: profile is required", ports.ErrInvalid)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE clients SET profile=? WHERE id=?`, profile, clientID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: client %q", ports.ErrNotFound, clientID)
	}
	s.flushCache()
	return nil
}

var _ = sql.ErrNoRows
