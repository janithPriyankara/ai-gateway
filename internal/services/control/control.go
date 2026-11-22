// Package control is the control plane: configuration (servers, profiles),
// tool pinning, approvals, the audit log and the live event bus.
package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/policy"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
	"github.com/mcp-gateway/mcp-gateway/internal/store"
)

var migrations = []string{
	`CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
	INSERT INTO meta(key, value) VALUES ('config_version', 1);
	CREATE TABLE servers (id TEXT PRIMARY KEY, prefix TEXT NOT NULL UNIQUE, data TEXT NOT NULL, health TEXT NOT NULL DEFAULT '');
	CREATE TABLE profiles (name TEXT PRIMARY KEY, data TEXT NOT NULL);
	CREATE TABLE pins (
		server_id TEXT NOT NULL, tool TEXT NOT NULL, fingerprint TEXT NOT NULL, status TEXT NOT NULL,
		pending_fingerprint TEXT NOT NULL DEFAULT '', old_description TEXT NOT NULL DEFAULT '', new_description TEXT NOT NULL DEFAULT '',
		old_schema TEXT NOT NULL DEFAULT '', new_schema TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', schema TEXT NOT NULL DEFAULT '', read_only INTEGER NOT NULL DEFAULT 0, rejected_fingerprint TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL, PRIMARY KEY (server_id, tool));
	CREATE TABLE approvals (id TEXT PRIMARY KEY, status TEXT NOT NULL, data TEXT NOT NULL, created_at INTEGER NOT NULL);
	CREATE INDEX approvals_status ON approvals(status, created_at);
	CREATE TABLE audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT, time_ns INTEGER NOT NULL, kind TEXT NOT NULL, request_id TEXT NOT NULL,
		user_id TEXT NOT NULL, client_id TEXT NOT NULL, profile TEXT NOT NULL, server_id TEXT NOT NULL, tool TEXT NOT NULL,
		decision TEXT NOT NULL, status TEXT NOT NULL, latency_ms INTEGER NOT NULL, summary TEXT NOT NULL,
		prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
	CREATE INDEX audit_time ON audit(time_ns);
	CREATE INDEX audit_client ON audit(client_id, id);
	CREATE INDEX audit_server ON audit(server_id, id);`,
}

// Options configures the control service.
type Options struct {
	DBPath        string
	StrictPinning bool
	Notifiers     []Notifier
}

// Service is the control plane.
type Service struct {
	db            *sql.DB
	strictPinning bool
	notifiers     []Notifier
	now           func() time.Time
	approvalTTL   time.Duration

	verMu   sync.Mutex
	changed chan struct{} // closed and replaced on every config change

	auditMu  sync.Mutex
	lastHash string
	hashInit bool

	apMu    sync.Mutex
	waiters map[string]chan domain.Approval

	bus bus
}

// New opens the control database.
func New(ctx context.Context, o Options) (*Service, error) {
	db, err := store.Open(ctx, o.DBPath, migrations)
	if err != nil {
		return nil, err
	}
	s := &Service{
		db: db, strictPinning: o.StrictPinning, notifiers: o.Notifiers, now: time.Now,
		approvalTTL: 120 * time.Second, changed: make(chan struct{}), waiters: map[string]chan domain.Approval{},
	}
	s.bus.subs = map[int]chan Event{}
	// Approvals left pending by a previous process can never be released: expire them.
	_, _ = db.ExecContext(ctx, `UPDATE approvals SET status='expired' WHERE status='pending'`)
	return s, nil
}

// Close closes the database.
func (s *Service) Close() error { return s.db.Close() }

// Ping checks the database (readiness).
func (s *Service) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

type actorKey struct{}

// WithActor marks ctx with the user performing an admin action (for the audit log).
func WithActor(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, actorKey{}, userID)
}

func actor(ctx context.Context) string {
	if v, ok := ctx.Value(actorKey{}).(string); ok && v != "" {
		return v
	}
	return "system"
}

// bumpVersion increments the config version inside tx.
func bumpVersion(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `UPDATE meta SET value = value + 1 WHERE key='config_version'`)
	return err
}

// notifyChanged wakes long-polling snapshot readers and SSE subscribers.
func (s *Service) notifyChanged() {
	s.verMu.Lock()
	close(s.changed)
	s.changed = make(chan struct{})
	s.verMu.Unlock()
	s.bus.publish(Event{Type: "config.changed"})
}

// mutate runs fn in a transaction, bumps the version, audits the admin action and notifies.
func (s *Service) mutate(ctx context.Context, summary string, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	if err := bumpVersion(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.notifyChanged()
	s.AuditAdmin(ctx, summary)
	return nil
}

// AuditAdmin records an admin action (CTL-033).
func (s *Service) AuditAdmin(ctx context.Context, summary string) {
	_ = s.Record(context.WithoutCancel(ctx), []domain.AuditEvent{{Kind: "admin", UserID: actor(ctx), Decision: "-", Status: domain.StatusOK, Summary: summary}})
}

var (
	prefixRE = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	idRE     = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
)

func validateServer(sv domain.Server) error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: "+f, append([]any{ports.ErrInvalid}, a...)...) }
	if !idRE.MatchString(sv.ID) {
		return bad("server id must match [a-z0-9_-]{1,64}")
	}
	if strings.TrimSpace(sv.Name) == "" {
		return bad("server name is required")
	}
	if !prefixRE.MatchString(sv.Prefix) {
		return bad("prefix must be 1-32 characters of a-z, 0-9 or _")
	}
	if strings.Contains(sv.Prefix, "__") {
		return bad("prefix must not contain a double underscore")
	}
	switch sv.Transport {
	case domain.TransportHTTP:
		u, err := url.Parse(sv.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return bad("http servers need an http(s) URL")
		}
	case domain.TransportStdio:
		if strings.TrimSpace(sv.Command) == "" {
			return bad("stdio servers need a command")
		}
	default:
		return bad("transport must be http or stdio")
	}
	switch sv.AuthKind {
	case "", "none", ports.CredBearer, ports.CredHeader, ports.CredEnv, ports.CredOAuth:
	default:
		return bad("auth_kind must be none, bearer, header, env or oauth")
	}
	if sv.TimeoutSeconds < 0 || sv.TimeoutSeconds > 3600 {
		return bad("timeout_seconds must be between 0 and 3600")
	}
	return nil
}

func normalizeServer(sv domain.Server) domain.Server {
	if sv.ID == "" {
		sv.ID = strings.ReplaceAll(sv.Prefix, "_", "-")
	}
	if sv.AuthKind == "" {
		sv.AuthKind = "none"
	}
	if sv.TimeoutSeconds == 0 {
		sv.TimeoutSeconds = 60
	}
	sv.Health = ""
	return sv
}

// PutServer creates or replaces a server (CTL-001).
func (s *Service) PutServer(ctx context.Context, sv domain.Server) error {
	sv = normalizeServer(sv)
	if err := validateServer(sv); err != nil {
		return err
	}
	data, _ := json.Marshal(sv)
	return s.mutate(ctx, fmt.Sprintf("put server %s (%s)", sv.ID, sv.Name), func(tx *sql.Tx) error {
		var other string
		err := tx.QueryRowContext(ctx, `SELECT id FROM servers WHERE prefix=? AND id<>?`, sv.Prefix, sv.ID).Scan(&other)
		if err == nil {
			return fmt.Errorf("%w: prefix %q is already used by server %q", ports.ErrConflict, sv.Prefix, other)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO servers(id, prefix, data) VALUES (?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET prefix=excluded.prefix, data=excluded.data`, sv.ID, sv.Prefix, string(data))
		return err
	})
}

// GetServer returns one server.
func (s *Service) GetServer(ctx context.Context, id string) (domain.Server, error) {
	var data, health string
	err := s.db.QueryRowContext(ctx, `SELECT data, health FROM servers WHERE id=?`, id).Scan(&data, &health)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Server{}, fmt.Errorf("%w: server %q", ports.ErrNotFound, id)
	}
	if err != nil {
		return domain.Server{}, err
	}
	var sv domain.Server
	err = json.Unmarshal([]byte(data), &sv)
	sv.Health = health
	return sv, err
}

// ListServers lists servers ordered by name.
func (s *Service) ListServers(ctx context.Context) ([]domain.Server, error) {
	return listServers(ctx, s.db)
}

type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
}

func listServers(ctx context.Context, q querier) ([]domain.Server, error) {
	rows, err := q.QueryContext(ctx, `SELECT data, health FROM servers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Server{}
	for rows.Next() {
		var data, health string
		if err := rows.Scan(&data, &health); err != nil {
			return nil, err
		}
		var sv domain.Server
		if err := json.Unmarshal([]byte(data), &sv); err != nil {
			return nil, err
		}
		sv.Health = health
		out = append(out, sv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, rows.Err()
}

// DeleteServer removes a server and its pins.
func (s *Service) DeleteServer(ctx context.Context, id string) error {
	return s.mutate(ctx, "delete server "+id, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM servers WHERE id=?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: server %q", ports.ErrNotFound, id)
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM pins WHERE server_id=?`, id)
		return err
	})
}

// SetServerHealth records a health check result (CTL-044). It does not bump the config version.
func (s *Service) SetServerHealth(ctx context.Context, id, health string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE servers SET health=? WHERE id=? AND health<>?`, health, id, health)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.bus.publish(Event{Type: "server.health", Data: map[string]string{"server_id": id, "health": health}})
	}
	return nil
}

// PutProfile creates or replaces a profile (CTL-002).
func (s *Service) PutProfile(ctx context.Context, p domain.Profile) error {
	if p.Servers == nil {
		p.Servers = []string{}
	}
	if p.Rules == nil {
		p.Rules = []domain.Rule{}
	}
	if err := policy.Validate(p); err != nil {
		return fmt.Errorf("%w: %v", ports.ErrInvalid, err)
	}
	data, _ := json.Marshal(p)
	return s.mutate(ctx, "put profile "+p.Name, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO profiles(name, data) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET data=excluded.data`, p.Name, string(data))
		return err
	})
}

// GetProfile returns one profile.
func (s *Service) GetProfile(ctx context.Context, name string) (domain.Profile, error) {
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM profiles WHERE name=?`, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Profile{}, fmt.Errorf("%w: profile %q", ports.ErrNotFound, name)
	}
	if err != nil {
		return domain.Profile{}, err
	}
	var p domain.Profile
	return p, json.Unmarshal([]byte(data), &p)
}

// ListProfiles lists profiles ordered by name.
func (s *Service) ListProfiles(ctx context.Context) ([]domain.Profile, error) {
	return listProfiles(ctx, s.db)
}

func listProfiles(ctx context.Context, q querier) ([]domain.Profile, error) {
	rows, err := q.QueryContext(ctx, `SELECT data FROM profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Profile{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var p domain.Profile
		if err := json.Unmarshal([]byte(data), &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteProfile removes a profile.
func (s *Service) DeleteProfile(ctx context.Context, name string) error {
	return s.mutate(ctx, "delete profile "+name, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM profiles WHERE name=?`, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: profile %q", ports.ErrNotFound, name)
		}
		return nil
	})
}

func (s *Service) version(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int64, error) {
	var v int64
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='config_version'`).Scan(&v)
	return v, err
}

// Snapshot implements ports.ConfigSource (CTL-003).
func (s *Service) Snapshot(ctx context.Context, since int64) (domain.Snapshot, error) {
	if since >= 0 {
		s.verMu.Lock()
		ch := s.changed
		s.verMu.Unlock()
		v, err := s.version(ctx, s.db)
		if err != nil {
			return domain.Snapshot{}, err
		}
		if v <= since {
			t := time.NewTimer(25 * time.Second)
			select {
			case <-ch:
			case <-ctx.Done():
			case <-t.C:
			}
			t.Stop()
		}
	}
	return s.readSnapshot(context.WithoutCancel(ctx))
}

func (s *Service) readSnapshot(ctx context.Context) (domain.Snapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return domain.Snapshot{}, err
	}
	defer tx.Rollback()
	var snap domain.Snapshot
	if snap.Version, err = s.version(ctx, tx); err != nil {
		return snap, err
	}
	if snap.Servers, err = listServers(ctx, tx); err != nil {
		return snap, err
	}
	if snap.Profiles, err = listProfiles(ctx, tx); err != nil {
		return snap, err
	}
	if snap.Pins, err = listPins(ctx, tx, false); err != nil {
		return snap, err
	}
	return snap, nil
}

// ConfigDoc is the YAML export format (CTL-004). It never contains secrets.
type ConfigDoc struct {
	Version  int              `yaml:"version"`
	Servers  []domain.Server  `yaml:"servers"`
	Profiles []domain.Profile `yaml:"profiles"`
}

// ExportYAML exports servers and profiles.
func (s *Service) ExportYAML(ctx context.Context) ([]byte, error) {
	snap, err := s.readSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(ConfigDoc{Version: 1, Servers: snap.Servers, Profiles: snap.Profiles})
}

// ImportYAML atomically replaces servers and profiles with the document's contents.
func (s *Service) ImportYAML(ctx context.Context, doc []byte) error {
	var d ConfigDoc
	dec := yaml.NewDecoder(strings.NewReader(string(doc)))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("%w: %v", ports.ErrInvalid, err)
	}
	if d.Version != 1 {
		return fmt.Errorf("%w: unsupported config version %d", ports.ErrInvalid, d.Version)
	}
	prefixes := map[string]bool{}
	for i := range d.Servers {
		d.Servers[i] = normalizeServer(d.Servers[i])
		if err := validateServer(d.Servers[i]); err != nil {
			return err
		}
		if prefixes[d.Servers[i].Prefix] {
			return fmt.Errorf("%w: duplicate prefix %q", ports.ErrInvalid, d.Servers[i].Prefix)
		}
		prefixes[d.Servers[i].Prefix] = true
	}
	if _, err := policy.Compile(d.Profiles); err != nil {
		return fmt.Errorf("%w: %v", ports.ErrInvalid, err)
	}
	return s.mutate(ctx, fmt.Sprintf("import config (%d servers, %d profiles)", len(d.Servers), len(d.Profiles)), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM servers`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM profiles`); err != nil {
			return err
		}
		for _, sv := range d.Servers {
			data, _ := json.Marshal(sv)
			if _, err := tx.ExecContext(ctx, `INSERT INTO servers(id, prefix, data) VALUES (?, ?, ?)`, sv.ID, sv.Prefix, string(data)); err != nil {
				return fmt.Errorf("%w: %v", ports.ErrInvalid, err)
			}
		}
		for _, p := range d.Profiles {
			if p.Servers == nil {
				p.Servers = []string{}
			}
			data, _ := json.Marshal(p)
			if _, err := tx.ExecContext(ctx, `INSERT INTO profiles(name, data) VALUES (?, ?)`, p.Name, string(data)); err != nil {
				return err
			}
		}
		return nil
	})
}
