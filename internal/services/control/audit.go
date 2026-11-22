package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
)

// canonicalEvent is the hashed representation of an event (CTL-031). Field order is fixed.
func canonicalEvent(e domain.AuditEvent) string {
	return strings.Join([]string{
		strconv.FormatInt(e.Time.UnixNano(), 10), e.Kind, e.RequestID, e.UserID, e.ClientID, e.Profile,
		e.ServerID, e.Tool, e.Decision, e.Status, strconv.FormatInt(e.LatencyMS, 10), e.Summary,
	}, "\x1f")
}

func chainHash(prev string, e domain.AuditEvent) string {
	sum := sha256.Sum256([]byte(prev + "\x1e" + canonicalEvent(e)))
	return hex.EncodeToString(sum[:])
}

// Record implements ports.AuditSink (CTL-030, CTL-031).
func (s *Service) Record(ctx context.Context, events []domain.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if !s.hashInit {
		var h string
		_ = s.db.QueryRowContext(ctx, `SELECT hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&h)
		s.lastHash, s.hashInit = h, true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO audit(time_ns, kind, request_id, user_id, client_id, profile, server_id, tool, decision, status, latency_ms, summary, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	prev := s.lastHash
	inserted := make([]domain.AuditEvent, 0, len(events))
	for _, e := range events {
		if e.Time.IsZero() {
			e.Time = s.now()
		}
		e.Time = time.Unix(0, e.Time.UnixNano()).UTC()
		if e.Kind == "" {
			e.Kind = "call"
		}
		e.PrevHash = prev
		e.Hash = chainHash(prev, e)
		res, err := stmt.ExecContext(ctx, e.Time.UnixNano(), e.Kind, e.RequestID, e.UserID, e.ClientID, e.Profile, e.ServerID,
			e.Tool, e.Decision, e.Status, e.LatencyMS, e.Summary, e.PrevHash, e.Hash)
		if err != nil {
			return err
		}
		e.ID, _ = res.LastInsertId()
		prev = e.Hash
		inserted = append(inserted, e)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.lastHash = prev
	for _, e := range inserted {
		s.bus.publish(Event{Type: "audit.event", Data: e})
	}
	return nil
}

// QueryAudit filters events, newest first, with cursor pagination (CTL-032).
func (s *Service) QueryAudit(ctx context.Context, q domain.AuditQuery) ([]domain.AuditEvent, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where = append(where, cond); args = append(args, v) }
	if !q.Since.IsZero() {
		add("time_ns >= ?", q.Since.UnixNano())
	}
	if !q.Until.IsZero() {
		add("time_ns < ?", q.Until.UnixNano())
	}
	for col, v := range map[string]string{"user_id": q.UserID, "client_id": q.ClientID, "server_id": q.ServerID, "tool": q.Tool, "decision": q.Decision, "kind": q.Kind} {
		if v != "" {
			add(col+" = ?", v)
		}
	}
	if q.BeforeID > 0 {
		add("id < ?", q.BeforeID)
	}
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, time_ns, kind, request_id, user_id, client_id, profile, server_id, tool, decision, status, latency_ms, summary, prev_hash, hash FROM audit`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT " + strconv.Itoa(limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.AuditEvent{}
	for rows.Next() {
		var e domain.AuditEvent
		var ns int64
		if err := rows.Scan(&e.ID, &ns, &e.Kind, &e.RequestID, &e.UserID, &e.ClientID, &e.Profile, &e.ServerID, &e.Tool,
			&e.Decision, &e.Status, &e.LatencyMS, &e.Summary, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.Time = time.Unix(0, ns).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// ChainResult reports an audit chain verification.
type ChainResult struct {
	OK       bool  `json:"ok"`
	Checked  int   `json:"checked"`
	BrokenAt int64 `json:"broken_at,omitempty"`
}

// VerifyChain recomputes the hash chain from the oldest remaining event (CTL-031, CTL-034).
func (s *Service) VerifyChain(ctx context.Context) (ChainResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, time_ns, kind, request_id, user_id, client_id, profile, server_id, tool, decision, status, latency_ms, summary, prev_hash, hash FROM audit ORDER BY id ASC`)
	if err != nil {
		return ChainResult{}, err
	}
	defer rows.Close()
	res := ChainResult{OK: true}
	prev, first := "", true
	for rows.Next() {
		var e domain.AuditEvent
		var ns int64
		if err := rows.Scan(&e.ID, &ns, &e.Kind, &e.RequestID, &e.UserID, &e.ClientID, &e.Profile, &e.ServerID, &e.Tool,
			&e.Decision, &e.Status, &e.LatencyMS, &e.Summary, &e.PrevHash, &e.Hash); err != nil {
			return res, err
		}
		e.Time = time.Unix(0, ns).UTC()
		res.Checked++
		if !first && e.PrevHash != prev {
			return ChainResult{OK: false, Checked: res.Checked, BrokenAt: e.ID}, nil
		}
		if chainHash(e.PrevHash, e) != e.Hash {
			return ChainResult{OK: false, Checked: res.Checked, BrokenAt: e.ID}, nil
		}
		prev, first = e.Hash, false
	}
	return res, rows.Err()
}

// PruneAudit deletes events older than retention (CTL-034) and returns how many were removed.
func (s *Service) PruneAudit(ctx context.Context, retention time.Duration) (int64, error) {
	s.auditMu.Lock()
	cutoff := s.now().Add(-retention).UnixNano()
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE time_ns < ?`, cutoff)
	s.auditMu.Unlock()
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// AuditStats returns counts for the overview page.
func (s *Service) AuditStats(ctx context.Context, since time.Time) (calls, blocked int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN decision='deny' OR status='denied' THEN 1 ELSE 0 END), 0)
		FROM audit WHERE kind='call' AND time_ns >= ?`, since.UnixNano()).Scan(&calls, &blocked)
	return
}

// ClientCallCounts returns the number of tool calls per client in the audit log.
func (s *Service) ClientCallCounts(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client_id, COUNT(*) FROM audit WHERE kind='call' AND client_id<>'' GROUP BY client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var n int64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
