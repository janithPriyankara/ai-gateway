package control

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

// canonicalJSON encodes v with sorted object keys (encoding/json sorts map keys).
// Values are round-tripped through any so struct field order does not matter either.
func canonicalJSON(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return string(b)
	}
	b, _ = json.Marshal(generic)
	return string(b)
}

// Fingerprint computes a tool's pin fingerprint (CTL-010).
func Fingerprint(t ports.ToolDef) string {
	h := sha256.New()
	h.Write([]byte(t.Name + "\n" + t.Description + "\n" + canonicalJSON(t.InputSchema) + "\n" + canonicalJSON(t.Annotations)))
	return hex.EncodeToString(h.Sum(nil))
}

func listPins(ctx context.Context, q querier, onlyPending bool) ([]domain.ToolPin, error) {
	query := `SELECT server_id, tool, fingerprint, status, description, read_only, pending_fingerprint, old_description, new_description, old_schema, new_schema, updated_at FROM pins`
	if onlyPending {
		query += ` WHERE pending_fingerprint <> ''`
	}
	rows, err := q.QueryContext(ctx, query+` ORDER BY server_id, tool`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ToolPin{}
	for rows.Next() {
		var p domain.ToolPin
		var upd int64
		if err := rows.Scan(&p.ServerID, &p.Tool, &p.Fingerprint, &p.Status, &p.Description, &p.ReadOnly, &p.PendingFingerprint,
			&p.OldDescription, &p.NewDescription, &p.OldSchema, &p.NewSchema, &upd); err != nil {
			return nil, err
		}
		p.UpdatedAt = timeOrZero(upd)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ObserveTools implements ports.PinRegistry (CTL-011, CTL-012, GW-018).
func (s *Service) ObserveTools(ctx context.Context, serverID string, tools []ports.ToolDef) ([]domain.ToolPin, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	changed := false
	out := make([]domain.ToolPin, 0, len(tools))
	now := s.now().Unix()
	for _, t := range tools {
		fp := Fingerprint(t)
		schema := canonicalJSON(t.InputSchema)
		var cur domain.ToolPin
		var desc, curSchema, rejected string
		err := tx.QueryRowContext(ctx, `SELECT fingerprint, status, pending_fingerprint, description, schema, rejected_fingerprint FROM pins WHERE server_id=? AND tool=?`, serverID, t.Name).
			Scan(&cur.Fingerprint, &cur.Status, &cur.PendingFingerprint, &desc, &curSchema, &rejected)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			status, trusted, pending := domain.PinApproved, fp, ""
			if s.strictPinning {
				// No trusted definition yet: the first one waits for review.
				status, trusted, pending = domain.PinQuarantined, "", fp
				changed = true
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO pins(server_id, tool, fingerprint, status, pending_fingerprint, new_description, new_schema, description, schema, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, serverID, t.Name, trusted, status, pending, t.Description, schema, t.Description, schema, now); err != nil {
				return nil, err
			}
		case err != nil:
			return nil, err
		case fp == cur.Fingerprint && cur.PendingFingerprint == "" && cur.Status == domain.PinApproved:
			// unchanged and trusted: nothing to do
		case fp == cur.Fingerprint:
			// back to the trusted definition: release the tool and clear any pending or rejected change
			if _, err := tx.ExecContext(ctx, `UPDATE pins SET status='approved', pending_fingerprint='', rejected_fingerprint='', old_description='', new_description='', old_schema='', new_schema='', updated_at=? WHERE server_id=? AND tool=?`, now, serverID, t.Name); err != nil {
				return nil, err
			}
			changed = true
		case fp == rejected && cur.PendingFingerprint == "":
			// a definition an admin already rejected: stay quarantined, don't ask again
		case fp != cur.PendingFingerprint || cur.Status != domain.PinQuarantined:
			if _, err := tx.ExecContext(ctx, `UPDATE pins SET status='quarantined', pending_fingerprint=?, old_description=?, new_description=?, old_schema=?, new_schema=?, updated_at=? WHERE server_id=? AND tool=?`,
				fp, desc, t.Description, curSchema, schema, now, serverID, t.Name); err != nil {
				return nil, err
			}
			changed = true
		}
		if _, err := tx.ExecContext(ctx, `UPDATE pins SET read_only=? WHERE server_id=? AND tool=?`, isReadOnly(t.Annotations), serverID, t.Name); err != nil {
			return nil, err
		}
		p, err := getPin(ctx, tx, serverID, t.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if changed {
		if err := bumpVersion(ctx, tx); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if changed {
		s.notifyChanged()
	}
	return out, nil
}

func getPin(ctx context.Context, tx *sql.Tx, serverID, tool string) (domain.ToolPin, error) {
	var p domain.ToolPin
	var upd int64
	err := tx.QueryRowContext(ctx, `SELECT server_id, tool, fingerprint, status, description, read_only, pending_fingerprint, old_description, new_description, old_schema, new_schema, updated_at FROM pins WHERE server_id=? AND tool=?`, serverID, tool).
		Scan(&p.ServerID, &p.Tool, &p.Fingerprint, &p.Status, &p.Description, &p.ReadOnly, &p.PendingFingerprint, &p.OldDescription, &p.NewDescription, &p.OldSchema, &p.NewSchema, &upd)
	p.UpdatedAt = timeOrZero(upd)
	return p, err
}

// ListPins lists every pin.
func (s *Service) ListPins(ctx context.Context) ([]domain.ToolPin, error) {
	return listPins(ctx, s.db, false)
}

// ListPinChanges lists tools with a pending definition change (CTL-012).
func (s *Service) ListPinChanges(ctx context.Context) ([]domain.ToolPin, error) {
	return listPins(ctx, s.db, true)
}

// AcceptPin approves a pending change (CTL-013).
func (s *Service) AcceptPin(ctx context.Context, serverID, tool, by string) error {
	return s.mutate(WithActor(ctx, by), fmt.Sprintf("accept tool change %s/%s", serverID, tool), func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE pins SET fingerprint=pending_fingerprint, status='approved', pending_fingerprint='', rejected_fingerprint='',
			description=new_description, schema=new_schema, old_description='', new_description='', old_schema='', new_schema='', updated_at=?
			WHERE server_id=? AND tool=? AND pending_fingerprint<>''`, s.now().Unix(), serverID, tool)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: no pending change for %s/%s", ports.ErrNotFound, serverID, tool)
		}
		return nil
	})
}

// RejectPin keeps the tool quarantined, remembers the rejected definition so it is
// not offered for review again, and removes it from the review list (CTL-013).
func (s *Service) RejectPin(ctx context.Context, serverID, tool, by string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE pins SET status='quarantined', rejected_fingerprint=pending_fingerprint, pending_fingerprint='',
		old_description='', new_description='', old_schema='', new_schema='', updated_at=? WHERE server_id=? AND tool=? AND pending_fingerprint<>''`,
		s.now().Unix(), serverID, tool)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: no pending change for %s/%s", ports.ErrNotFound, serverID, tool)
	}
	s.AuditAdmin(WithActor(ctx, by), fmt.Sprintf("reject tool change %s/%s (tool stays quarantined)", serverID, tool))
	return nil
}

// isReadOnly reads readOnlyHint from arbitrary annotation values.
func isReadOnly(a any) bool {
	var m map[string]any
	if a == nil {
		return false
	}
	b, err := json.Marshal(a)
	if err != nil || json.Unmarshal(b, &m) != nil {
		return false
	}
	v, _ := m["readOnlyHint"].(bool)
	return v
}

// ServerPins lists the pins of one server (its known tools).
func (s *Service) ServerPins(ctx context.Context, serverID string) ([]domain.ToolPin, error) {
	all, err := listPins(ctx, s.db, false)
	if err != nil {
		return nil, err
	}
	out := []domain.ToolPin{}
	for _, p := range all {
		if p.ServerID == serverID {
			out = append(out, p)
		}
	}
	return out, nil
}
