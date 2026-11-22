package control

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

func newID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func timeOrZero(s int64) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return time.Unix(s, 0).UTC()
}

// RequestApproval implements ports.ApprovalBroker (CTL-020..CTL-022, CTL-024).
// It blocks until the approval is decided, expires, or ctx is cancelled.
func (s *Service) RequestApproval(ctx context.Context, a domain.Approval) (domain.Approval, error) {
	now := s.now().UTC()
	a.ID = newID("apr_")
	a.Status = domain.ApprovalPending
	a.CreatedAt = now
	a.ExpiresAt = now.Add(s.approvalTTL)
	a.Reason, a.DecidedBy, a.DecidedAt = "", "", time.Time{}
	ch := make(chan domain.Approval, 1)
	s.apMu.Lock()
	s.waiters[a.ID] = ch
	s.apMu.Unlock()
	defer func() {
		s.apMu.Lock()
		delete(s.waiters, a.ID)
		s.apMu.Unlock()
	}()
	if err := s.saveApproval(ctx, a); err != nil {
		return a, err
	}
	s.bus.publish(Event{Type: "approval.created", Data: a})
	for _, n := range s.notifiers {
		go func(n Notifier) {
			nctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = n.Notify(nctx, a)
		}(n)
	}
	timer := time.NewTimer(s.approvalTTL)
	defer timer.Stop()
	select {
	case decided := <-ch:
		return decided, nil
	case <-timer.C:
		return s.finish(context.WithoutCancel(ctx), a.ID, domain.ApprovalExpired, "approval timed out", "system")
	case <-ctx.Done():
		return s.finish(context.WithoutCancel(ctx), a.ID, domain.ApprovalExpired, "caller went away", "system")
	}
}

func (s *Service) saveApproval(ctx context.Context, a domain.Approval) error {
	data, _ := json.Marshal(a)
	_, err := s.db.ExecContext(ctx, `INSERT INTO approvals(id, status, data, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET status=excluded.status, data=excluded.data`, a.ID, a.Status, string(data), a.CreatedAt.Unix())
	return err
}

// GetApproval returns one approval.
func (s *Service) GetApproval(ctx context.Context, id string) (domain.Approval, error) {
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM approvals WHERE id=?`, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Approval{}, fmt.Errorf("%w: approval %q", ports.ErrNotFound, id)
	}
	if err != nil {
		return domain.Approval{}, err
	}
	var a domain.Approval
	return a, json.Unmarshal([]byte(data), &a)
}

// finish moves a pending approval to a final state exactly once. If someone else
// finished it first, their result is returned.
func (s *Service) finish(ctx context.Context, id, status, reason, by string) (domain.Approval, error) {
	a, err := s.GetApproval(ctx, id)
	if err != nil {
		return a, err
	}
	if a.Status != domain.ApprovalPending {
		return a, fmt.Errorf("%w: approval already %s", ports.ErrConflict, a.Status)
	}
	a.Status, a.Reason, a.DecidedBy, a.DecidedAt = status, reason, by, s.now().UTC()
	data, _ := json.Marshal(a)
	res, err := s.db.ExecContext(ctx, `UPDATE approvals SET status=?, data=? WHERE id=? AND status='pending'`, status, string(data), id)
	if err != nil {
		return a, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		cur, _ := s.GetApproval(ctx, id)
		return cur, fmt.Errorf("%w: approval already %s", ports.ErrConflict, cur.Status)
	}
	s.apMu.Lock()
	ch := s.waiters[id]
	s.apMu.Unlock()
	if ch != nil {
		select {
		case ch <- a:
		default:
		}
	}
	s.bus.publish(Event{Type: "approval.decided", Data: a})
	return a, nil
}

// DecideApproval approves or denies (CTL-021). With always, an allow rule for the
// tool is inserted above the rule that asked (CTL-023).
func (s *Service) DecideApproval(ctx context.Context, id string, approve, always bool, by string) error {
	status, reason := domain.ApprovalDenied, "denied by "+by
	if approve {
		status, reason = domain.ApprovalApproved, "approved by "+by
	}
	a, err := s.finish(ctx, id, status, reason, by)
	if err != nil {
		if errors.Is(err, ports.ErrConflict) && a.Status == domain.ApprovalExpired {
			return fmt.Errorf("%w: approval already expired", ports.ErrConflict)
		}
		return err
	}
	s.AuditAdmin(WithActor(ctx, by), fmt.Sprintf("%s %s for %s (%s)", status, a.Tool, a.ClientName, a.ID))
	if approve && always {
		p, err := s.GetProfile(ctx, a.Profile)
		if err != nil {
			return err
		}
		idx := a.RuleIndex
		if idx < 0 || idx > len(p.Rules) || p.Rules[idx].Action != domain.ActionAsk {
			idx = 0
		}
		rule := domain.Rule{Tool: a.Tool, Action: domain.ActionAllow}
		p.Rules = append(p.Rules[:idx], append([]domain.Rule{rule}, p.Rules[idx:]...)...)
		return s.PutProfile(WithActor(ctx, by), p)
	}
	return nil
}

// ListApprovals lists approvals, optionally filtered by status, newest first.
func (s *Service) ListApprovals(ctx context.Context, status string) ([]domain.Approval, error) {
	q := `SELECT data FROM approvals`
	var args []any
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at DESC LIMIT 200`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Approval{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var a domain.Approval
		if err := json.Unmarshal([]byte(data), &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
