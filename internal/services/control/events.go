package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
)

// Event is a live update for the dashboard (CTL-042).
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

type bus struct {
	mu   sync.Mutex
	next int
	subs map[int]chan Event
}

func (b *bus) publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default: // slow subscriber: drop rather than block the control plane
		}
	}
}

// Subscribe returns a channel of live events and a cancel function.
func (s *Service) Subscribe() (<-chan Event, func()) {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	id := s.bus.next
	s.bus.next++
	ch := make(chan Event, 64)
	s.bus.subs[id] = ch
	return ch, func() {
		s.bus.mu.Lock()
		defer s.bus.mu.Unlock()
		if _, ok := s.bus.subs[id]; ok {
			delete(s.bus.subs, id)
			close(ch)
		}
	}
}

// Notifier sends approval requests to humans (CTL-024). Implementations are plugins.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, a domain.Approval) error
}

// LogNotifier writes approvals to the structured log.
type LogNotifier struct{ Logger *slog.Logger }

func (LogNotifier) Name() string { return "log" }

func (n LogNotifier) Notify(_ context.Context, a domain.Approval) error {
	l := n.Logger
	if l == nil {
		l = slog.Default()
	}
	l.Info("approval requested", "id", a.ID, "client", a.ClientName, "tool", a.Tool, "expires", a.ExpiresAt.Format(time.RFC3339))
	return nil
}

// WebhookNotifier POSTs a JSON message to a URL (ntfy, Slack incoming webhooks, n8n, …).
type WebhookNotifier struct {
	URL          string
	DashboardURL string
	Client       *http.Client
}

func (WebhookNotifier) Name() string { return "webhook" }

func (n WebhookNotifier) Notify(ctx context.Context, a domain.Approval) error {
	text := fmt.Sprintf("%s wants to run %s (%s). Approve or deny: %s/admin/approvals", a.ClientName, a.Tool, a.Summary, n.DashboardURL)
	body, _ := json.Marshal(map[string]any{"text": text, "title": "mcp-gateway approval", "approval": a})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := n.Client
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
