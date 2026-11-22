package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/policy"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

// toolHandler is the per-tool call pipeline:
// identity → rate limit → policy → pin check → approval → credential → upstream → redact → audit.
func (g *Gateway) toolHandler(serverID, upstreamName, name string, ro bool) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := g.now()
		id, ok := identityFrom(req.Extra.TokenInfo)
		if !ok {
			return toolError("unauthenticated"), nil
		}
		rt := g.rt.Load()
		args := req.Params.Arguments
		base := NewRedactor(nil)
		ev := domain.AuditEvent{Kind: "call", RequestID: newRequestID(), UserID: id.UserID, ClientID: id.ClientID, Profile: id.Profile,
			ServerID: serverID, Tool: name, Summary: base.Summary(args)}
		done := func(res *mcp.CallToolResult, decision, status string) (*mcp.CallToolResult, error) {
			ev.Decision, ev.Status = decision, status
			ev.LatencyMS = g.now().Sub(start).Milliseconds()
			g.audit.add(ev)
			return res, nil
		}

		if !rt.engine.AllowRate(id.Profile, id.ClientID) {
			return done(toolError("Rate limit reached for this AI tool's profile. Try again in a minute."), "deny", domain.StatusDenied)
		}
		d := rt.engine.Decide(id.Profile, serverID, name, ro)
		if rt.quarantine[serverID+"\x00"+upstreamName] {
			return done(toolError("This tool's definition changed and is paused until an admin reviews it in the dashboard (Tool changes)."), "deny", domain.StatusDenied)
		}
		switch d.Action {
		case domain.ActionDeny:
			return done(toolError("Blocked by gateway policy: "+d.Reason), "deny", domain.StatusDenied)
		case domain.ActionAsk:
			a, err := g.o.Approvals.RequestApproval(ctx, domain.Approval{UserID: id.UserID, ClientID: id.ClientID, ClientName: id.ClientName,
				Profile: id.Profile, ServerID: serverID, Tool: name, Summary: ev.Summary, RuleIndex: d.RuleIndex})
			if err != nil {
				return done(toolError("Could not request approval: "+err.Error()), "ask", domain.StatusError)
			}
			if a.Status != domain.ApprovalApproved {
				msg := "Denied by a human reviewer."
				if a.Status == domain.ApprovalExpired {
					msg = "No one approved this call in time, so it was not run."
				}
				return done(toolError(msg), "ask", domain.StatusDenied)
			}
			ev.Summary += " (approved by " + a.DecidedBy + ")"
		}

		sv, ok := rt.servers[serverID]
		if !ok || !sv.Enabled {
			return done(toolError("This server is no longer configured."), string(d.Action), domain.StatusError)
		}
		res, err := g.callUpstream(ctx, sv, id.UserID, upstreamName, args, ro)
		decision := string(d.Action)
		if err != nil {
			status := domain.StatusError
			if errors.Is(err, context.DeadlineExceeded) {
				status = domain.StatusTimeout
			}
			return done(toolError(userMessage(sv, err)), decision, status)
		}
		return done(res, decision, domain.StatusOK)
	}
}

func userMessage(sv domain.Server, err error) string {
	switch {
	case errors.Is(err, ports.ErrNoCredential):
		return fmt.Sprintf("%s is not connected yet. Add a credential for it in the gateway dashboard (Servers → %s).", sv.Name, sv.Name)
	case errors.Is(err, ports.ErrNeedsReauth), errors.Is(err, errUpstreamUnauthorized):
		return fmt.Sprintf("The connection to %s expired. Reconnect it in the gateway dashboard (Servers → %s).", sv.Name, sv.Name)
	case errors.Is(err, errCircuitOpen):
		return fmt.Sprintf("%s: %s", sv.Name, errCircuitOpen.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("%s did not answer within %d seconds.", sv.Name, sv.TimeoutSeconds)
	}
	return fmt.Sprintf("%s could not be reached. The gateway logged the details.", sv.Name)
}

// callUpstream forwards a call with timeout, breaker and a single retry for read-only tools (GW-012, GW-013).
func (g *Gateway) callUpstream(ctx context.Context, sv domain.Server, userID, tool string, args json.RawMessage, ro bool) (*mcp.CallToolResult, error) {
	b := g.pool.breakerFor(sv.ID)
	if !b.allow(g.now()) {
		return nil, errCircuitOpen
	}
	timeout := time.Duration(sv.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	attempts := 1
	if ro {
		attempts = 2
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		res, secrets, err := g.callOnce(cctx, sv, userID, tool, args)
		cancel()
		if err == nil {
			b.record(true, g.now())
			NewRedactor(secrets).Result(res)
			return res, nil
		}
		lastErr = err
		if errors.Is(err, ports.ErrNoCredential) || errors.Is(err, ports.ErrNeedsReauth) || errors.Is(err, errUpstreamUnauthorized) || ctx.Err() != nil {
			return nil, err // not a transport failure: no retry, no breaker penalty
		}
		g.log.Warn("upstream call failed", "server", sv.ID, "tool", tool, "attempt", i+1, "err", err)
		g.pool.drop(sv, userID)
		b.record(false, g.now())
		if errors.Is(err, context.DeadlineExceeded) {
			break
		}
	}
	return nil, lastErr
}

func (g *Gateway) callOnce(ctx context.Context, sv domain.Server, userID, tool string, args json.RawMessage) (*mcp.CallToolResult, []string, error) {
	s, err := g.pool.get(ctx, sv, userID)
	if err != nil {
		return nil, nil, err
	}
	params := &mcp.CallToolParams{Name: tool}
	if len(args) > 0 {
		params.Arguments = args
	}
	res, err := s.cs.CallTool(ctx, params)
	if err != nil {
		return nil, nil, unwrapCredErr(err)
	}
	return res, s.secrets, nil
}

// auditBatcher records audit events asynchronously in batches (GW-011).
type auditBatcher struct {
	sink    ports.AuditSink
	log     *slog.Logger
	ch      chan domain.AuditEvent
	wg      sync.WaitGroup
	dropped atomic.Int64
	once    sync.Once
}

func newAuditBatcher(sink ports.AuditSink, log *slog.Logger) *auditBatcher {
	a := &auditBatcher{sink: sink, log: log, ch: make(chan domain.AuditEvent, 8192)}
	a.wg.Add(1)
	go a.run()
	return a
}

func (a *auditBatcher) add(e domain.AuditEvent) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	select {
	case a.ch <- e:
	default:
		if a.dropped.Add(1)%1000 == 1 {
			a.log.Error("audit queue full; dropping events", "dropped_total", a.dropped.Load())
		}
	}
}

func (a *auditBatcher) run() {
	defer a.wg.Done()
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	batch := make([]domain.AuditEvent, 0, 256)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := a.sink.Record(ctx, batch); err != nil {
			a.log.Error("audit write failed", "events", len(batch), "err", err)
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-a.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= 256 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (a *auditBatcher) close() {
	a.once.Do(func() { close(a.ch); a.wg.Wait() })
}

var _ = policy.ReasonRateLimited
