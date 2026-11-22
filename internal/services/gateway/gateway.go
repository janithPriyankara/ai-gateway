// Package gateway is the MCP data plane: it authenticates AI clients, aggregates
// upstream tools, enforces policy, injects upstream credentials and audits calls.
//
// It depends only on the interfaces in internal/ports, so it runs the same in
// single-binary mode and as a stateless microservice.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/policy"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

// Options configures the gateway.
type Options struct {
	Auth      ports.Authenticator
	Config    ports.ConfigSource
	Creds     ports.CredentialProvider
	Audit     ports.AuditSink
	Approvals ports.ApprovalBroker
	Pins      ports.PinRegistry
	// ResourceMetadataURL is advertised in WWW-Authenticate on 401 (AUTH-020).
	ResourceMetadataURL string
	// TrustedOrigins are browser origins allowed to call /mcp (GW-017).
	TrustedOrigins []string
	Version        string
	Logger         *slog.Logger
	// ToolCacheTTL controls how long upstream tool lists are cached (default 5 min).
	ToolCacheTTL time.Duration
}

// Gateway is the data plane.
type Gateway struct {
	o    Options
	log  *slog.Logger
	pool *pool
	now  func() time.Time

	rt atomic.Pointer[runtime]

	toolsMu  sync.Mutex
	tools    map[string]*toolSet // server id -> tools
	toolsGen atomic.Int64

	srvMu   sync.Mutex
	servers map[string]*mcp.Server // profile|version|toolsGen -> server

	audit *auditBatcher
	stop  context.CancelFunc
	done  chan struct{}
}

// runtime is an immutable view of the current config.
type runtime struct {
	snap       domain.Snapshot
	engine     *policy.Engine
	servers    map[string]domain.Server
	quarantine map[string]bool // serverID + "\x00" + tool
}

type toolSet struct {
	hash    string // server config hash the tools were fetched for
	tools   []*mcp.Tool
	fetched time.Time
}

// New builds a gateway. Call Start to begin following config changes.
func New(o Options) (*Gateway, error) {
	if o.Auth == nil || o.Config == nil || o.Creds == nil || o.Audit == nil || o.Approvals == nil || o.Pins == nil {
		return nil, errors.New("gateway: all ports must be provided")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.ToolCacheTTL == 0 {
		o.ToolCacheTTL = 5 * time.Minute
	}
	g := &Gateway{o: o, log: o.Logger, pool: newPool(o.Creds, o.Version), now: time.Now,
		tools: map[string]*toolSet{}, servers: map[string]*mcp.Server{}, done: make(chan struct{})}
	g.audit = newAuditBatcher(o.Audit, o.Logger)
	empty, _ := policy.Compile(nil)
	g.rt.Store(&runtime{engine: empty, servers: map[string]domain.Server{}, quarantine: map[string]bool{}, snap: domain.Snapshot{Version: -1}})
	return g, nil
}

// Start loads the first snapshot and follows changes in the background (GW-015).
func (g *Gateway) Start(ctx context.Context) error {
	snap, err := g.o.Config.Snapshot(ctx, -1)
	if err != nil {
		return fmt.Errorf("gateway: loading config: %w", err)
	}
	if err := g.apply(snap); err != nil {
		return err
	}
	ctx, g.stop = context.WithCancel(context.WithoutCancel(ctx))
	go g.follow(ctx)
	return nil
}

// Ready reports whether a config snapshot has been loaded.
func (g *Gateway) Ready() bool { return g.rt.Load().snap.Version >= 0 }

// Close stops background work, flushes audit events and closes upstream sessions.
func (g *Gateway) Close() {
	if g.stop != nil {
		g.stop()
		<-g.done
	}
	g.audit.close()
	g.pool.closeAll()
}

func (g *Gateway) follow(ctx context.Context) {
	defer close(g.done)
	reap := time.NewTicker(time.Minute)
	defer reap.Stop()
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-reap.C:
			g.reapSessions()
		default:
		}
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		snap, err := g.o.Config.Snapshot(pctx, g.rt.Load().snap.Version)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			g.log.Warn("config refresh failed; keeping last config", "err", err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if snap.Version != g.rt.Load().snap.Version {
			if err := g.apply(snap); err != nil {
				g.log.Error("invalid config snapshot ignored", "err", err)
			}
		}
	}
}

func (g *Gateway) reapSessions() {
	rt := g.rt.Load()
	valid := map[string]bool{}
	for _, s := range rt.servers {
		valid[s.ID+"\x00"+configHash(s)] = true
	}
	g.pool.reap(valid)
}

func (g *Gateway) apply(snap domain.Snapshot) error {
	eng, err := policy.Compile(snap.Profiles)
	if err != nil {
		return err
	}
	rt := &runtime{snap: snap, engine: eng, servers: map[string]domain.Server{}, quarantine: map[string]bool{}}
	for _, s := range snap.Servers {
		rt.servers[s.ID] = s
	}
	for _, p := range snap.Pins {
		if p.Status == domain.PinQuarantined {
			rt.quarantine[p.ServerID+"\x00"+p.Tool] = true
		}
	}
	g.rt.Store(rt)
	g.srvMu.Lock()
	g.servers = map[string]*mcp.Server{} // rebuilt lazily per profile
	g.srvMu.Unlock()
	return nil
}

// --- HTTP -------------------------------------------------------------------

type identityKey struct{}

// Handler returns the /mcp handler (GW-001, GW-002, GW-017).
func (g *Gateway) Handler() http.Handler {
	h := mcp.NewStreamableHTTPHandler(g.serverFor, &mcp.StreamableHTTPOptions{
		Stateless: true, Logger: nil, MaxRequestBodyBytes: 4 << 20,
	})
	verifier := func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		id, err := g.o.Auth.Authenticate(ctx, token)
		if err != nil {
			if errors.Is(err, ports.ErrUnauthenticated) {
				return nil, auth.ErrInvalidToken
			}
			return nil, err
		}
		return &auth.TokenInfo{UserID: id.UserID, Expiration: g.now().Add(time.Hour), Extra: map[string]any{"identity": id}}, nil
	}
	authed := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{ResourceMetadataURL: g.o.ResourceMetadataURL})(h)
	cop := http.NewCrossOriginProtection()
	for _, o := range g.o.TrustedOrigins {
		_ = cop.AddTrustedOrigin(o)
	}
	return cop.Handler(authed)
}

func identityFrom(ti *auth.TokenInfo) (domain.Identity, bool) {
	if ti == nil || ti.Extra == nil {
		return domain.Identity{}, false
	}
	id, ok := ti.Extra["identity"].(domain.Identity)
	return id, ok
}

// serverFor returns the MCP server for the caller's profile, warming tool caches as needed.
func (g *Gateway) serverFor(r *http.Request) *mcp.Server {
	id, ok := identityFrom(auth.TokenInfoFromContext(r.Context()))
	rt := g.rt.Load()
	if !ok {
		return mcp.NewServer(&mcp.Implementation{Name: "mcp-gateway", Version: g.o.Version}, nil)
	}
	g.warmTools(r.Context(), rt, id)
	key := id.Profile + "|" + strconv.FormatInt(rt.snap.Version, 10) + "|" + strconv.FormatInt(g.toolsGen.Load(), 10)
	g.srvMu.Lock()
	s := g.servers[key]
	g.srvMu.Unlock()
	if s != nil {
		return s
	}
	s = g.buildServer(rt, id.Profile)
	g.srvMu.Lock()
	if len(g.servers) > 256 {
		g.servers = map[string]*mcp.Server{}
	}
	g.servers[key] = s
	g.srvMu.Unlock()
	return s
}

// profileServers returns the enabled servers of a profile, sorted by id.
func (rt *runtime) profileServers(profile string) []domain.Server {
	var out []domain.Server
	for id := range rt.engine.ProfileServers(profile) {
		if s, ok := rt.servers[id]; ok && s.Enabled {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// warmTools makes sure tool lists for the caller's servers are cached (fetching with
// the caller's credentials), in parallel, bounded by a short deadline.
func (g *Gateway) warmTools(ctx context.Context, rt *runtime, id domain.Identity) {
	var wg sync.WaitGroup
	for _, sv := range rt.profileServers(id.Profile) {
		g.toolsMu.Lock()
		ts := g.tools[sv.ID]
		g.toolsMu.Unlock()
		if ts != nil && ts.hash == configHash(sv) && g.now().Sub(ts.fetched) < g.o.ToolCacheTTL {
			continue
		}
		wg.Add(1)
		go func(sv domain.Server) {
			defer wg.Done()
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			if err := g.refreshTools(fctx, sv, id.UserID); err != nil {
				g.log.Debug("tool list unavailable", "server", sv.ID, "err", err)
			}
		}(sv)
	}
	wg.Wait()
}

// refreshTools lists an upstream's tools and reports them to the pin registry (GW-018).
func (g *Gateway) refreshTools(ctx context.Context, sv domain.Server, userID string) error {
	s, err := g.pool.get(ctx, sv, userID)
	if err != nil {
		return err
	}
	var tools []*mcp.Tool
	for t, err := range s.cs.Tools(ctx, nil) {
		if err != nil {
			g.pool.drop(sv, userID)
			return err
		}
		tools = append(tools, t)
	}
	defs := make([]ports.ToolDef, 0, len(tools))
	for _, t := range tools {
		defs = append(defs, ports.ToolDef{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema, Annotations: t.Annotations})
	}
	pins, err := g.o.Pins.ObserveTools(ctx, sv.ID, defs)
	if err != nil {
		g.log.Warn("pin registry unavailable; treating changed tools as untrusted", "server", sv.ID, "err", err)
	} else {
		// Apply quarantine decisions immediately, before the next snapshot arrives.
		rt := g.rt.Load()
		changed := false
		for _, p := range pins {
			k := p.ServerID + "\x00" + p.Tool
			if (p.Status == domain.PinQuarantined) != rt.quarantine[k] {
				changed = true
			}
		}
		if changed {
			nq := make(map[string]bool, len(rt.quarantine))
			for k, v := range rt.quarantine {
				nq[k] = v
			}
			for _, p := range pins {
				nq[p.ServerID+"\x00"+p.Tool] = p.Status == domain.PinQuarantined
			}
			nrt := *rt
			nrt.quarantine = nq
			g.rt.CompareAndSwap(rt, &nrt)
		}
	}
	g.toolsMu.Lock()
	g.tools[sv.ID] = &toolSet{hash: configHash(sv), tools: tools, fetched: g.now()}
	g.toolsMu.Unlock()
	g.toolsGen.Add(1)
	return nil
}

func readOnly(t *mcp.Tool) bool { return t.Annotations != nil && t.Annotations.ReadOnlyHint }

// sanitizeSchema returns an object schema the SDK accepts, whatever the upstream sent.
func sanitizeSchema(in any) map[string]any {
	m := map[string]any{}
	if in != nil {
		if b, err := json.Marshal(in); err == nil {
			_ = json.Unmarshal(b, &m)
		}
	}
	if m == nil {
		m = map[string]any{}
	}
	m["type"] = "object"
	return m
}

// buildServer creates the aggregated MCP server for a profile (GW-003, GW-004).
func (g *Gateway) buildServer(rt *runtime, profile string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "mcp-gateway", Title: "MCP Gateway", Version: g.o.Version},
		&mcp.ServerOptions{
			Instructions: "Tools from several MCP servers, namespaced as <server>__<tool>. Some calls may wait for human approval.",
			// GW-019: advertise tools even when none are loaded yet, or clients never ask.
			// listChanged is false: the endpoint is stateless and cannot push notifications.
			Capabilities: &mcp.ServerCapabilities{Logging: &mcp.LoggingCapabilities{}, Tools: &mcp.ToolCapabilities{}},
		})
	registered := map[string]bool{}
	// Calls to hidden tools (denied, quarantined, unknown) get an audited tool error
	// instead of a bare protocol error (GW-006, GW-011).
	srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/call" {
				if ctr, ok := req.(*mcp.CallToolRequest); ok && ctr.Params != nil && !registered[ctr.Params.Name] {
					return g.rejectHidden(rt, ctr), nil
				}
			}
			return next(ctx, method, req)
		}
	})
	for _, sv := range rt.profileServers(profile) {
		g.toolsMu.Lock()
		ts := g.tools[sv.ID]
		g.toolsMu.Unlock()
		if ts == nil || ts.hash != configHash(sv) {
			continue
		}
		for _, t := range ts.tools {
			name := sv.Prefix + "__" + t.Name
			ro := readOnly(t)
			if rt.quarantine[sv.ID+"\x00"+t.Name] || !rt.engine.Visible(profile, sv.ID, name, ro) {
				continue
			}
			nt := &mcp.Tool{Name: name, Title: t.Title, Description: t.Description, InputSchema: sanitizeSchema(t.InputSchema), Annotations: t.Annotations}
			func() {
				defer func() {
					if r := recover(); r != nil {
						g.log.Warn("skipping upstream tool with an invalid definition", "tool", name, "err", r)
					}
				}()
				srv.AddTool(nt, g.toolHandler(sv.ID, t.Name, name, ro))
				registered[name] = true
			}()
		}
	}
	return srv
}

// rejectHidden explains why a tool is not callable and audits the attempt.
func (g *Gateway) rejectHidden(rt *runtime, req *mcp.CallToolRequest) *mcp.CallToolResult {
	name := req.Params.Name
	id, _ := identityFrom(req.Extra.TokenInfo)
	serverID, upstream := "", name
	if i := strings.Index(name, "__"); i > 0 {
		for _, s := range rt.servers {
			if s.Prefix == name[:i] {
				serverID, upstream = s.ID, name[i+2:]
			}
		}
	}
	msg := "Unknown tool " + name + "."
	switch {
	case serverID == "":
	case rt.quarantine[serverID+"\x00"+upstream]:
		msg = "This tool's definition changed and is paused until an admin reviews it in the dashboard (Tool changes)."
	default:
		ro := false
		g.toolsMu.Lock()
		if ts := g.tools[serverID]; ts != nil {
			for _, t := range ts.tools {
				if t.Name == upstream {
					ro = readOnly(t)
				}
			}
		}
		g.toolsMu.Unlock()
		if d := rt.engine.Decide(id.Profile, serverID, name, ro); d.Action == domain.ActionDeny {
			msg = "Blocked by gateway policy: " + d.Reason
		}
	}
	g.audit.add(domain.AuditEvent{Kind: "call", RequestID: newRequestID(), UserID: id.UserID, ClientID: id.ClientID, Profile: id.Profile,
		ServerID: serverID, Tool: name, Decision: "deny", Status: domain.StatusDenied, Summary: NewRedactor(nil).Summary(req.Params.Arguments)})
	return toolError(msg)
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Probe connects to a server with the given user's credentials (empty user = shared
// credential) and lists its tools. Used by "Test connection" and health checks (CTL-044).
func (g *Gateway) Probe(ctx context.Context, serverID, userID string) (int, error) {
	rt := g.rt.Load()
	sv, ok := rt.servers[serverID]
	if !ok {
		// The snapshot may lag a just-created server: fetch the latest config.
		snap, err := g.o.Config.Snapshot(ctx, -1)
		if err != nil {
			return 0, err
		}
		_ = g.apply(snap)
		if sv, ok = g.rt.Load().servers[serverID]; !ok {
			return 0, fmt.Errorf("%w: server %q", ports.ErrNotFound, serverID)
		}
	}
	g.pool.drop(sv, userID)
	g.pool.dropCredential(sv, userID)
	if err := g.refreshTools(ctx, sv, userID); err != nil {
		return 0, err
	}
	g.toolsMu.Lock()
	defer g.toolsMu.Unlock()
	return len(g.tools[serverID].tools), nil
}
