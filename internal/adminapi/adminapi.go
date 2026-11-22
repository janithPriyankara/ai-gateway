// Package adminapi is the Admin REST API used by the dashboard, the CLI and
// automation (CTL-040, CTL-041). It runs with the control service and reaches
// auth, vault and the gateway through interfaces, so it works the same in
// single-binary and microservices mode.
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/httpx"
	"github.com/mcp-gateway/mcp-gateway/internal/policy"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
	"github.com/mcp-gateway/mcp-gateway/internal/services/auth"
	"github.com/mcp-gateway/mcp-gateway/internal/services/control"
	"github.com/mcp-gateway/mcp-gateway/internal/services/vault"
)

// Auth is what the Admin API needs from the auth service.
type Auth interface {
	AuthenticateAdmin(ctx context.Context, sessionID, bearer string) (auth.Principal, error)
	ListUsers(ctx context.Context) ([]domain.User, error)
	SetRole(ctx context.Context, userID string, role domain.Role) error
	DeleteUser(ctx context.Context, userID string) error
	CreateInvite(ctx context.Context, by string, role domain.Role) (string, error)
	CreateAdminKey(ctx context.Context, userID, name string) (string, auth.AdminKey, error)
	ListAdminKeys(ctx context.Context) ([]auth.AdminKey, error)
	RevokeAdminKey(ctx context.Context, id string) error
	ListClients(ctx context.Context, userID string) ([]domain.Client, error)
	GetClient(ctx context.Context, id string) (domain.Client, error)
	CreateStaticToken(ctx context.Context, userID, name, profile string) (string, domain.Client, error)
	RevokeClient(ctx context.Context, id string) error
	SetClientProfile(ctx context.Context, id, profile string) error
	SigningKey() auth.SigningKeyInfo
	RotateSigningKey(ctx context.Context) error
}

// Vault is what the Admin API needs from the vault service.
type Vault interface {
	SetCredential(ctx context.Context, user, server string, c ports.Credential) error
	DeleteCredential(ctx context.Context, user, server string) error
	ListCredentials(ctx context.Context, server string) ([]vault.CredentialInfo, error)
	DeleteServer(ctx context.Context, server string) error
	SetOAuthApp(ctx context.Context, a vault.OAuthApp) error
	StartConnect(ctx context.Context, user, server string) (string, error)
	CompleteConnect(ctx context.Context, state, code string) (string, error)
	KeyProvider() KeyProviderInfo
}

// KeyProviderInfo describes the active key provider (security page).
type KeyProviderInfo struct {
	Name     string `json:"name"`
	Strength string `json:"strength"`
	Healthy  bool   `json:"healthy"`
}

// Prober tests upstream connectivity (implemented by the gateway).
type Prober interface {
	Probe(ctx context.Context, serverID, userID string) (int, error)
}

// Options configures the API.
type Options struct {
	Auth      Auth
	Vault     Vault
	Control   *control.Service
	Prober    Prober
	PublicURL string
}

// API serves /admin/api/v1 (except /auth, served by the auth service).
type API struct {
	o      Options
	mux    *http.ServeMux
	routes []string // "METHOD /path" patterns, for the OpenAPI drift test
}

// Routes lists the registered route patterns.
func (a *API) Routes() []string { return append([]string(nil), a.routes...) }

type principalKey struct{}

func principal(r *http.Request) auth.Principal {
	p, _ := r.Context().Value(principalKey{}).(auth.Principal)
	return p
}

// New builds the API.
func New(o Options) *API {
	a := &API{o: o, mux: http.NewServeMux()}
	a.register()
	return a
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

type handler func(w http.ResponseWriter, r *http.Request) error

// route registers a handler with a minimum role (AUTH-034). Mutations made with a
// session cookie must carry the session's CSRF token (AUTH-033).
func (a *API) route(pattern string, min domain.Role, h handler) {
	a.routes = append(a.routes, pattern)
	a.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p, err := a.o.Auth.AuthenticateAdmin(r.Context(), auth.SessionID(r), httpx.Bearer(r))
		if err != nil {
			httpx.WriteErr(w, 401, "unauthenticated", "sign in to the dashboard or use an admin API key")
			return
		}
		if !p.Role.AtLeast(min) {
			httpx.WriteErr(w, 403, "forbidden", fmt.Sprintf("this action needs the %s role or higher", min))
			return
		}
		if p.ViaSession && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-CSRF-Token") != p.CSRF {
			httpx.WriteErr(w, 403, "csrf", "missing or invalid X-CSRF-Token header")
			return
		}
		ctx := control.WithActor(context.WithValue(r.Context(), principalKey{}, p), p.UserID)
		if err := h(w, r.WithContext(ctx)); err != nil {
			httpx.WriteError(w, r, err)
		}
	})
}

func ok(w http.ResponseWriter, v any) error { httpx.WriteJSON(w, 200, v); return nil }

const base = "/admin/api/v1"

func (a *API) register() {
	V, M, A, O := domain.RoleViewer, domain.RoleMember, domain.RoleAdmin, domain.RoleOwner
	a.route("GET "+base+"/overview", V, a.overview)
	a.route("GET "+base+"/catalog", V, func(w http.ResponseWriter, r *http.Request) error {
		c, err := control.Catalog()
		if err != nil {
			return err
		}
		return ok(w, c)
	})
	// servers
	a.route("GET "+base+"/servers", V, func(w http.ResponseWriter, r *http.Request) error {
		s, err := a.o.Control.ListServers(r.Context())
		if err != nil {
			return err
		}
		return ok(w, s)
	})
	a.route("POST "+base+"/servers", A, a.createServer)
	a.route("GET "+base+"/servers/{id}", V, a.getServer)
	a.route("PUT "+base+"/servers/{id}", A, a.updateServer)
	a.route("DELETE "+base+"/servers/{id}", A, a.deleteServer)
	a.route("GET "+base+"/servers/{id}/tools", V, func(w http.ResponseWriter, r *http.Request) error {
		p, err := a.o.Control.ServerPins(r.Context(), r.PathValue("id"))
		if err != nil {
			return err
		}
		return ok(w, p)
	})
	a.route("POST "+base+"/servers/{id}/test", M, a.testServer)
	a.route("GET "+base+"/servers/{id}/credentials", V, func(w http.ResponseWriter, r *http.Request) error {
		c, err := a.o.Vault.ListCredentials(r.Context(), r.PathValue("id"))
		if err != nil {
			return err
		}
		if c == nil {
			c = []vault.CredentialInfo{}
		}
		return ok(w, c)
	})
	a.route("PUT "+base+"/servers/{id}/credential", M, a.setCredential)
	a.route("DELETE "+base+"/servers/{id}/credential", M, a.deleteCredential)
	a.route("PUT "+base+"/servers/{id}/oauth-app", A, a.setOAuthApp)
	a.route("POST "+base+"/servers/{id}/connect", M, func(w http.ResponseWriter, r *http.Request) error {
		u, err := a.o.Vault.StartConnect(r.Context(), principal(r).UserID, r.PathValue("id"))
		if err != nil {
			return err
		}
		return ok(w, map[string]string{"authorize_url": u})
	})
	// clients
	a.route("GET "+base+"/clients", V, a.listClients)
	a.route("POST "+base+"/clients", M, a.createClient)
	a.route("PATCH "+base+"/clients/{id}", M, a.patchClient)
	a.route("DELETE "+base+"/clients/{id}", M, a.revokeClient)
	// profiles
	a.route("GET "+base+"/profiles", V, func(w http.ResponseWriter, r *http.Request) error {
		p, err := a.o.Control.ListProfiles(r.Context())
		if err != nil {
			return err
		}
		return ok(w, p)
	})
	a.route("PUT "+base+"/profiles/{name}", A, a.putProfile)
	a.route("DELETE "+base+"/profiles/{name}", A, func(w http.ResponseWriter, r *http.Request) error {
		if err := a.o.Control.DeleteProfile(r.Context(), r.PathValue("name")); err != nil {
			return err
		}
		return ok(w, map[string]bool{"ok": true})
	})
	a.route("POST "+base+"/profiles/simulate", V, a.simulate)
	// approvals
	a.route("GET "+base+"/approvals", V, a.listApprovals)
	a.route("POST "+base+"/approvals/{id}/decide", M, a.decideApproval)
	// pins
	a.route("GET "+base+"/pins/changes", V, func(w http.ResponseWriter, r *http.Request) error {
		p, err := a.o.Control.ListPinChanges(r.Context())
		if err != nil {
			return err
		}
		return ok(w, p)
	})
	a.route("POST "+base+"/pins/{server}/{tool}/accept", A, func(w http.ResponseWriter, r *http.Request) error {
		if err := a.o.Control.AcceptPin(r.Context(), r.PathValue("server"), r.PathValue("tool"), principal(r).UserID); err != nil {
			return err
		}
		return ok(w, map[string]bool{"ok": true})
	})
	a.route("POST "+base+"/pins/{server}/{tool}/reject", A, func(w http.ResponseWriter, r *http.Request) error {
		if err := a.o.Control.RejectPin(r.Context(), r.PathValue("server"), r.PathValue("tool"), principal(r).UserID); err != nil {
			return err
		}
		return ok(w, map[string]bool{"ok": true})
	})
	// audit
	a.route("GET "+base+"/audit", V, a.queryAudit)
	a.route("GET "+base+"/audit/verify", V, func(w http.ResponseWriter, r *http.Request) error {
		res, err := a.o.Control.VerifyChain(r.Context())
		if err != nil {
			return err
		}
		return ok(w, res)
	})
	a.route("GET "+base+"/audit/export", A, a.exportAudit)
	// users and keys
	a.route("GET "+base+"/users", A, func(w http.ResponseWriter, r *http.Request) error {
		u, err := a.o.Auth.ListUsers(r.Context())
		if err != nil {
			return err
		}
		return ok(w, u)
	})
	a.route("POST "+base+"/users/invites", O, a.createInvite)
	a.route("PATCH "+base+"/users/{id}", O, a.patchUser)
	a.route("DELETE "+base+"/users/{id}", O, func(w http.ResponseWriter, r *http.Request) error {
		if r.PathValue("id") == principal(r).UserID {
			return fmt.Errorf("%w: you cannot delete yourself", ports.ErrConflict)
		}
		if err := a.o.Auth.DeleteUser(r.Context(), r.PathValue("id")); err != nil {
			return err
		}
		a.o.Control.AuditAdmin(r.Context(), "delete user "+r.PathValue("id"))
		return ok(w, map[string]bool{"ok": true})
	})
	a.route("GET "+base+"/keys", O, func(w http.ResponseWriter, r *http.Request) error {
		k, err := a.o.Auth.ListAdminKeys(r.Context())
		if err != nil {
			return err
		}
		return ok(w, k)
	})
	a.route("POST "+base+"/keys", O, func(w http.ResponseWriter, r *http.Request) error {
		var req struct {
			Name string `json:"name"`
		}
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			return err
		}
		key, meta, err := a.o.Auth.CreateAdminKey(r.Context(), principal(r).UserID, req.Name)
		if err != nil {
			return err
		}
		a.o.Control.AuditAdmin(r.Context(), "create admin API key "+meta.Name)
		return ok(w, map[string]any{"key": key, "meta": meta})
	})
	a.route("DELETE "+base+"/keys/{id}", O, func(w http.ResponseWriter, r *http.Request) error {
		if err := a.o.Auth.RevokeAdminKey(r.Context(), r.PathValue("id")); err != nil {
			return err
		}
		a.o.Control.AuditAdmin(r.Context(), "revoke admin API key "+r.PathValue("id"))
		return ok(w, map[string]bool{"ok": true})
	})
	// security and config
	a.route("GET "+base+"/security", V, func(w http.ResponseWriter, r *http.Request) error {
		return ok(w, map[string]any{"key_provider": a.o.Vault.KeyProvider(), "signing_key": a.o.Auth.SigningKey()})
	})
	a.route("POST "+base+"/security/rotate-signing-key", O, func(w http.ResponseWriter, r *http.Request) error {
		if err := a.o.Auth.RotateSigningKey(r.Context()); err != nil {
			return err
		}
		a.o.Control.AuditAdmin(r.Context(), "rotate signing key")
		return ok(w, map[string]any{"signing_key": a.o.Auth.SigningKey()})
	})
	a.route("GET "+base+"/config/export", A, func(w http.ResponseWriter, r *http.Request) error {
		y, err := a.o.Control.ExportYAML(r.Context())
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Content-Disposition", `attachment; filename="mcp-gateway-config.yaml"`)
		_, err = w.Write(y)
		return err
	})
	a.route("POST "+base+"/config/import", O, func(w http.ResponseWriter, r *http.Request) error {
		body, err := httpx.ReadBody(w, r)
		if err != nil {
			return err
		}
		if err := a.o.Control.ImportYAML(r.Context(), body); err != nil {
			return err
		}
		return ok(w, map[string]bool{"ok": true})
	})
	a.route("GET "+base+"/events", V, a.events)
	// Upstream OAuth callback: the browser lands here after consenting at the upstream.
	a.mux.HandleFunc("GET /admin/oauth/callback", a.oauthCallback)
}

func (a *API) overview(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p := principal(r)
	servers, err := a.o.Control.ListServers(ctx)
	if err != nil {
		return err
	}
	scope := p.UserID
	if p.Role.AtLeast(domain.RoleAdmin) || p.Role == domain.RoleViewer {
		scope = ""
	}
	clients, err := a.o.Auth.ListClients(ctx, scope)
	if err != nil {
		return err
	}
	active := 0
	for _, c := range clients {
		if c.RevokedAt.IsZero() {
			active++
		}
	}
	y, m, d := time.Now().Date()
	calls, blocked, err := a.o.Control.AuditStats(ctx, time.Date(y, m, d, 0, 0, 0, 0, time.Local))
	if err != nil {
		return err
	}
	pending, _ := a.o.Control.ListApprovals(ctx, domain.ApprovalPending)
	changes, _ := a.o.Control.ListPinChanges(ctx)
	creds, _ := a.o.Vault.ListCredentials(ctx, "")
	needsReauth := []string{}
	for _, c := range creds {
		if c.Status == vault.StatusNeedsReauth {
			needsReauth = append(needsReauth, c.ServerID)
		}
	}
	down := []string{}
	for _, s := range servers {
		if s.Health == "down" || s.Health == "needs_reauth" {
			down = append(down, s.ID)
		}
	}
	return ok(w, map[string]any{
		"servers": len(servers), "clients": active, "calls_today": calls, "blocked_today": blocked,
		"pending_approvals": len(pending), "pin_changes": len(changes), "needs_reauth": needsReauth, "servers_down": down,
		"key_provider": a.o.Vault.KeyProvider(),
	})
}

type serverReq struct {
	domain.Server
	Rules []domain.Rule `json:"rules,omitempty"` // catalog default rules, added to the "default" profile
}

func (a *API) createServer(w http.ResponseWriter, r *http.Request) error {
	var req serverReq
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	if req.ID == "" {
		req.ID = strings.ReplaceAll(req.Prefix, "_", "-")
	}
	if _, err := a.o.Control.GetServer(r.Context(), req.ID); err == nil {
		return fmt.Errorf("%w: a server with id %q already exists", ports.ErrConflict, req.ID)
	}
	if err := a.o.Control.PutServer(r.Context(), req.Server); err != nil {
		return err
	}
	sv, err := a.o.Control.GetServer(r.Context(), req.ID)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, sv)
	return nil
}

func (a *API) getServer(w http.ResponseWriter, r *http.Request) error {
	sv, err := a.o.Control.GetServer(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	return ok(w, sv)
}

func (a *API) updateServer(w http.ResponseWriter, r *http.Request) error {
	var sv domain.Server
	if err := httpx.DecodeJSON(w, r, &sv); err != nil {
		return err
	}
	sv.ID = r.PathValue("id")
	if _, err := a.o.Control.GetServer(r.Context(), sv.ID); err != nil {
		return err
	}
	if err := a.o.Control.PutServer(r.Context(), sv); err != nil {
		return err
	}
	return a.getServer(w, r)
}

func (a *API) deleteServer(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := a.o.Control.DeleteServer(r.Context(), id); err != nil {
		return err
	}
	if err := a.o.Vault.DeleteServer(r.Context(), id); err != nil {
		return err
	}
	return ok(w, map[string]bool{"ok": true})
}

func (a *API) testServer(w http.ResponseWriter, r *http.Request) error {
	if a.o.Prober == nil {
		return errors.New("probing is not available in this deployment")
	}
	scope := r.URL.Query().Get("as")
	user := principal(r).UserID
	if scope == "shared" {
		user = ""
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	n, err := a.o.Prober.Probe(ctx, r.PathValue("id"), user)
	if err != nil {
		health := "down"
		if errors.Is(err, ports.ErrNeedsReauth) {
			health = "needs_reauth"
		}
		_ = a.o.Control.SetServerHealth(r.Context(), r.PathValue("id"), health)
		msg := err.Error()
		if errors.Is(err, ports.ErrNotFound) {
			return err
		}
		return ok(w, map[string]any{"ok": false, "error": msg})
	}
	_ = a.o.Control.SetServerHealth(r.Context(), r.PathValue("id"), "ok")
	return ok(w, map[string]any{"ok": true, "tools": n})
}

type credReq struct {
	Scope string `json:"scope"` // "me" (default) or "shared" (admin+)
	ports.Credential
}

func (a *API) credOwner(r *http.Request, scope string) (string, error) {
	p := principal(r)
	switch scope {
	case "", "me":
		return p.UserID, nil
	case "shared":
		if !p.Role.AtLeast(domain.RoleAdmin) {
			return "", fmt.Errorf("%w: shared credentials need the admin role", ports.ErrForbidden)
		}
		return "", nil
	}
	return "", fmt.Errorf("%w: scope must be me or shared", ports.ErrInvalid)
}

func (a *API) setCredential(w http.ResponseWriter, r *http.Request) error {
	var req credReq
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	owner, err := a.credOwner(r, req.Scope)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if _, err := a.o.Control.GetServer(r.Context(), id); err != nil {
		return err
	}
	if err := a.o.Vault.SetCredential(r.Context(), owner, id, req.Credential); err != nil {
		return err
	}
	scope := "personal"
	if owner == "" {
		scope = "shared"
	}
	a.o.Control.AuditAdmin(r.Context(), fmt.Sprintf("set %s %s credential for server %s", scope, req.Kind, id))
	return ok(w, map[string]bool{"ok": true}) // write-only (CTL-043)
}

func (a *API) deleteCredential(w http.ResponseWriter, r *http.Request) error {
	owner, err := a.credOwner(r, r.URL.Query().Get("scope"))
	if err != nil {
		return err
	}
	if err := a.o.Vault.DeleteCredential(r.Context(), owner, r.PathValue("id")); err != nil {
		return err
	}
	a.o.Control.AuditAdmin(r.Context(), "delete credential for server "+r.PathValue("id"))
	return ok(w, map[string]bool{"ok": true})
}

func (a *API) setOAuthApp(w http.ResponseWriter, r *http.Request) error {
	var app vault.OAuthApp
	if err := httpx.DecodeJSON(w, r, &app); err != nil {
		return err
	}
	app.ServerID = r.PathValue("id")
	if app.RedirectURL == "" {
		app.RedirectURL = strings.TrimRight(a.o.PublicURL, "/") + "/admin/oauth/callback"
	}
	if err := a.o.Vault.SetOAuthApp(r.Context(), app); err != nil {
		return err
	}
	a.o.Control.AuditAdmin(r.Context(), "set OAuth app for server "+app.ServerID)
	return ok(w, map[string]bool{"ok": true})
}

func (a *API) oauthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Redirect(w, r, "/admin/servers?oauth_error="+url.QueryEscape(e), http.StatusFound)
		return
	}
	server, err := a.o.Vault.CompleteConnect(r.Context(), q.Get("state"), q.Get("code"))
	if err != nil {
		http.Redirect(w, r, "/admin/servers?oauth_error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	a.o.Control.AuditAdmin(r.Context(), "connected OAuth credential for server "+server)
	http.Redirect(w, r, "/admin/servers/"+url.PathEscape(server)+"?connected=1", http.StatusFound)
}

// --- clients ---

func (a *API) canManageClient(r *http.Request, id string) (domain.Client, error) {
	c, err := a.o.Auth.GetClient(r.Context(), id)
	if err != nil {
		return c, err
	}
	p := principal(r)
	if c.UserID != p.UserID && !p.Role.AtLeast(domain.RoleAdmin) {
		return c, fmt.Errorf("%w: you can only manage your own AI tools", ports.ErrForbidden)
	}
	return c, nil
}

func (a *API) listClients(w http.ResponseWriter, r *http.Request) error {
	p := principal(r)
	scope := p.UserID
	if p.Role.AtLeast(domain.RoleAdmin) || p.Role == domain.RoleViewer || r.URL.Query().Get("all") == "1" && p.Role.AtLeast(domain.RoleAdmin) {
		scope = ""
	}
	cs, err := a.o.Auth.ListClients(r.Context(), scope)
	if err != nil {
		return err
	}
	if counts, err := a.o.Control.ClientCallCounts(r.Context()); err == nil {
		for i := range cs {
			cs[i].Calls = counts[cs[i].ID]
		}
	}
	return ok(w, cs)
}

// Snippets are ready-to-paste client configurations (UI-005).
func (a *API) snippets(token string) map[string]string {
	u := strings.TrimRight(a.o.PublicURL, "/") + "/mcp"
	return map[string]string{
		"claude_code": fmt.Sprintf("claude mcp add --transport http gateway %s --header \"Authorization: Bearer %s\"", u, token),
		"codex":       fmt.Sprintf("[mcp_servers.gateway]\nurl = \"%s\"\nbearer_token_env_var = \"MCP_GATEWAY_TOKEN\"\n\n# then: export MCP_GATEWAY_TOKEN=%s", u, token),
		"cursor":      fmt.Sprintf("{\n  \"mcpServers\": {\n    \"gateway\": {\n      \"url\": \"%s\",\n      \"headers\": { \"Authorization\": \"Bearer %s\" }\n    }\n  }\n}", u, token),
		"generic":     fmt.Sprintf("URL: %s\nHeader: Authorization: Bearer %s", u, token),
	}
}

func (a *API) createClient(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name    string `json:"name"`
		Profile string `json:"profile"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	if _, err := a.o.Control.GetProfile(r.Context(), req.Profile); err != nil {
		return fmt.Errorf("%w: unknown profile %q", ports.ErrInvalid, req.Profile)
	}
	tok, c, err := a.o.Auth.CreateStaticToken(r.Context(), principal(r).UserID, req.Name, req.Profile)
	if err != nil {
		return err
	}
	a.o.Control.AuditAdmin(r.Context(), fmt.Sprintf("create AI tool token %s (profile %s)", c.Name, c.Profile))
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"token": tok, "client": c, "snippets": a.snippets(tok)})
	return nil
}

func (a *API) patchClient(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Profile string `json:"profile"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	if _, err := a.canManageClient(r, r.PathValue("id")); err != nil {
		return err
	}
	if _, err := a.o.Control.GetProfile(r.Context(), req.Profile); err != nil {
		return fmt.Errorf("%w: unknown profile %q", ports.ErrInvalid, req.Profile)
	}
	if err := a.o.Auth.SetClientProfile(r.Context(), r.PathValue("id"), req.Profile); err != nil {
		return err
	}
	a.o.Control.AuditAdmin(r.Context(), fmt.Sprintf("set profile of client %s to %s", r.PathValue("id"), req.Profile))
	c, err := a.o.Auth.GetClient(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	return ok(w, c)
}

func (a *API) revokeClient(w http.ResponseWriter, r *http.Request) error {
	c, err := a.canManageClient(r, r.PathValue("id"))
	if err != nil {
		return err
	}
	if err := a.o.Auth.RevokeClient(r.Context(), c.ID); err != nil {
		return err
	}
	a.o.Control.AuditAdmin(r.Context(), "revoke AI tool "+c.Name+" ("+c.ID+")")
	return ok(w, map[string]bool{"ok": true})
}

// --- profiles ---

func (a *API) putProfile(w http.ResponseWriter, r *http.Request) error {
	var p domain.Profile
	if err := httpx.DecodeJSON(w, r, &p); err != nil {
		return err
	}
	p.Name = r.PathValue("name")
	if err := a.o.Control.PutProfile(r.Context(), p); err != nil {
		return err
	}
	out, err := a.o.Control.GetProfile(r.Context(), p.Name)
	if err != nil {
		return err
	}
	return ok(w, out)
}

func (a *API) simulate(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Profile  string `json:"profile"`
		Tool     string `json:"tool"`
		ReadOnly bool   `json:"read_only"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	profiles, err := a.o.Control.ListProfiles(r.Context())
	if err != nil {
		return err
	}
	eng, err := policy.Compile(profiles)
	if err != nil {
		return err
	}
	servers, err := a.o.Control.ListServers(r.Context())
	if err != nil {
		return err
	}
	serverID := ""
	if i := strings.Index(req.Tool, "__"); i > 0 {
		for _, s := range servers {
			if s.Prefix == req.Tool[:i] {
				serverID = s.ID
			}
		}
	}
	d := eng.Decide(req.Profile, serverID, req.Tool, req.ReadOnly)
	if serverID == "" && d.RuleIndex == -1 {
		d.Reason = "no server uses the prefix of this tool name"
	}
	return ok(w, map[string]any{"decision": d, "server_id": serverID})
}

// --- approvals ---

func (a *API) listApprovals(w http.ResponseWriter, r *http.Request) error {
	list, err := a.o.Control.ListApprovals(r.Context(), r.URL.Query().Get("status"))
	if err != nil {
		return err
	}
	p := principal(r)
	if p.Role == domain.RoleMember {
		mine := []domain.Approval{}
		for _, ap := range list {
			if ap.UserID == p.UserID {
				mine = append(mine, ap)
			}
		}
		list = mine
	}
	return ok(w, list)
}

func (a *API) decideApproval(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Approve bool `json:"approve"`
		Always  bool `json:"always"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	p := principal(r)
	ap, err := a.o.Control.GetApproval(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	if ap.UserID != p.UserID && !p.Role.AtLeast(domain.RoleAdmin) {
		return fmt.Errorf("%w: only the requesting user or an admin can decide", ports.ErrForbidden)
	}
	if req.Always && !p.Role.AtLeast(domain.RoleAdmin) {
		return fmt.Errorf("%w: only admins can add an always-allow rule", ports.ErrForbidden)
	}
	if err := a.o.Control.DecideApproval(r.Context(), ap.ID, req.Approve, req.Always, p.Name); err != nil {
		return err
	}
	out, err := a.o.Control.GetApproval(r.Context(), ap.ID)
	if err != nil {
		return err
	}
	return ok(w, out)
}

// --- audit ---

func auditQuery(r *http.Request) domain.AuditQuery {
	q := r.URL.Query()
	aq := domain.AuditQuery{UserID: q.Get("user"), ClientID: q.Get("client"), ServerID: q.Get("server"), Tool: q.Get("tool"),
		Decision: q.Get("decision"), Kind: q.Get("kind")}
	aq.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	aq.Limit, _ = strconv.Atoi(q.Get("limit"))
	if s, err := time.Parse(time.RFC3339, q.Get("since")); err == nil {
		aq.Since = s
	}
	if s, err := time.Parse(time.RFC3339, q.Get("until")); err == nil {
		aq.Until = s
	}
	return aq
}

func (a *API) queryAudit(w http.ResponseWriter, r *http.Request) error {
	aq := auditQuery(r)
	p := principal(r)
	if p.Role == domain.RoleMember {
		aq.UserID = p.UserID // members see their own activity
	}
	evs, err := a.o.Control.QueryAudit(r.Context(), aq)
	if err != nil {
		return err
	}
	return ok(w, evs)
}

func (a *API) exportAudit(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="mcp-gateway-audit.ndjson"`)
	enc := json.NewEncoder(w)
	aq := auditQuery(r)
	aq.Limit = 500
	for {
		evs, err := a.o.Control.QueryAudit(r.Context(), aq)
		if err != nil {
			return err
		}
		for _, e := range evs {
			if err := enc.Encode(e); err != nil {
				return nil
			}
		}
		if len(evs) < aq.Limit {
			return nil
		}
		aq.BeforeID = evs[len(evs)-1].ID
	}
}

// --- users ---

func (a *API) createInvite(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Role domain.Role `json:"role"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	tok, err := a.o.Auth.CreateInvite(r.Context(), principal(r).UserID, req.Role)
	if err != nil {
		return err
	}
	a.o.Control.AuditAdmin(r.Context(), "create invite for role "+string(req.Role))
	return ok(w, map[string]string{"token": tok, "url": strings.TrimRight(a.o.PublicURL, "/") + "/admin/invite?token=" + url.QueryEscape(tok)})
}

func (a *API) patchUser(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Role domain.Role `json:"role"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	if err := a.o.Auth.SetRole(r.Context(), r.PathValue("id"), req.Role); err != nil {
		return err
	}
	a.o.Control.AuditAdmin(r.Context(), fmt.Sprintf("set role of user %s to %s", r.PathValue("id"), req.Role))
	return ok(w, map[string]bool{"ok": true})
}

// --- events (SSE, CTL-042) ---

func (a *API) events(w http.ResponseWriter, r *http.Request) error {
	fl, okf := w.(http.Flusher)
	if !okf {
		return errors.New("streaming unsupported")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, cancel := a.o.Control.Subscribe()
	defer cancel()
	_, _ = io.WriteString(w, ": connected\n\n")
	fl.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	p := principal(r)
	for {
		select {
		case <-r.Context().Done():
			return nil
		case <-ping.C:
			_, _ = io.WriteString(w, ": ping\n\n")
			fl.Flush()
		case e, okc := <-ch:
			if !okc {
				return nil
			}
			if p.Role == domain.RoleMember && !visibleToMember(e, p.UserID) {
				continue
			}
			b, _ := json.Marshal(e.Data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, b)
			fl.Flush()
		}
	}
}

func visibleToMember(e control.Event, userID string) bool {
	switch d := e.Data.(type) {
	case domain.Approval:
		return d.UserID == userID
	case domain.AuditEvent:
		return d.UserID == userID
	}
	return true
}
