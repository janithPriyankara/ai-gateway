package auth

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/httpx"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
)

// SessionCookie is the dashboard session cookie name.
const SessionCookie = "gw_session"

// ProfileLister lists profile names for the consent screen. In single-binary mode it
// is the control service; in microservices mode, an RPC client.
type ProfileLister func(ctx context.Context) ([]string, error)

func (s *Service) secureCookies() bool { return strings.HasPrefix(s.publicURL, "https://") }

func (s *Service) setSession(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: s.secureCookies(),
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionIdle.Seconds())})
}

func (s *Service) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// SessionID reads the session cookie.
func SessionID(r *http.Request) string {
	if c, err := r.Cookie(SessionCookie); err == nil {
		return c.Value
	}
	return ""
}

// ProtectedResourceMetadata is RFC 9728 metadata (AUTH-020).
func (s *Service) ProtectedResourceMetadata() map[string]any {
	return map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.issuer},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "mcp-gateway",
	}
}

// ResourceMetadataURL is advertised in WWW-Authenticate.
func (s *Service) ResourceMetadataURL() string {
	return s.publicURL + "/.well-known/oauth-protected-resource"
}

// AuthorizationServerMetadata is RFC 8414 metadata (AUTH-021).
func (s *Service) AuthorizationServerMetadata() map[string]any {
	return map[string]any{
		"issuer":                                         s.issuer,
		"authorization_endpoint":                         s.publicURL + "/oauth/authorize",
		"token_endpoint":                                 s.publicURL + "/oauth/token",
		"registration_endpoint":                          s.publicURL + "/oauth/register",
		"jwks_uri":                                       s.publicURL + "/.well-known/jwks.json",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"scopes_supported":                               []string{"mcp"},
		"authorization_response_iss_parameter_supported": true,
	}
}

// OAuthHandler serves the OAuth 2.1 authorization server and discovery endpoints.
func (s *Service) OAuthHandler(profiles ProfileLister) http.Handler {
	mux := http.NewServeMux()
	prm := func(w http.ResponseWriter, r *http.Request) { httpx.WriteJSON(w, 200, s.ProtectedResourceMetadata()) }
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", prm)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", prm)
	asm := func(w http.ResponseWriter, r *http.Request) { httpx.WriteJSON(w, 200, s.AuthorizationServerMetadata()) }
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", asm)
	mux.HandleFunc("GET /.well-known/openid-configuration", asm)
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.JWKS())
	})
	mux.HandleFunc("POST /oauth/register", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ClientName   string   `json:"client_name"`
			RedirectURIs []string `json:"redirect_uris"`
		}
		body, err := httpx.ReadBody(w, r)
		if err == nil {
			err = json.Unmarshal(body, &req) // unknown RFC 7591 fields are allowed and ignored
		}
		if err != nil {
			writeOAuthErr(w, oerr(400, "invalid_client_metadata", "invalid JSON"))
			return
		}
		c, err := s.RegisterClient(r.Context(), req.ClientName, req.RedirectURIs)
		if err != nil {
			writeOAuthErr(w, err)
			return
		}
		httpx.WriteJSON(w, http.StatusCreated, map[string]any{
			"client_id": c.ClientID, "client_name": c.Name, "redirect_uris": c.RedirectURIs,
			"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"},
			"response_types": []string{"code"}, "client_id_issued_at": c.CreatedAt.Unix(),
		})
	})
	mux.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, r *http.Request) { s.authorizeGet(w, r, profiles) })
	mux.HandleFunc("POST /oauth/authorize", func(w http.ResponseWriter, r *http.Request) { s.authorizePost(w, r) })
	mux.HandleFunc("POST /oauth/token", s.tokenEndpoint)
	return mux
}

func writeOAuthErr(w http.ResponseWriter, err error) {
	var oe *OAuthError
	if !errors.As(err, &oe) {
		status, _ := httpx.StatusFor(err)
		oe = oerr(status, "server_error", "request failed")
		if status == 400 {
			oe = oerr(400, "invalid_request", err.Error())
		}
	}
	httpx.WriteJSON(w, oe.Status, oe)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state string, e *OAuthError) {
	q := url.Values{"error": {e.Code}, "error_description": {e.Description}}
	if state != "" {
		q.Set("state", state)
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	http.Redirect(w, r, redirectURI+sep+q.Encode(), http.StatusFound)
}

func (s *Service) authorizeGet(w http.ResponseWriter, r *http.Request, profiles ProfileLister) {
	ar, err, canRedirect := s.ValidateAuthorize(r.Context(), r.URL.Query())
	if err != nil {
		var oe *OAuthError
		errors.As(err, &oe)
		if canRedirect {
			redirectWithError(w, r, ar.RedirectURI, ar.State, oe)
			return
		}
		renderMessage(w, http.StatusBadRequest, "This sign-in link is not valid", oe.Description)
		return
	}
	p, err := s.AuthenticateAdmin(r.Context(), SessionID(r), "")
	if err != nil {
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/admin/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	names := []string{}
	if profiles != nil {
		if names, err = profiles(r.Context()); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	ru, _ := url.Parse(ar.RedirectURI)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' "+ru.Scheme+"://"+ru.Host+"; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	_ = consentTmpl.Execute(w, map[string]any{
		"Client": ar.Client.Name, "RedirectHost": ru.Host, "User": p.Name, "Profiles": names, "CSRF": p.CSRF,
		"Query": r.URL.RawQuery,
	})
}

func (s *Service) authorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderMessage(w, 400, "Bad request", "The form could not be read.")
		return
	}
	q, err := url.ParseQuery(r.PostForm.Get("query"))
	if err != nil {
		renderMessage(w, 400, "Bad request", "The sign-in request is malformed.")
		return
	}
	ar, verr, canRedirect := s.ValidateAuthorize(r.Context(), q)
	if verr != nil {
		var oe *OAuthError
		errors.As(verr, &oe)
		if canRedirect {
			redirectWithError(w, r, ar.RedirectURI, ar.State, oe)
			return
		}
		renderMessage(w, 400, "This sign-in link is not valid", oe.Description)
		return
	}
	p, err := s.AuthenticateAdmin(r.Context(), SessionID(r), "")
	if err != nil {
		renderMessage(w, 401, "Your session expired", "Sign in to the dashboard and try connecting again.")
		return
	}
	if r.PostForm.Get("csrf") == "" || r.PostForm.Get("csrf") != p.CSRF {
		renderMessage(w, 403, "Request blocked", "The form expired. Go back and try again.")
		return
	}
	if r.PostForm.Get("decision") != "approve" {
		redirectWithError(w, r, ar.RedirectURI, ar.State, oerr(400, "access_denied", "the user denied the request"))
		return
	}
	loc, err := s.IssueCode(r.Context(), ar, p.UserID, r.PostForm.Get("profile"))
	if err != nil {
		renderMessage(w, 400, "Pick a profile", "Choose which profile this AI tool should use, then try again.")
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func (s *Service) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthErr(w, oerr(400, "invalid_request", "invalid form body"))
		return
	}
	f := r.PostForm
	var resp TokenResponse
	var err error
	switch f.Get("grant_type") {
	case "authorization_code":
		resp, err = s.ExchangeCode(r.Context(), f.Get("code"), f.Get("code_verifier"), f.Get("client_id"), f.Get("redirect_uri"), f.Get("resource"))
	case "refresh_token":
		resp, err = s.Refresh(r.Context(), f.Get("refresh_token"), f.Get("client_id"))
	default:
		err = oerr(400, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
	if err != nil {
		writeOAuthErr(w, err)
		return
	}
	w.Header().Set("Pragma", "no-cache")
	httpx.WriteJSON(w, 200, resp)
}

// AdminAuthHandler serves /admin/api/v1/auth/*: passkey setup, invites, login, logout, me.
func (s *Service) AdminAuthHandler() http.Handler {
	mux := http.NewServeMux()
	const p = "/admin/api/v1/auth"
	type beginReq struct {
		Token string `json:"token"`
		Name  string `json:"name"`
	}
	type finishReq struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
	}
	mux.HandleFunc("GET "+p+"/status", func(w http.ResponseWriter, r *http.Request) {
		n, err := s.CountUsers(r.Context())
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{"setup_required": n == 0})
	})
	beginReg := func(purpose string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var req beginReq
			if err := httpx.DecodeJSON(w, r, &req); err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			userID := ""
			if purpose == RegisterAdd {
				pr, err := s.requireSession(r)
				if err != nil {
					httpx.WriteError(w, r, err)
					return
				}
				userID = pr.UserID
			}
			id, opts, err := s.BeginRegistration(r.Context(), purpose, req.Token, req.Name, userID)
			if err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			httpx.WriteJSON(w, 200, map[string]any{"ceremony": id, "options": opts})
		}
	}
	finishReg := func(w http.ResponseWriter, r *http.Request) {
		var req finishReq
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		u, sid, err := s.FinishRegistration(r.Context(), req.Ceremony, req.Credential)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		if sid != "" {
			s.setSession(w, sid)
		}
		httpx.WriteJSON(w, 200, map[string]any{"user": u})
	}
	mux.HandleFunc("POST "+p+"/setup/begin", beginReg(RegisterSetup))
	mux.HandleFunc("POST "+p+"/invite/begin", beginReg(RegisterInvite))
	mux.HandleFunc("POST "+p+"/passkeys/begin", beginReg(RegisterAdd))
	mux.HandleFunc("POST "+p+"/register/finish", finishReg)
	mux.HandleFunc("POST "+p+"/login/begin", func(w http.ResponseWriter, r *http.Request) {
		id, opts, err := s.BeginLogin(r.Context())
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, 200, map[string]any{"ceremony": id, "options": opts})
	})
	mux.HandleFunc("POST "+p+"/login/finish", func(w http.ResponseWriter, r *http.Request) {
		var req finishReq
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		u, sid, err := s.FinishLogin(r.Context(), req.Ceremony, req.Credential)
		if err != nil {
			time.Sleep(200 * time.Millisecond) // slow down guessing
			httpx.WriteError(w, r, err)
			return
		}
		s.setSession(w, sid)
		httpx.WriteJSON(w, 200, map[string]any{"user": u})
	})
	mux.HandleFunc("POST "+p+"/logout", func(w http.ResponseWriter, r *http.Request) {
		if sid := SessionID(r); sid != "" {
			_ = s.Logout(r.Context(), sid)
		}
		s.clearSession(w)
		httpx.WriteJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET "+p+"/me", func(w http.ResponseWriter, r *http.Request) {
		pr, err := s.AuthenticateAdmin(r.Context(), SessionID(r), httpx.Bearer(r))
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, 200, pr)
	})
	return mux
}

func (s *Service) requireSession(r *http.Request) (Principal, error) {
	p, err := s.AuthenticateAdmin(r.Context(), SessionID(r), "")
	if err != nil {
		return p, err
	}
	if r.Header.Get("X-CSRF-Token") != p.CSRF {
		return p, errors.Join(ports.ErrForbidden, errors.New("missing or invalid CSRF token"))
	}
	return p, nil
}

// RoleAllows reports whether a principal's role meets min (AUTH-034).
func RoleAllows(p Principal, min domain.Role) bool { return p.Role.AtLeast(min) }

var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect {{.Client}} · mcp-gateway</title>
<style>
:root{--bg:#f6f5f2;--card:#fff;--text:#1f1e1c;--muted:#6b6963;--border:#e2e0da;--accent:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#1b1b1a;--card:#262624;--text:#ecebe7;--muted:#a3a19a;--border:#3a3936;--accent:#7aa0ff}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:28px;max-width:440px;width:100%}
h1{font-size:20px;font-weight:600;margin:0 0 6px}p{color:var(--muted);margin:0 0 18px}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}select{width:100%;padding:9px 10px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit;margin-bottom:20px}
.row{display:flex;gap:10px}button{flex:1;padding:10px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.host{font-family:ui-monospace,monospace;font-size:13px}
</style></head><body><main class="card">
<h1>Connect {{.Client}}?</h1>
<p>Signed in as <strong>{{.User}}</strong>. {{.Client}} will be able to use your MCP servers through this gateway, limited by the profile you choose. You'll be sent back to <span class="host">{{.RedirectHost}}</span>.</p>
<form method="post" action="/oauth/authorize">
<input type="hidden" name="query" value="{{.Query}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="profile">Profile</label>
<select id="profile" name="profile" required>{{range .Profiles}}<option value="{{.}}">{{.}}</option>{{else}}<option value="">No profiles yet: create one in the dashboard</option>{{end}}</select>
<div class="row"><button type="submit" name="decision" value="deny">Deny</button><button class="primary" type="submit" name="decision" value="approve">Allow</button></div>
</form></main></body></html>`))

var messageTmpl = template.Must(template.New("msg").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{.Title}}</title>
<style>body{font:15px/1.55 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px;background:#f6f5f2;color:#1f1e1c}@media (prefers-color-scheme:dark){body{background:#1b1b1a;color:#ecebe7}}main{max-width:440px}</style>
</head><body><main><h1 style="font-size:20px;font-weight:600">{{.Title}}</h1><p>{{.Body}}</p></main></body></html>`))

func renderMessage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(status)
	_ = messageTmpl.Execute(w, map[string]string{"Title": title, "Body": body})
}
