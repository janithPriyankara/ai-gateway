// Package app wires services together, either all in one process or as a subset
// that reaches the others over internal HTTP (DEP-001).
package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/adminapi"
	"github.com/mcp-gateway/mcp-gateway/internal/domain"
	"github.com/mcp-gateway/mcp-gateway/internal/httpx"
	"github.com/mcp-gateway/mcp-gateway/internal/keybox"
	"github.com/mcp-gateway/mcp-gateway/internal/ports"
	"github.com/mcp-gateway/mcp-gateway/internal/rpc"
	"github.com/mcp-gateway/mcp-gateway/internal/services/auth"
	"github.com/mcp-gateway/mcp-gateway/internal/services/control"
	"github.com/mcp-gateway/mcp-gateway/internal/services/gateway"
	"github.com/mcp-gateway/mcp-gateway/internal/services/vault"
	"github.com/mcp-gateway/mcp-gateway/internal/tlsx"
	"github.com/mcp-gateway/mcp-gateway/web"
)

// Service names.
const (
	SvcGateway = "gateway"
	SvcAuth    = "auth"
	SvcVault   = "vault"
	SvcControl = "control"
)

// AllServices is the default single-binary set.
var AllServices = []string{SvcGateway, SvcAuth, SvcVault, SvcControl}

// Config is the runtime configuration (flags and GW_* environment variables).
type Config struct {
	Listen            string
	PublicURL         string
	TLS               string // off | local | files (DEP-010, DEP-013)
	TLSCert, TLSKey   string
	DataDir           string
	Services          []string
	KeyProvider       string
	KeyConfig         keybox.Config
	InternalToken     string
	AuthURL           string
	VaultURL          string
	ControlURL        string
	GatewayURL        string
	BootstrapAdminKey string
	TrustedOrigins    []string
	WebhookURL        string
	StrictPinning     bool
	AuditRetention    time.Duration
	HealthInterval    time.Duration
	Version           string
	Logger            *slog.Logger
}

func (c *Config) has(s string) bool { return slices.Contains(c.Services, s) }

// Validate checks the configuration (DEP-002, DEP-004).
func (c *Config) Validate() error {
	if len(c.Services) == 0 {
		c.Services = AllServices
	}
	for _, s := range c.Services {
		if !slices.Contains(AllServices, s) {
			return fmt.Errorf("unknown service %q (use gateway, auth, vault, control)", s)
		}
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.Listen, err)
	}
	if c.TLS == "" {
		c.TLS = tlsx.ModeOff
		if c.TLSCert != "" || c.TLSKey != "" {
			c.TLS = tlsx.ModeFiles
		}
	}
	switch c.TLS {
	case tlsx.ModeOff, tlsx.ModeLocal:
	case tlsx.ModeFiles:
		if c.TLSCert == "" || c.TLSKey == "" {
			return errors.New("--tls=files needs both --tls-cert and --tls-key")
		}
	default:
		return fmt.Errorf("unknown TLS mode %q (use off, local or files)", c.TLS)
	}
	scheme := "http"
	if c.TLS != tlsx.ModeOff {
		scheme = "https"
	}
	loopback := host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
	if c.PublicURL == "" {
		if !loopback {
			return errors.New("listening on a non-loopback address requires --public-url (the URL clients use to reach the gateway)")
		}
		// Browsers refuse IP addresses as passkey domains, so default to "localhost".
		_, port, _ := net.SplitHostPort(c.Listen)
		c.PublicURL = scheme + "://localhost:" + port
	}
	pu, err := url.Parse(c.PublicURL)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		return fmt.Errorf("invalid public URL %q", c.PublicURL)
	}
	if c.TLS != tlsx.ModeOff && pu.Scheme != "https" {
		return fmt.Errorf("with --tls=%s the public URL must start with https:// (got %q)", c.TLS, c.PublicURL)
	}
	if c.TLS == tlsx.ModeLocal && !tlsx.IsLocalHost(pu.Hostname()) {
		return fmt.Errorf("--tls=local only covers localhost; for %s use --tls=files with a real certificate, or a reverse proxy", pu.Hostname())
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	split := len(c.Services) < len(AllServices)
	if split && len(c.InternalToken) < 32 {
		return errors.New("microservices mode needs GW_INTERNAL_TOKEN of at least 32 characters")
	}
	need := map[string]*string{}
	if c.has(SvcGateway) || c.has(SvcControl) {
		need[SvcAuth], need[SvcVault] = &c.AuthURL, &c.VaultURL
	}
	if c.has(SvcGateway) || c.has(SvcAuth) {
		need[SvcControl] = &c.ControlURL
	}
	if c.has(SvcControl) {
		need[SvcGateway] = &c.GatewayURL
	}
	for svc, u := range need {
		if !c.has(svc) && *u == "" {
			return fmt.Errorf("service %s is not local: set GW_%s_URL", svc, strings.ToUpper(svc))
		}
	}
	if c.AuditRetention == 0 {
		c.AuditRetention = 90 * 24 * time.Hour
	}
	if c.HealthInterval == 0 {
		c.HealthInterval = 60 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

// App is a running set of services.
type App struct {
	cfg     Config
	log     *slog.Logger
	Handler http.Handler

	Auth    *auth.Service
	Vault   *vault.Service
	Control *control.Service
	Gateway *gateway.Gateway
	box     *keybox.Box

	ready   []func(context.Context) error
	closers []func()
	cancel  context.CancelFunc
}

// vaultAdmin adds KeyProvider reporting to the vault service.
type vaultAdmin struct {
	*vault.Service
}

func (v vaultAdmin) KeyProvider() adminapi.KeyProviderInfo {
	p := v.Box().Provider()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return adminapi.KeyProviderInfo{Name: p.Name(), Strength: string(p.Strength()), Healthy: p.Health(ctx) == nil}
}

// New builds the services selected in cfg.
func New(ctx context.Context, cfg Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, log: cfg.Logger}
	ok := false
	defer func() {
		if !ok {
			a.Close()
		}
	}()
	db := func(name string) string { return filepath.Join(cfg.DataDir, name) }

	if cfg.has(SvcAuth) || cfg.has(SvcVault) {
		kc := cfg.KeyConfig
		kc.DataDir = cfg.DataDir
		p, err := keybox.Open(ctx, cfg.KeyProvider, kc)
		if err != nil {
			return nil, err
		}
		if err := p.Health(ctx); err != nil {
			return nil, err
		}
		a.box = keybox.New(p)
		a.log.Info("key provider ready", "provider", p.Name(), "strength", p.Strength())
		if p.Strength() != keybox.StrengthStrong && !strings.HasPrefix(cfg.PublicURL, "http://127.0.0.1") && !strings.HasPrefix(cfg.PublicURL, "http://localhost") {
			a.log.Warn("the master key provider is not hardware- or KMS-backed; prefer a keychain, TPM or KMS provider for exposed deployments", "provider", p.Name())
		}
	}

	var internal *rpc.Server
	if cfg.InternalToken != "" {
		internal = rpc.NewServer(cfg.InternalToken)
	}
	client := func(u string) *rpc.Client { return rpc.NewClient(u, cfg.InternalToken) }

	var err error
	// control
	var ctl rpc.ControlPorts
	var profileNames auth.ProfileLister
	if cfg.has(SvcControl) {
		notifiers := []control.Notifier{control.LogNotifier{Logger: a.log}}
		if cfg.WebhookURL != "" {
			notifiers = append(notifiers, control.WebhookNotifier{URL: cfg.WebhookURL, DashboardURL: cfg.PublicURL})
		}
		if a.Control, err = control.New(ctx, control.Options{DBPath: db("control.db"), StrictPinning: cfg.StrictPinning, Notifiers: notifiers}); err != nil {
			return nil, err
		}
		a.closers = append(a.closers, func() { a.Control.Close() })
		a.ready = append(a.ready, a.Control.Ping)
		ctl = a.Control
		profileNames = func(ctx context.Context) ([]string, error) {
			ps, err := a.Control.ListProfiles(ctx)
			names := make([]string, 0, len(ps))
			for _, p := range ps {
				names = append(names, p.Name)
			}
			return names, err
		}
		if internal != nil {
			rpc.RegisterControl(internal, a.Control)
		}
	} else if cfg.has(SvcGateway) || cfg.has(SvcAuth) {
		cc := rpc.ControlClient{C: client(cfg.ControlURL)}
		ctl = cc
		profileNames = cc.ProfileNames
		a.ready = append(a.ready, cc.C.Ping)
	}

	// auth
	var authSvc rpc.AuthService
	if cfg.has(SvcAuth) {
		if a.Auth, err = auth.New(ctx, auth.Options{DBPath: db("auth.db"), Box: a.box, PublicURL: cfg.PublicURL, Logger: a.log, BootstrapAdminKey: cfg.BootstrapAdminKey}); err != nil {
			return nil, err
		}
		a.closers = append(a.closers, func() { a.Auth.Close() })
		a.ready = append(a.ready, a.Auth.Ping)
		authSvc = a.Auth
		if internal != nil {
			rpc.RegisterAuth(internal, a.Auth)
		}
	} else if cfg.has(SvcGateway) || cfg.has(SvcControl) {
		ac := &rpc.AuthClient{C: client(cfg.AuthURL)}
		authSvc = ac
		a.ready = append(a.ready, ac.C.Ping)
	}

	// vault
	var vaultSvc rpc.VaultService
	if cfg.has(SvcVault) {
		if a.Vault, err = vault.New(ctx, vault.Options{DBPath: db("vault.db"), Box: a.box}); err != nil {
			return nil, err
		}
		a.closers = append(a.closers, func() { a.Vault.Close() })
		a.ready = append(a.ready, a.Vault.Ping)
		vaultSvc = vaultAdmin{a.Vault}
		if internal != nil {
			rpc.RegisterVault(internal, vaultAdmin{a.Vault})
		}
	} else if cfg.has(SvcGateway) || cfg.has(SvcControl) {
		vc := rpc.VaultClient{C: client(cfg.VaultURL)}
		vaultSvc = vc
		a.ready = append(a.ready, vc.C.Ping)
	}

	// gateway
	var prober adminapi.Prober
	if cfg.has(SvcGateway) {
		rmURL := cfg.PublicURL + "/.well-known/oauth-protected-resource"
		if a.Gateway, err = gateway.New(gateway.Options{Auth: authSvc, Config: ctl, Creds: vaultSvc, Audit: ctl, Approvals: ctl, Pins: ctl,
			ResourceMetadataURL: rmURL, TrustedOrigins: cfg.TrustedOrigins, Version: cfg.Version, Logger: a.log}); err != nil {
			return nil, err
		}
		if err := a.Gateway.Start(ctx); err != nil {
			return nil, err
		}
		a.closers = append(a.closers, a.Gateway.Close)
		a.ready = append(a.ready, func(context.Context) error {
			if !a.Gateway.Ready() {
				return errors.New("gateway has no config yet")
			}
			return nil
		})
		prober = a.Gateway
		if internal != nil {
			rpc.RegisterProber(internal, a.Gateway)
		}
	} else if cfg.has(SvcControl) {
		prober = rpc.ProberClient{C: client(cfg.GatewayURL)}
	}

	// HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", a.readyz)
	if a.Gateway != nil {
		h := a.Gateway.Handler()
		mux.Handle("/mcp", h)
		mux.Handle("/mcp/", h)
	}
	if a.Auth != nil {
		oh := a.Auth.OAuthHandler(profileNames)
		mux.Handle("/.well-known/", oh)
		mux.Handle("/oauth/", oh)
		mux.Handle("/admin/api/v1/auth/", a.Auth.AdminAuthHandler())
	} else if a.Gateway != nil {
		// The gateway still advertises where the authorization server lives (AUTH-020).
		mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
			httpx.WriteJSON(w, 200, map[string]any{"resource": cfg.PublicURL + "/mcp", "authorization_servers": []string{cfg.PublicURL}, "bearer_methods_supported": []string{"header"}})
		})
	}
	if a.Control != nil {
		api := adminapi.New(adminapi.Options{Auth: authSvc, Vault: vaultSvc, Control: a.Control, Prober: prober, PublicURL: cfg.PublicURL})
		mux.Handle("/admin/api/v1/", api)
		mux.Handle("GET /admin/oauth/callback", api)
		mux.Handle("/admin/", dashboard())
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin/", http.StatusFound) })
	}
	if internal != nil {
		mux.Handle(rpc.Prefix, internal)
	}
	a.Handler = httpx.SecurityHeaders(mux)

	bg, cancel := context.WithCancel(context.WithoutCancel(ctx))
	a.cancel = cancel
	if a.Control != nil {
		go a.retentionLoop(bg)
		if prober != nil {
			go a.healthLoop(bg, prober)
		}
	}
	if a.Auth != nil {
		if tok, err := a.Auth.EnsureSetupToken(ctx); err == nil && tok != "" {
			a.log.Info("first-run setup: open this link to create the owner account", "url", cfg.PublicURL+"/admin/setup?token="+tok)
		}
	}
	ok = true
	return a, nil
}

func (a *App) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	for _, f := range a.ready {
		if err := f(ctx); err != nil {
			httpx.WriteJSON(w, 503, map[string]string{"status": "not ready", "error": err.Error()})
			return
		}
	}
	httpx.WriteJSON(w, 200, map[string]string{"status": "ready"})
}

func (a *App) retentionLoop(ctx context.Context) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		if n, err := a.Control.PruneAudit(ctx, a.cfg.AuditRetention); err == nil && n > 0 {
			a.Control.AuditAdmin(ctx, fmt.Sprintf("pruned %d audit events older than %s", n, a.cfg.AuditRetention))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// healthLoop probes enabled servers with their shared credential (CTL-044).
func (a *App) healthLoop(ctx context.Context, p adminapi.Prober) {
	t := time.NewTicker(a.cfg.HealthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		servers, err := a.Control.ListServers(ctx)
		if err != nil {
			continue
		}
		for _, s := range servers {
			if !s.Enabled {
				continue
			}
			pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, err := p.Probe(pctx, s.ID, "")
			cancel()
			health := "ok"
			switch {
			case err == nil:
			case errors.Is(err, ports.ErrNoCredential):
				continue // personal credentials only: nothing to probe with
			case errors.Is(err, ports.ErrNeedsReauth):
				health = "needs_reauth"
			default:
				health = "down"
			}
			_ = a.Control.SetServerHealth(ctx, s.ID, health)
		}
	}
}

// Close stops background work and closes services.
func (a *App) Close() {
	if a.cancel != nil {
		a.cancel()
	}
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
}

// dashboard serves the embedded SPA, falling back to index.html for client routes.
func dashboard() http.Handler {
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/admin")
		p = strings.TrimPrefix(p, "/")
		if p != "" {
			if st, err := fs.Stat(dist, p); err == nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					h.Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				r2 := r.Clone(r.Context())
				r2.URL.Path = "/" + p
				files.ServeHTTP(w, r2)
				return
			}
		}
		h.Set("Cache-Control", "no-store")
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		files.ServeHTTP(w, r2)
	})
}

var _ = domain.RoleOwner
