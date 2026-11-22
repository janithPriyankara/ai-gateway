// Command gw is the mcp-gateway binary.
//
//	gw serve     run the gateway (all services, or a subset with --services)
//	gw doctor    check the configuration and environment
//	gw keygen    generate an admin API key, master key or internal token
//	gw trust     trust the gateway's local HTTPS certificate authority
//	gw version   print version information
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/app"
	"github.com/mcp-gateway/mcp-gateway/internal/keybox"
	"github.com/mcp-gateway/mcp-gateway/internal/services/auth"
	"github.com/mcp-gateway/mcp-gateway/internal/tlsx"
)

// Set by the build (-ldflags "-X main.version=...").
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "doctor":
		err = doctor(os.Args[2:])
	case "keygen":
		err = keygen(os.Args[2:])
	case "trust":
		err = trust(os.Args[2:])
	case "healthcheck":
		err = healthcheck()
	case "version", "--version", "-v":
		fmt.Printf("mcp-gateway %s (commit %s, built %s, %s/%s)\n", version, commit, date, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mcp-gateway: one login for all your AI tools' MCP servers.

Usage:
  gw serve [flags]      run the gateway
  gw doctor [flags]     check configuration and environment
  gw keygen <kind>      generate a secret: admin | master | internal
  gw trust [--print | --remove]
                        trust the local HTTPS certificate authority (for --tls=local)
  gw version            print version

Run "gw serve -h" for flags. Every flag can also be set with a GW_* environment variable.
`)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultDataDir() string {
	if d := os.Getenv("GW_DATA_DIR"); d != "" {
		return d
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "mcp-gateway")
	}
	return "./data"
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func configFlags(fs *flag.FlagSet) func() app.Config {
	listen := fs.String("listen", env("GW_LISTEN", "127.0.0.1:8787"), "address to listen on (GW_LISTEN)")
	public := fs.String("public-url", env("GW_PUBLIC_URL", ""), "URL clients use to reach the gateway; required when not on loopback (GW_PUBLIC_URL)")
	data := fs.String("data-dir", defaultDataDir(), "data directory (GW_DATA_DIR)")
	tlsMode := fs.String("tls", env("GW_TLS", ""), "serve HTTPS: off, local (own localhost certificate authority) or files (GW_TLS)")
	tlsCert := fs.String("tls-cert", env("GW_TLS_CERT", ""), "certificate file for --tls=files (GW_TLS_CERT)")
	tlsKey := fs.String("tls-key", env("GW_TLS_KEY", ""), "private key file for --tls=files (GW_TLS_KEY)")
	services := fs.String("services", env("GW_SERVICES", "all"), "services to run: all, or a comma list of gateway,auth,vault,control (GW_SERVICES)")
	kp := fs.String("key-provider", env("GW_KEY_PROVIDER", "auto"), "master key provider: auto, macos-keychain, file, env, passphrase (GW_KEY_PROVIDER)")
	origins := fs.String("trusted-origins", env("GW_TRUSTED_ORIGINS", ""), "comma-separated browser origins allowed to call /mcp (GW_TRUSTED_ORIGINS)")
	webhook := fs.String("webhook-url", env("GW_WEBHOOK_URL", ""), "POST approval requests to this URL, e.g. ntfy or Slack (GW_WEBHOOK_URL)")
	strict := fs.Bool("strict-pinning", env("GW_STRICT_PINNING", "") == "true", "quarantine newly seen tools until approved (GW_STRICT_PINNING)")
	retention := fs.Duration("audit-retention", 90*24*time.Hour, "delete audit events older than this")
	logLevel := fs.String("log-level", env("GW_LOG_LEVEL", "info"), "debug, info, warn or error (GW_LOG_LEVEL)")
	logJSON := fs.Bool("log-json", env("GW_LOG_FORMAT", "") == "json", "log as JSON (GW_LOG_FORMAT=json)")
	return func() app.Config {
		var lvl slog.Level
		_ = lvl.UnmarshalText([]byte(*logLevel))
		var h slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
		if *logJSON {
			h = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
		}
		logger := slog.New(h)
		slog.SetDefault(logger)
		svcs := app.AllServices
		if *services != "all" && *services != "" {
			svcs = splitList(*services)
		}
		return app.Config{
			Listen: *listen, PublicURL: *public, TLS: *tlsMode, TLSCert: *tlsCert, TLSKey: *tlsKey, DataDir: *data, Services: svcs, KeyProvider: *kp,
			KeyConfig:     keybox.Config{Passphrase: os.Getenv("GW_PASSPHRASE"), KeyFile: os.Getenv("GW_MASTER_KEY_FILE")},
			InternalToken: os.Getenv("GW_INTERNAL_TOKEN"),
			AuthURL:       os.Getenv("GW_AUTH_URL"), VaultURL: os.Getenv("GW_VAULT_URL"), ControlURL: os.Getenv("GW_CONTROL_URL"), GatewayURL: os.Getenv("GW_GATEWAY_URL"),
			BootstrapAdminKey: os.Getenv("GW_BOOTSTRAP_ADMIN_KEY"), TrustedOrigins: splitList(*origins), WebhookURL: *webhook,
			StrictPinning: *strict, AuditRetention: *retention, Version: version, Logger: logger,
		}
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgFn := configFlags(fs)
	_ = fs.Parse(args)
	cfg := cfgFn()
	if err := cfg.Validate(); err != nil { // fills defaults such as the public URL
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer a.Close()
	srv := &http.Server{
		Addr: cfg.Listen, Handler: a.Handler,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
		// No WriteTimeout: approvals and SSE streams are long-lived by design.
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	if cfg.TLS != tlsx.ModeOff {
		tc, err := tlsx.ServerConfig(tlsx.Options{Mode: cfg.TLS, DataDir: cfg.DataDir, CertFile: cfg.TLSCert, KeyFile: cfg.TLSKey})
		if err != nil {
			ln.Close()
			return err
		}
		srv.TLSConfig = tc
		ln = tls.NewListener(ln, tc)
		if cfg.TLS == tlsx.ModeLocal {
			slog.Info("serving HTTPS with the gateway's local certificate authority; run `gw trust` once so browsers and AI tools accept it",
				"ca", tlsx.CAPath(cfg.DataDir))
		}
	}
	slog.Info("mcp-gateway listening", "addr", ln.Addr().String(), "public_url", cfg.PublicURL,
		"services", strings.Join(cfg.Services, ","), "version", version)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	slog.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// doctor checks the environment and prints actionable findings (DEP-009).
func doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgFn := configFlags(fs)
	_ = fs.Parse(args)
	cfg := cfgFn()
	problems := 0
	report := func(okay bool, what, fix string) {
		mark := "ok  "
		if !okay {
			mark = "FAIL"
			problems++
		}
		fmt.Printf("[%s] %s\n", mark, what)
		if !okay && fix != "" {
			fmt.Printf("       → %s\n", fix)
		}
	}
	warn := func(what, fix string) { fmt.Printf("[warn] %s\n       → %s\n", what, fix) }

	err := cfg.Validate()
	report(err == nil, "configuration is valid", fmt.Sprint(err))
	if st, err := os.Stat(cfg.DataDir); err == nil {
		report(st.Mode().Perm()&0o077 == 0 || runtime.GOOS == "windows", "data directory "+cfg.DataDir+" is private", "run: chmod 700 "+cfg.DataDir)
	} else {
		fmt.Printf("[info] data directory %s will be created on first start\n", cfg.DataDir)
	}
	ctx := context.Background()
	kc := cfg.KeyConfig
	kc.DataDir = cfg.DataDir
	if p, err := keybox.Open(ctx, cfg.KeyProvider, kc); err != nil {
		report(false, "master key provider", err.Error())
	} else {
		herr := p.Health(ctx)
		report(herr == nil, fmt.Sprintf("master key provider %q (strength %s)", p.Name(), p.Strength()), fmt.Sprint(herr))
		if p.Strength() != keybox.StrengthStrong && cfg.PublicURL != "" && !strings.Contains(cfg.PublicURL, "127.0.0.1") && !strings.Contains(cfg.PublicURL, "localhost") {
			warn("an exposed gateway uses a "+string(p.Strength())+"-strength key provider", "use macos-keychain, a TPM-sealed key file, or a cloud KMS provider")
		}
	}
	if ln, err := net.Listen("tcp", cfg.Listen); err != nil {
		report(false, "listen address "+cfg.Listen+" is free", err.Error())
	} else {
		ln.Close()
		report(true, "listen address "+cfg.Listen+" is free", "")
	}
	if strings.HasPrefix(cfg.PublicURL, "http://") && !strings.Contains(cfg.PublicURL, "127.0.0.1") && !strings.Contains(cfg.PublicURL, "localhost") {
		warn("public URL uses plain http", "use --tls=files, or put the gateway behind TLS (Caddy, Cloudflare Tunnel or Tailscale)")
	}
	if strings.HasPrefix(cfg.PublicURL, "http://") && (strings.Contains(cfg.PublicURL, "127.0.0.1") || strings.Contains(cfg.PublicURL, "localhost")) {
		fmt.Println("[info] serving plain http: some AI apps (such as the Claude app) only sign in over https → use --tls=local and run gw trust")
	}
	if err == nil && cfg.TLS != tlsx.ModeOff {
		_, terr := tlsx.ServerConfig(tlsx.Options{Mode: cfg.TLS, DataDir: cfg.DataDir, CertFile: cfg.TLSCert, KeyFile: cfg.TLSKey})
		report(terr == nil, "HTTPS certificate ("+cfg.TLS+")", fmt.Sprint(terr))
	}
	if problems > 0 {
		return fmt.Errorf("%d problem(s) found", problems)
	}
	fmt.Println("\nAll checks passed.")
	return nil
}

// healthcheck is for container HEALTHCHECK: the final image has no shell or curl.
func healthcheck() error {
	addr := env("GW_LISTEN", "127.0.0.1:8787")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme, tr := "http", http.DefaultTransport
	if m := env("GW_TLS", ""); (m != "" && m != tlsx.ModeOff) || env("GW_TLS_CERT", "") != "" {
		// Liveness probe of our own process over loopback: only the status matters, and
		// the certificate is for the public name, so it is not verified here (DEP-014).
		scheme = "https"
		tr = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	c := &http.Client{Timeout: 3 * time.Second, Transport: tr}
	resp, err := c.Get(scheme + "://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}
func keygen(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gw keygen admin | master | internal")
	}
	switch args[0] {
	case "admin":
		fmt.Println(auth.NewAdminKeyString())
	case "master":
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		fmt.Println(base64.StdEncoding.EncodeToString(k))
	case "internal":
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		fmt.Println(base64.RawURLEncoding.EncodeToString(k))
	default:
		return fmt.Errorf("unknown kind %q (use admin, master or internal)", args[0])
	}
	return nil
}

// trust adds the local HTTPS certificate authority to the user's trust store (DEP-015).
func trust(args []string) error {
	fs := flag.NewFlagSet("trust", flag.ExitOnError)
	data := fs.String("data-dir", defaultDataDir(), "data directory (GW_DATA_DIR)")
	printOnly := fs.Bool("print", false, "only print the CA certificate path")
	remove := fs.Bool("remove", false, "remove the CA from the macOS login keychain")
	_ = fs.Parse(args)
	ca, err := tlsx.LoadOrCreateCA(*data, time.Now())
	if err != nil {
		return err
	}
	path, _ := filepath.Abs(ca.CertPath)
	if *printOnly {
		fmt.Println(path)
		return nil
	}
	run := func(name string, args ...string) error {
		c := exec.Command(name, args...)
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		return c.Run()
	}
	home, _ := os.UserHomeDir()
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	if *remove {
		if runtime.GOOS != "darwin" {
			return errors.New("--remove is only automated on macOS; remove the certificate with your system's tools")
		}
		_ = run("security", "remove-trusted-cert", path)
		return run("security", "delete-certificate", "-c", ca.Cert.Subject.CommonName, keychain)
	}
	fmt.Printf("Local certificate authority: %s\n", path)
	fmt.Printf("It can only vouch for localhost, 127.0.0.1 and ::1.\n\n")
	switch runtime.GOOS {
	case "darwin":
		fmt.Println("Adding it to your login keychain. macOS will ask for your password or Touch ID.")
		if err := run("security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, path); err != nil {
			return fmt.Errorf("adding the certificate to the keychain: %w", err)
		}
		fmt.Println("Done: Safari, Chrome and the Claude apps now trust https://localhost from this gateway.")
	case "linux":
		fmt.Printf("Run:\n  sudo cp %q /usr/local/share/ca-certificates/mcp-gateway.crt && sudo update-ca-certificates\n", path)
		fmt.Println("Firefox keeps its own list: Settings → Certificates → Import.")
	case "windows":
		fmt.Printf("Run:\n  certutil -user -addstore Root %q\n", path)
	default:
		fmt.Println("Add this file to your system's trusted root certificates.")
	}
	fmt.Printf("\nTools that use their own certificate list (older Node.js tools) need:\n  NODE_EXTRA_CA_CERTS=%s\n", path)
	return nil
}
