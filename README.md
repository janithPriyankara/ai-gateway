# mcp-gateway

**One login for all your AI tools' MCP servers.**

Claude Code, Claude Desktop, claude.ai, Codex, Cursor and others each want their own login to GitHub, Notion, Slack and every other MCP server. mcp-gateway sits in the middle:

- You sign in to each MCP server **once**, at the gateway. It keeps those tokens encrypted and refreshed.
- Each AI tool connects to the gateway **once** (OAuth or a token), and gets every server you allow.
- Every call is checked against your rules (allow, ask a human, or deny), stripped of secrets and written to a tamper-evident audit log.

```
 Claude Code ─┐                ┌──────────── mcp-gateway ────────────┐        ┌─► GitHub
 claude.ai ───┤  one login     │ login → policy → pin check → vault  │ stored ├─► Notion
 Codex ───────┼──────────────► │   → upstream call → redact → audit  │ ───────┼─► Slack
 Cursor ──────┘   each         └──── admin dashboard · Admin API ────┘ creds  └─► local tools
```

See [docs/architecture.drawio](docs/architecture.drawio) for the full architecture diagram (open it in [diagrams.net](https://app.diagrams.net)).

## Features

| | |
|---|---|
| **Single sign-on for AI tools** | Built-in OAuth 2.1 authorization server (PKCE, dynamic client registration, refresh-token rotation with reuse detection) that MCP clients discover automatically, plus static tokens for tools that can't do OAuth. |
| **Passkey dashboard login** | No passwords. First-run setup link, invites, roles (owner, admin, member, viewer). |
| **Encrypted credential vault** | Envelope encryption (AES-256-GCM per secret). The master key lives in the macOS Keychain, a Linux TPM2 (`systemd-creds`), Windows DPAPI, a key file or Docker secret, an environment variable or a passphrase, through a pluggable provider interface ready for cloud KMS. |
| **Upstream OAuth** | Connect OAuth-protected MCP servers once. Tokens refresh automatically, with single-flight refresh and re-auth alerts. |
| **Policy engine** | Per-profile rules on namespaced tools (`github__merge_*`), read-only aware, default deny, rate limits. Evaluates in about 180 ns with zero allocations. |
| **Human approvals** | `ask` rules pause the call until someone approves in the dashboard (live) or through a webhook (ntfy, Slack…). |
| **Tool pinning** | Fingerprints every tool definition. If a server silently changes a tool's description (a "rug pull" or tool poisoning), the tool is quarantined until reviewed. |
| **Audit log** | Every call and admin action, hash-chained so edits and deletions are detectable. Filters and NDJSON export. |
| **Admin dashboard** | Manage servers, AI tools, profiles, approvals, tool changes, activity, users and security from the browser. |
| **Fast and light** | One Go binary, about 0.3 ms p50 overhead per tool call, SQLite (WAL), no external dependencies. |
| **Microservices mode** | The same binary runs as separate `gateway` (stateless, scalable), `auth`, `vault` and `control` services, each with its own database. |

## Quick start

### Binary

```bash
make web build                       # dashboard + bin/gw
./bin/gw serve                       # listens on http://127.0.0.1:8787
```

The first start prints a one-time link (`/admin/setup?token=…`). Open it, register a passkey, and you're the owner. On macOS the master key is created in your login Keychain automatically. Elsewhere, set one of `GW_MASTER_KEY_FILE`, `GW_MASTER_KEY` or `GW_PASSPHRASE` (run `gw doctor` to check).

### Docker (all in one)

```bash
mkdir -p deploy/secrets && ./bin/gw keygen master > deploy/secrets/master.key && chmod 600 deploy/secrets/master.key
docker compose -f deploy/compose.yml up -d --build
docker compose -f deploy/compose.yml logs gateway | grep setup
```

### Docker (microservices)

```bash
cp deploy/split.env.example deploy/split.env   # fill in with: gw keygen internal / master / admin
docker compose -f deploy/compose.split.yml --env-file deploy/split.env up -d --build
```

## Connect your AI tools

In the dashboard, go to **AI tools → Connect a tool**. Pick a profile and copy the snippet it shows. For OAuth-capable clients, just add the URL:

```bash
claude mcp add --transport http gateway http://127.0.0.1:8787/mcp   # then /mcp to sign in once
```

- **claude.ai / Claude Desktop:** Settings → Connectors → Add custom connector → your gateway's public HTTPS URL + `/mcp`. claude.ai connects from the cloud, so expose the gateway with Cloudflare Tunnel, Tailscale Funnel or a reverse proxy, and set `GW_PUBLIC_URL`.
- **Codex:** use the `[mcp_servers.gateway]` snippet from the dashboard (static token via `bearer_token_env_var`).

## Configuration

Every flag has a `GW_*` environment variable. Run `gw serve -h` for the full list.

| Variable | Default | Meaning |
|---|---|---|
| `GW_LISTEN` | `127.0.0.1:8787` | Listen address. Non-loopback addresses require `GW_PUBLIC_URL`. |
| `GW_PUBLIC_URL` | `http://<listen>` | The URL clients use (OAuth issuer, MCP resource). |
| `GW_DATA_DIR` | OS config dir | Where `auth.db`, `vault.db` and `control.db` live. |
| `GW_KEY_PROVIDER` | `auto` | `macos-keychain`, `linux-tpm`, `windows-dpapi`, `file`, `env`, `passphrase`. |
| `GW_SERVICES` | `all` | Comma list of `gateway,auth,vault,control` for microservices mode. |
| `GW_INTERNAL_TOKEN` | | Shared secret for service-to-service calls (microservices mode). |
| `GW_BOOTSTRAP_ADMIN_KEY` | | Creates an owner with this API key when no users exist (CI and automation). |
| `GW_WEBHOOK_URL` | | Receives approval requests as JSON. |
| `GW_STRICT_PINNING` | `false` | Quarantine newly seen tools until approved. |

## Security model

- Upstream secrets never leave the gateway: they are never sent to AI tools, never logged and never shown in the API (write-only).
- Client tokens are never forwarded upstream (no token passthrough). The two trust domains stay separate.
- Tokens are short-lived (1 h), audience-bound ES256 JWTs. Signing keys are stored encrypted and rotate.
- Destructive tools are denied or require approval. Changed tools are quarantined.
- DNS-rebinding and cross-origin protection on `/mcp`. Strict CSP on the dashboard. CSRF tokens on session mutations.
- Stdio servers get a minimal environment: only an allow-list plus their own credential.

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Development

This project is **spec-driven**. Every behaviour is an acceptance criterion in [`specs/features`](specs/features), and every criterion has a test that cites its ID.

```bash
make test-race     # unit + integration tests (race detector)
make blackbox      # drives the compiled binary over HTTP only
make e2e           # Playwright UI automation of the dashboard
make spec-check    # fails if any acceptance criterion has no test
make docker-test   # image hardening + container smoke tests
make test-split    # black-box suite against the microservices compose stack
make bench         # hot-path benchmarks
```

Layout:

```
cmd/gw/                 the binary (serve, doctor, keygen, version, healthcheck)
internal/domain         plain data types
internal/ports          service interfaces (the seams between services)
internal/policy         rule engine
internal/keybox         envelope encryption + key provider plugins
internal/services/      auth · vault · control · gateway
internal/adminapi       Admin REST API (api/openapi.yaml)
internal/rpc            ports over internal HTTP (microservices mode)
internal/app            wiring: one process or a subset of services
web/                    React dashboard (embedded into the binary)
test/blackbox           black-box tests   ·   test/e2e   Playwright tests
specs/                  acceptance criteria   ·   deploy/   Docker and Caddy
```

## License

Apache-2.0. See [LICENSE](LICENSE).
