# Architecture

Diagram: [architecture.drawio](architecture.drawio). Open it in [diagrams.net](https://app.diagrams.net), or open [architecture.html](architecture.html) in a browser.

## Services

| Service | Owns | Database | Scales |
|---|---|---|---|
| **gateway** | `/mcp` data plane: authentication, policy, pinning checks, credential injection, upstream sessions, redaction, audit emission | none (stateless) | horizontally (N replicas) |
| **auth** | OAuth 2.1 authorization server, passkeys, sessions, AI-tool clients and tokens, admin API keys, signing keys | `auth.db` | one instance |
| **vault** | sealed upstream credentials, upstream OAuth connect and refresh | `vault.db` | one instance |
| **control** | servers, profiles, tool pins, approvals, audit log, Admin API, dashboard, live events | `control.db` | one instance |

The gateway depends only on the interfaces in `internal/ports`:

```
Authenticator · ConfigSource · CredentialProvider · AuditSink · ApprovalBroker · PinRegistry
```

`internal/app` satisfies them either with the services themselves (single binary) or with the HTTP clients in `internal/rpc` (microservices). The gateway code is identical in both modes.

## Request path (`tools/call`)

```
bearer → Authenticate → rate limit → policy.Decide → pin check → [approval] → vault credential
      → upstream session (pooled per server+user) → redact → result      ↘ audit (async batch)
```

## Decisions

### 1. Go for the server
A high-throughput proxy with many concurrent long-lived streams, distributed as a single static binary for every OS and as a tiny distroless image. Go gives all of that and has the official MCP SDK. Measured overhead is about 0.3 ms p50 per tool call. Policy evaluation takes about 180 ns with zero allocations.

### 2. Modular monolith that deploys as microservices
One codebase and one binary: `gw serve` runs everything, while `gw serve --services=gateway` runs one service. Personal users get a single process with no network hops. Teams get a stateless gateway tier they can scale, plus isolated databases per service. Service boundaries are enforced by interfaces, not by convention.

### 3. Database per service, SQLite in WAL mode
No external database to operate, and each service owns its schema (forward-only migrations in code). The control plane is the single writer of config, and the gateway follows it through versioned snapshots with long-polling, so config changes apply within milliseconds without restarts.

### 4. Envelope encryption with pluggable key providers
Every secret gets its own AES-256-GCM data key, bound to its owner by AAD. Only the small wrapped key depends on the provider (Keychain, file or Docker secret, environment variable, passphrase, and later TPM, cloud KMS or Vault Transit). Master-key rotation re-wraps data keys without touching ciphertexts.

### 5. Embedded OAuth 2.1 authorization server
MCP clients expect discovery (RFC 9728 / 8414), dynamic registration (RFC 7591) and PKCE. An embedded server keeps the deployment to one process and lets AI-tool identities, profiles and revocation live together. Access tokens are short-lived, audience-bound ES256 JWTs. Refresh tokens rotate with family revocation on reuse.

### 6. Trust on first use for tools, with drift quarantine
Tool descriptions are part of the prompt the model sees, which makes them an attack surface. Fingerprints use canonical JSON so key order does not matter. A changed tool disappears from `tools/list` and calls to it are refused until a human accepts the change. Strict mode quarantines new tools too.

### 7. Spec-driven development
`specs/features/*.md` holds numbered acceptance criteria. Every criterion is cited by at least one test, and `scripts/spec-check.sh` enforces it in CI. Test layers: unit → in-process integration (real services, real MCP servers) → black-box (compiled binary over HTTP only) → Playwright (real browser) → Docker (image and microservices stack).

## Extending

| To add… | Do this |
|---|---|
| a key provider | implement `keybox.Provider`, call `keybox.Register` in `init()` |
| a notifier (Slack, Telegram…) | implement `control.Notifier`, wire it in `internal/app` |
| a catalog server | add `internal/services/control/catalog/<name>.yaml` |
| a new service dependency | add a method to a port in `internal/ports`, then implement it in the service and in both sides of `internal/rpc` |
| an Admin API route | add it in `internal/adminapi` and to `api/openapi.yaml` (a test enforces this) |
