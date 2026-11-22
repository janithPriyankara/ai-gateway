# CTL: Control plane

## Configuration

- **CTL-001** Servers have: `id`, `name`, `prefix` (unique, `[a-z0-9_]{1,32}`), `transport` (`http` | `stdio`), `url` or `command` + `args`, `auth` kind, `enabled`, `timeout_seconds`.
- **CTL-002** Profiles have: `name` (unique), `servers` (list of server ids), `rules` (POL), optional `rate_limit`.
- **CTL-003** Every config change increments a monotonic **config version**. `GET /internal/v1/snapshot` returns `{version, servers, profiles, pins}`; with `?since=N` it long-polls up to 25 s until the version is greater than N.
- **CTL-004** Config can be exported as YAML (no secrets) and imported; importing is atomic (all or nothing) and validated (POL-007, CTL-001).
- **CTL-005** A server catalog (`catalog/*.yaml`, embedded) provides presets: name, prefix, transport, URL or command, auth kind, and default safe rules.

## Tool pinning

- **CTL-010** A tool's fingerprint is `sha256(name + "\n" + description + "\n" + canonical-JSON(inputSchema) + "\n" + canonical-JSON(annotations))`.
- **CTL-011** The first time a tool is seen, its fingerprint is pinned as `approved` (trust on first use; configurable to `quarantined` for strict mode).
- **CTL-012** If a tool's fingerprint changes, the tool becomes `quarantined` and the change (old and new description and schema) is recorded for review.
- **CTL-013** An admin can accept a change (the new fingerprint becomes approved) or reject it (the tool stays quarantined, the change leaves the review list, and that exact definition is not offered again; a different new definition is). If the upstream reverts to the trusted definition, the tool is released automatically.

## Approvals

- **CTL-020** An `ask` decision creates a pending approval with: client, user, tool, redacted argument summary, created time and expiry (default 120 s).
- **CTL-021** Approvers (the user themselves, or admin+) can approve or deny. The waiting gateway call is released immediately.
- **CTL-022** Approvals that reach their expiry are automatically denied with reason `approval timed out`.
- **CTL-023** Approve may include "always allow this tool for this profile", which appends an `allow` rule above the matching `ask` rule.
- **CTL-024** New approvals are pushed to notifiers (log notifier always; webhook notifier for ntfy, Slack and similar).

## Audit

- **CTL-030** Audit events record: time, request id, user, client, profile, server, tool, decision, status (`ok`, `error`, `denied`, `timeout`), latency ms, redacted argument summary.
- **CTL-031** Events are append-only and hash-chained: each event stores `sha256(previous hash + canonical event)`. `VerifyChain` detects any edited or deleted event.
- **CTL-032** Audit queries filter by time range, user, client, server, tool and decision, with cursor pagination, newest first.
- **CTL-033** Admin actions (config changes, approvals, revocations, key rotations, logins) are audited in the same log with `kind=admin`.
- **CTL-034** Events older than the retention period (default 90 days) are deleted by a daily job; the chain stays verifiable from the oldest remaining event.

## Admin API

- **CTL-040** The Admin API lives at `/admin/api/v1`, is described by `api/openapi.yaml`, and returns JSON errors of the form `{"error": {"code": "...", "message": "..."}}`.
- **CTL-041** Routes: overview, servers (CRUD, test connection, list tools, connect/disconnect credential), clients (list, create static token, revoke), profiles (CRUD), approvals (list, decide), pins (list changes, accept, reject), audit (query, verify chain, export), users (list, invite, change role, delete), security (key provider status, rotate signing key), config (export, import), events (SSE).
- **CTL-042** `GET /admin/api/v1/events` streams Server-Sent Events: `approval.created`, `approval.decided`, `audit.event`, `server.health`, `config.changed`.
- **CTL-043** Secrets are write-only through the Admin API: credentials can be set or deleted, never read back.
- **CTL-044** Server health is checked every 60 s (MCP `initialize` + `tools/list`) and exposed as `ok`, `degraded`, `down` or `needs_reauth`.
