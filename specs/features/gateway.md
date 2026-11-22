# GW: Gateway (MCP data plane)

## Acceptance criteria

- **GW-001** The gateway serves MCP over Streamable HTTP at `POST /mcp`. Clients complete `initialize` and receive server info `mcp-gateway`.
- **GW-002** Requests without a valid credential get `401` (AUTH-020). Credentials are a static token (AUTH-002) or an access token (AUTH-011).
- **GW-003** `tools/list` returns the union of the tools of all enabled servers in the caller's profile, named `<server prefix>__<tool name>`, with the upstream description, input schema and annotations preserved.
- **GW-004** `tools/list` omits tools hidden by policy (POL-010) and quarantined tools (CTL-012).
- **GW-005** `tools/call` on a namespaced tool is forwarded to the right upstream with the original tool name and arguments, and the upstream result is returned unchanged except for redaction (GW-010).
- **GW-006** Before forwarding, the call is checked by policy. `deny` returns a tool error result (`isError: true`) with the reason and is not forwarded. `ask` blocks until an approval decision (CTL-020), then proceeds or returns a denial.
- **GW-007** The upstream request carries the *upstream* credential from the vault (VLT-003) and never the client's token or any client headers.
- **GW-008** If the vault returns `ErrNeedsReauth` or `ErrNoCredential`, the call returns a tool error telling the user to reconnect that server in the dashboard; nothing is forwarded.
- **GW-009** If an upstream returns HTTP 401, the gateway asks the vault to refresh once and retries once; a second 401 marks the credential `needs_reauth`.
- **GW-010** Results are scrubbed of secret-looking strings (credential values the gateway injected, `ghp_…`, `github_pat_…`, `xox?-…`, `sk-…`, JWTs, `Bearer …`) before being returned.
- **GW-011** Every call produces exactly one audit event (CTL-030) with the decision, status, latency and redacted argument summary. Audit emission never blocks the response path.
- **GW-012** Upstream calls time out (default 60 s, configurable per server). Tools marked read-only are retried once on transport errors; write tools are never retried.
- **GW-013** A circuit breaker per upstream opens after 5 consecutive failures for 30 s; while open, calls fail fast with a clear error and other upstreams are unaffected.
- **GW-014** Upstream transports: Streamable HTTP and stdio. Stdio servers run as child processes with a minimal environment (only the variables from their credential and an allow-list such as `PATH`, `HOME`).
- **GW-015** The gateway is stateless apart from caches: config comes from the control plane as a versioned snapshot, refreshed on change notifications and at least every 30 s.
- **GW-016** Gateway overhead (excluding upstream time) is under 2 ms p50 for `tools/call` against an in-memory upstream (benchmark).
- **GW-017** The DNS-rebinding and Origin protections are on: requests with a disallowed `Origin` are rejected.
- **GW-018** The tool's current fingerprint is compared with its pinned fingerprint (CTL-011) on every `tools/list` refresh; drift quarantines the tool.
