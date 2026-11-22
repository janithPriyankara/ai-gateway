# POL: Policy engine

A **profile** is a named set of allowed servers plus an ordered list of **rules**.
Every `tools/call` is evaluated against the caller's profile before anything is forwarded.

Rule shape:

```yaml
- tool: "github__merge_*"     # glob on the namespaced tool name (* matches any run of characters)
  when: read_only | write | any   # optional, default any; uses the tool's readOnlyHint annotation
  action: allow | ask | deny
```

## Acceptance criteria

- **POL-001** Rules are evaluated top to bottom; the first matching rule decides.
- **POL-002** If no rule matches, the decision is `deny` (default deny).
- **POL-003** `tool` patterns support `*` globs anywhere in the pattern; matching is case-sensitive and anchored to the whole name.
- **POL-004** `when: read_only` matches only tools whose `readOnlyHint` is true; `when: write` matches only tools whose `readOnlyHint` is false or missing; `any` or omitted matches both.
- **POL-005** A call to a tool on a server that is not in the profile's `servers` list is denied, regardless of rules.
- **POL-006** The decision includes the index of the matching rule (or -1) and a human-readable reason.
- **POL-007** Profiles are validated on load: unknown actions, unknown `when` values, empty patterns and duplicate profile names are rejected with a clear error.
- **POL-008** Rate limits: a profile may set `rate_limit.per_minute`; calls above the limit for a given client are denied with reason `rate limited`. Limits are per client, not global.
- **POL-009** Policy evaluation is allocation-light and takes under 2 µs per call for a 50-rule profile (benchmark).
- **POL-010** A tool hidden by policy (every rule for it is `deny`, or its server is not in the profile) is not returned by `tools/list`.
