# Specifications

This project is **spec-driven**. Every behaviour starts life here as a numbered acceptance
criterion, then gets a failing test, and only then gets code.

```
spec (this folder)  →  failing test that cites the spec ID  →  implementation  →  green
```

## Rules

1. Every acceptance criterion has a stable ID: `<AREA>-<NNN>` (for example `POL-003`).
2. Every test that verifies a criterion cites it in a comment: `// spec: POL-003`.
   Playwright tests cite it in the test title: `test('[UI-004] approve a request', ...)`.
3. `make spec-check` fails the build if any criterion in `specs/features/*.md` has no test.
4. Changing behaviour means changing the spec first, in the same pull request.

## Test layers

| Layer | Where | What it proves | Speed |
|---|---|---|---|
| Unit | `internal/**/*_test.go` | One package in isolation (policy, crypto, store, …) | ms |
| Integration | `internal/**/*_integration_test.go` | Services wired together in-process with real SQLite and real MCP upstreams (SDK servers) | < 1 s |
| Black-box | `test/blackbox` | The compiled `gw` binary (or Docker image) is driven only through its public HTTP surface with a real MCP client | seconds |
| UI automation | `test/e2e` (Playwright) | The dashboard in a real browser against a real `gw` process | seconds |
| Benchmarks | `internal/**/*_bench_test.go` | Hot paths stay fast (policy evaluation, token verification, proxy overhead) | — |

## Feature specs

| File | Area |
|---|---|
| [features/policy.md](features/policy.md) | `POL` policy engine |
| [features/keybox.md](features/keybox.md) | `KEY` envelope encryption and key providers |
| [features/vault.md](features/vault.md) | `VLT` upstream credential storage and refresh |
| [features/auth.md](features/auth.md) | `AUTH` client authentication and OAuth 2.1 server |
| [features/gateway.md](features/gateway.md) | `GW` MCP data plane |
| [features/control.md](features/control.md) | `CTL` control plane: config, pins, approvals, audit, Admin API |
| [features/dashboard.md](features/dashboard.md) | `UI` admin dashboard |
| [features/deploy.md](features/deploy.md) | `DEP` binary, Docker, microservices mode |
