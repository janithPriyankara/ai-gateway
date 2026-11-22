# Dashboard end-to-end tests

Playwright UI tests for the admin dashboard (`web/`), run against a real `bin/gw`
binary. Each test title cites the acceptance criterion it covers (`[UI-001]` …
`[UI-015]`, see `specs/features/dashboard.md`); `scripts/spec-check.sh` checks that
every criterion is cited.

## Run

```sh
# 1. Build the dashboard, then the binary that embeds it (order matters)
cd web && npm ci && npm run build && cd ..
go build -o bin/gw ./cmd/gw

# 2. Install test dependencies and Chromium (once)
cd test/e2e
npm ci
npx playwright install chromium

# 3. Run
npx playwright test
```

`npm run build:all` in this folder does step 1 for you. The global setup never builds
anything: it fails with a clear message if `bin/gw` or `web/dist` is missing.

Useful flags: `npx playwright test tests/approvals.spec.ts`, `--headed`, `--debug`,
`--grep UI-008`. Traces and screenshots of failed tests land in `test-results/`
(`npx playwright show-trace test-results/<test>/trace.zip`).

## How it works

- **One gateway per run** (`global-setup.ts`): a fresh `bin/gw serve` on a free port
  with a temporary data directory, `GW_KEY_PROVIDER=env`, a generated `GW_MASTER_KEY`
  and a generated `GW_BOOTSTRAP_ADMIN_KEY`. Setup waits for `GET /readyz` == 200. The
  bootstrap key is an owner API key; tests use it to seed data through the Admin API.
- **Browser URL is `http://localhost:<port>`** (`GW_PUBLIC_URL`), because WebAuthn
  needs a domain as relying-party ID, not an IP address. Node-side calls use
  `127.0.0.1`.
- **Passkeys** use Chromium's CDP virtual authenticator (`ctap2`, internal transport,
  resident keys, user verification). Logged-in pages come from the real invite flow:
  an invite is created with the bootstrap key and the user registers a passkey in the
  UI (`support/fixtures.ts`). One owner is registered per worker; `asRole('viewer')`
  registers extra users on demand. There is no backdoor in the backend.
- **First-run setup** (`tests/auth.spec.ts`, `[UI-002]`, `[UI-001]`) starts a *second*
  gateway without a bootstrap key and reads the setup link from its log
  (`/admin/setup?token=…`).
- **Upstream MCP fixture** (`support/mcp-fixture.ts`): a stateless Streamable HTTP MCP
  server built with `@modelcontextprotocol/sdk`. Every path `/mcp/<instance>` is an
  independent server with `list_issues` (read-only), `merge_pr` and `search_code`.
  `POST /control/<instance>/description` changes a tool description at runtime for the
  tool-pinning test (`[UI-009]`).
- **Live approvals** (`[UI-008]`): a profile with an `ask` rule, a static client token
  from `POST /clients`, and the MCP SDK client calling `<prefix>__merge_pr` without
  awaiting. The test waits for the approval to arrive over SSE, approves it in the UI
  and asserts that the client call resolves.

Tests run with one worker: they share one gateway and the security test imports a
config file, which replaces servers and profiles. A full run takes about 15 seconds.
