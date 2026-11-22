Thanks for helping! The workflow is **spec → failing test → code**:
1. Describe the behaviour as a numbered acceptance criterion in `specs/features/*.md`
   (or update an existing one). New IDs continue the area's sequence (`GW-019`, …).
2. Write a test that cites it: `// spec: GW-019` in Go, or `[GW-019]` in a Playwright test title.
3. Make it pass. Keep `make test-race blackbox spec-check` green.
Guidelines:
- Services talk only through `internal/ports` interfaces. If the gateway needs something new
  from another service, add it to a port and to `internal/rpc` (both sides).
- No secrets in logs, errors or API responses. Add redaction tests when touching data paths.
- Keep dependencies minimal and justified in the PR description.
- New MCP server presets go in `internal/services/control/catalog/*.yaml` with safe default rules.
- New key providers implement `keybox.Provider` and register in `init()`.
Be kind. We follow the Contributor Covenant.
