# DEP: Distribution and deployment

- **DEP-001** `gw serve` runs all services in one process (`--services=all`, default). `--services=gateway,auth,vault,control` selects a subset; the rest are reached over internal HTTP at configured URLs.
- **DEP-002** Internal service-to-service calls require a shared internal token (`GW_INTERNAL_TOKEN`, at least 32 bytes) sent as `Authorization: Bearer`; internal routes are mounted under `/internal/v1` and reject requests without it.
- **DEP-003** Each service owns its own SQLite database file (`auth.db`, `vault.db`, `control.db`) in the data directory, in WAL mode.
- **DEP-004** By default the gateway listens on `127.0.0.1:8787`. Listening on a non-loopback address requires `--public-url` to be set (used as the OAuth issuer and MCP resource URL). On loopback the public URL defaults to `http://localhost:<port>`, because browsers refuse IP addresses as passkey domains.
- **DEP-005** `GET /healthz` returns 200 when the process is alive; `GET /readyz` returns 200 only when its databases, key provider and (in split mode) dependent services are reachable.
- **DEP-006** The Docker image is multi-stage, runs as a non-root user, has no shell or package manager in the final stage, and stores data in `/data`.
- **DEP-007** `deploy/compose.yml` runs the all-in-one container; `deploy/compose.split.yml` runs gateway (2 replicas), auth, vault and control as separate containers that pass the black-box suite.
- **DEP-008** The binary embeds the dashboard and the server catalog; it needs no files besides its data directory.
- **DEP-009** `gw version` prints version, commit and build date; `gw doctor` checks the key provider, databases, listen address and file permissions and prints actionable warnings.
- **DEP-010** `--tls=local` (`GW_TLS=local`) serves HTTPS with a certificate from the gateway's own local certificate authority. The CA is created once in `<data-dir>/tls/` (`ca.crt`, and `ca.key` with mode 0600 in a 0700 directory) and reused on later starts. With TLS on, the loopback public URL defaults to `https://localhost:<port>`.
- **DEP-011** The local CA is name-constrained to `localhost` (and its subdomains), `127.0.0.0/8` and `::1`, so even a leaked CA key cannot vouch for any other site. Local TLS refuses a public URL whose host is not local.
- **DEP-012** Server certificates from the local CA are short-lived (90 days) and renewed automatically, without a restart, when fewer than 30 days remain.
- **DEP-013** `--tls=files` with `--tls-cert` and `--tls-key` (`GW_TLS_CERT`, `GW_TLS_KEY`) serves a provided certificate. A certificate replaced on disk (for example by certbot) is picked up without a restart. Setting only `--tls-cert` implies `files`.
- **DEP-014** With TLS on, the public URL must use `https://`, the minimum TLS version is 1.2, and `gw healthcheck` probes over HTTPS.
- **DEP-015** `gw trust` adds the local CA to the user's trust store (the login keychain on macOS; on Linux and Windows it prints the exact commands) and prints the CA file path for Node-based tools (`NODE_EXTRA_CA_CERTS`). `gw trust --print` only prints the path; `gw trust --remove` removes it from the macOS keychain.
