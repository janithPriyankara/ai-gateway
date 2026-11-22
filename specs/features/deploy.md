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
