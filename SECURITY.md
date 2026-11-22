mcp-gateway holds credentials to other systems, so we take reports seriously.
Do **not** open a public issue. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability"). Include steps to reproduce, the
affected version (`gw version`) and your assessment of impact.
We aim to acknowledge reports within 3 working days and to ship a fix or
mitigation within 90 days, coordinating disclosure with you.
In scope: the `gw` binary, the Docker image, the dashboard and the deployment
files in this repository. Out of scope: vulnerabilities in upstream MCP
servers themselves, and attacks that need an already-compromised host or an
owner account.
- Put the gateway behind TLS whenever it is reachable from other machines.
- Prefer a strong key provider (macOS Keychain, TPM-sealed key file, cloud KMS).
- Keep `ask` or `deny` rules on destructive tools; give web and chat clients read-only profiles.
- Back up the data directory and, separately, the master key.
- Run `gw doctor` after configuration changes.
