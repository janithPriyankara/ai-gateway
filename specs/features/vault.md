# VLT: Vault service (upstream credentials)

## Acceptance criteria

- **VLT-001** A credential is stored per `(user, server)`; a credential with an empty user is a *shared* credential used for any user who has none of their own.
- **VLT-002** Credentials are stored only in sealed form (KEY-001); the database never contains plaintext tokens.
- **VLT-003** `GetCredential(user, server)` returns the user's credential, else the shared one, else `ErrNoCredential`.
- **VLT-004** Credential kinds: `bearer` (Authorization: Bearer), `header` (custom header name + value), `env` (environment variables for stdio servers), `oauth` (access + refresh token + expiry + token endpoint).
- **VLT-005** For `oauth` credentials, `GetCredential` refreshes the access token when less than 20% of its lifetime remains, stores the new tokens (sealed), and returns the fresh one. Concurrent callers trigger only one refresh (single-flight).
- **VLT-006** If a refresh fails with `invalid_grant`, the credential is marked `needs_reauth`, and `GetCredential` returns `ErrNeedsReauth` until it is reconnected.
- **VLT-007** Upstream OAuth connect: `StartConnect(user, server)` returns an authorization URL with PKCE (S256) and a random `state`; `CompleteConnect(state, code)` exchanges the code, validates `state` (single use, 10-minute expiry) and stores the tokens.
- **VLT-008** The API never returns secret values to callers other than the gateway's credential injector; listing credentials returns metadata only (kind, expiry, status, updated time).
- **VLT-009** Deleting a server deletes all its credentials.
