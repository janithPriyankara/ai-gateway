# AUTH: Client authentication and OAuth 2.1 authorization server

## Static tokens

- **AUTH-001** `CreateStaticToken(user, client name, profile)` returns a token of the form `gw_<43 url-safe chars>` exactly once. Only an argon2id hash and an 8-character lookup prefix are stored.
- **AUTH-002** Verifying a valid static token returns the Identity (user, client id, client name, profile). Revoked or unknown tokens fail with the same generic error.
- **AUTH-003** Static token verification uses constant-time comparison and caches successful verifications for at most 60 seconds (revocation takes effect within that window).

## Access tokens (JWT)

- **AUTH-010** Access tokens are ES256 JWTs with `iss`, `sub` (user), `aud` (the gateway's MCP resource URL), `exp` (1 hour), `iat`, `jti`, `client_id`, `profile` and a `kid` header.
- **AUTH-011** Verification rejects: wrong signature, unknown `kid`, wrong `iss`, wrong `aud`, expired tokens (30 s leeway), `alg` other than ES256 (including `none`).
- **AUTH-012** `/.well-known/jwks.json` publishes current and recently retired public keys. Signing keys are stored sealed (KEY-001) and rotate; tokens signed by a retired key remain valid until they expire.

## OAuth 2.1 server (for MCP clients)

- **AUTH-020** `/.well-known/oauth-protected-resource` (RFC 9728) returns the resource URL and the authorization server URL. Unauthenticated `/mcp` requests get `401` with `WWW-Authenticate: Bearer resource_metadata="…"`.
- **AUTH-021** `/.well-known/oauth-authorization-server` (RFC 8414) advertises `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `code_challenge_methods_supported: ["S256"]`, `grant_types_supported: ["authorization_code","refresh_token"]`, `token_endpoint_auth_methods_supported: ["none"]`.
- **AUTH-022** Dynamic Client Registration (RFC 7591) at `/oauth/register` accepts public clients with `redirect_uris`. Redirect URIs must be `https`, or `http` on loopback (`127.0.0.1`, `[::1]`, `localhost`). Others are rejected.
- **AUTH-023** `/oauth/authorize` requires `response_type=code`, a registered `client_id`, an exact-match registered `redirect_uri`, `code_challenge` with `code_challenge_method=S256`, and a `state` (passed back unchanged). Plain PKCE is rejected.
- **AUTH-024** The authorize step requires a logged-in gateway user (dashboard session). Without one, the user is sent to the login page and returned afterwards. The user must approve the consent screen and pick a profile.
- **AUTH-025** Authorization codes are single-use, expire in 60 seconds and are bound to the client, the redirect URI and the PKCE challenge. Reusing a code revokes all tokens issued from it.
- **AUTH-026** `/oauth/token` with `grant_type=authorization_code` verifies the PKCE `code_verifier` and returns an access token (AUTH-010) and a refresh token.
- **AUTH-027** Refresh tokens rotate on every use. Presenting an already-used refresh token revokes the whole token family (reuse detection).
- **AUTH-028** `resource` parameter (RFC 8707), if sent, must equal the gateway's MCP resource URL.

## Dashboard login

- **AUTH-030** On first start with no users, the gateway prints a one-time **setup token** to its log. Visiting `/admin/setup?token=…` creates the first user with the `owner` role.
- **AUTH-031** Users log in with passkeys (WebAuthn). Registration and login ceremonies use a server-generated challenge that is single-use and expires in 5 minutes.
- **AUTH-032** For automation and CI, an **admin API key** (`gwa_…`, hashed like AUTH-001) can be created by an owner and used as `Authorization: Bearer` on the Admin API.
- **AUTH-033** Dashboard sessions are `HttpOnly`, `Secure` (except on loopback), `SameSite=Lax` cookies holding an opaque random ID; sessions expire after 12 hours idle; state-changing Admin API calls from cookie sessions require a matching `X-CSRF-Token` header.
- **AUTH-034** Roles: `owner` > `admin` > `member` > `viewer`. Each Admin API route declares its minimum role; requests below it get `403`.
