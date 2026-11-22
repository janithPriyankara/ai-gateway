// Typed client for the mcp-gateway Admin API (/admin/api/v1). One function per endpoint.
// Every request uses the session cookie; non-GET requests carry the CSRF token from /auth/me.

export type Role = 'owner' | 'admin' | 'member' | 'viewer';
export type Transport = 'http' | 'stdio';
export type AuthKind = 'none' | 'bearer' | 'header' | 'env' | 'oauth';
export type Action = 'allow' | 'ask' | 'deny';
export type When = 'any' | 'read_only' | 'write';

export interface Me {
  user_id: string;
  name: string;
  role: Role;
  csrf?: string;
  via_session: boolean;
}

export interface Server {
  id: string;
  name: string;
  prefix: string;
  transport: Transport;
  url?: string;
  command?: string;
  args?: string[];
  auth_kind: AuthKind | string;
  enabled: boolean;
  timeout_seconds?: number;
  health?: string;
}

export interface Rule {
  tool: string;
  when?: When | '';
  action: Action;
}

export interface Profile {
  name: string;
  servers: string[];
  rules: Rule[];
  rate_limit?: { per_minute: number } | null;
}

export interface Decision {
  action: Action;
  rule_index: number;
  reason: string;
}

export interface ToolPin {
  server_id: string;
  tool: string;
  fingerprint: string;
  status: 'approved' | 'quarantined' | string;
  description: string;
  read_only: boolean;
  pending_fingerprint?: string;
  old_description?: string;
  new_description?: string;
  old_schema?: string;
  new_schema?: string;
  updated_at: string;
}

export interface Approval {
  id: string;
  user_id: string;
  client_id: string;
  client_name: string;
  profile: string;
  server_id: string;
  tool: string;
  summary: string;
  rule_index: number;
  status: 'pending' | 'approved' | 'denied' | 'expired' | string;
  reason?: string;
  decided_by?: string;
  created_at: string;
  expires_at: string;
  decided_at?: string;
}

export interface AuditEvent {
  id: number;
  time: string;
  kind: string;
  request_id: string;
  user_id: string;
  client_id: string;
  profile: string;
  server_id: string;
  tool: string;
  decision: string;
  status: string;
  latency_ms: number;
  summary: string;
  hash: string;
  prev_hash: string;
}

export interface User {
  id: string;
  name: string;
  role: Role;
  created_at: string;
}

export interface Client {
  id: string;
  user_id: string;
  name: string;
  profile: string;
  kind: string;
  prefix?: string;
  created_at: string;
  last_seen_at?: string;
  revoked_at?: string;
  calls?: number;
}

export interface CredentialInfo {
  user_id: string;
  server_id: string;
  kind: string;
  status: string;
  expires_at?: string;
  updated_at: string;
}

export interface KeyProviderInfo {
  name: string;
  strength: string;
  healthy: boolean;
}

export interface SigningKeyInfo {
  kid: string;
  created_at: string;
  age_days: number;
}

export interface AdminKey {
  id: string;
  user_id?: string;
  name: string;
  prefix?: string;
  created_at?: string;
  last_used_at?: string;
  revoked_at?: string;
}

export interface Overview {
  servers: number;
  clients: number;
  calls_today: number;
  blocked_today: number;
  pending_approvals: number;
  pin_changes: number;
  needs_reauth: string[];
  servers_down: string[];
  key_provider: KeyProviderInfo;
}

export interface CatalogEntry {
  description: string;
  docs?: string;
  server: Server;
  rules: Rule[];
}

export type SnippetKey = 'claude_code' | 'codex' | 'cursor' | 'generic';

export interface CreatedClient {
  token: string;
  client: Client;
  snippets: Record<SnippetKey, string>;
}

export interface Credential {
  kind: 'bearer' | 'header' | 'env' | 'oauth';
  token?: string;
  header_name?: string;
  header_value?: string;
  env?: Record<string, string>;
}

export interface ChainResult {
  ok: boolean;
  checked: number;
  broken_at?: number;
}

export interface AuditFilter {
  server?: string;
  client?: string;
  decision?: string;
  before?: number;
  limit?: number;
}

/** PublicKey options as produced by go-webauthn ({"publicKey": {...}}). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type WebAuthnOptions = { publicKey: Record<string, unknown> };

export const API_BASE = '/admin/api/v1';

/** An error from the API, always with a human-readable message. */
export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

let csrfToken = '';
let onUnauthenticated: (() => void) | null = null;

export function setCsrf(token: string | undefined): void {
  csrfToken = token ?? '';
}

/** Called when a request made during a session comes back 401 (session expired). */
export function setUnauthenticatedHandler(fn: (() => void) | null): void {
  onUnauthenticated = fn;
}

function friendlyStatus(status: number): string {
  if (status === 401) return 'Your session has ended. Sign in again.';
  if (status === 403) return 'You do not have permission to do that.';
  if (status === 404) return 'Not found.';
  if (status === 413) return 'The request is too large.';
  if (status >= 500) return 'The gateway hit a problem. Check its logs and try again.';
  return `The request failed (status ${status}).`;
}

/** Turns any thrown value into a sentence that is safe to show. Never shows stack traces. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof DOMException) {
    if (err.name === 'NotAllowedError') return 'The passkey request was cancelled or timed out.';
    if (err.name === 'InvalidStateError') return 'This passkey is already registered.';
    if (err.name === 'SecurityError') return 'Passkeys are not available on this address. Use the gateway public URL.';
    return 'The browser refused the request.';
  }
  if (err instanceof Error) {
    const name = (err as { name?: string }).name ?? '';
    const code = (err as { code?: string }).code ?? '';
    if (code === 'ERROR_INVALID_DOMAIN' || /invalid domain/i.test(err.message)) {
      return `Passkeys need a domain name, not an IP address. Open the dashboard at http://localhost:${window.location.port || '80'} instead (and set GW_PUBLIC_URL to match).`;
    }
    if (name === 'NotAllowedError') return 'The passkey request was cancelled or timed out.';
    if (err.message && err.message.length < 200 && !/\n\s+at /.test(err.message)) return err.message;
  }
  return 'Something went wrong. Try again.';
}

function capitalise(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

type Body = unknown;

interface RequestOptions {
  body?: Body;
  raw?: string;
  contentType?: string;
  signal?: AbortSignal;
  /** Do not trigger the global sign-out handler on 401. */
  quiet401?: boolean;
}

async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  let body: string | undefined;
  if (opts.raw !== undefined) {
    body = opts.raw;
    headers['Content-Type'] = opts.contentType ?? 'text/plain';
  } else if (opts.body !== undefined) {
    body = JSON.stringify(opts.body);
    headers['Content-Type'] = 'application/json';
  }
  if (method !== 'GET' && method !== 'HEAD' && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  let res: Response;
  try {
    res = await fetch(API_BASE + path, { method, headers, body, credentials: 'same-origin', signal: opts.signal });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network', 'Could not reach the gateway. Check that it is running.');
  }
  const text = await res.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = undefined;
    }
  }
  if (!res.ok) {
    const env = data as { error?: { code?: string; message?: string } } | undefined;
    const code = env?.error?.code ?? 'http_' + res.status;
    const msg = env?.error?.message ? capitalise(env.error.message) : friendlyStatus(res.status);
    if (res.status === 401 && !opts.quiet401 && onUnauthenticated) onUnauthenticated();
    throw new ApiError(res.status, code, msg);
  }
  if (data === undefined && text) {
    // Non-JSON success (YAML export etc.) is returned as text.
    return text as unknown as T;
  }
  return data as T;
}

const enc = encodeURIComponent;

function qs(params: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') p.set(k, String(v));
  const s = p.toString();
  return s ? '?' + s : '';
}

// --- auth ---
export const authStatus = () => request<{ setup_required: boolean }>('GET', '/auth/status', { quiet401: true });
export const me = () => request<Me>('GET', '/auth/me', { quiet401: true });
export const setupBegin = (token: string, name: string) =>
  request<{ ceremony: string; options: WebAuthnOptions }>('POST', '/auth/setup/begin', { body: { token, name }, quiet401: true });
export const inviteBegin = (token: string, name: string) =>
  request<{ ceremony: string; options: WebAuthnOptions }>('POST', '/auth/invite/begin', { body: { token, name }, quiet401: true });
export const passkeyBegin = (name: string) =>
  request<{ ceremony: string; options: WebAuthnOptions }>('POST', '/auth/passkeys/begin', { body: { token: '', name } });
export const registerFinish = (ceremony: string, credential: unknown) =>
  request<{ user: User }>('POST', '/auth/register/finish', { body: { ceremony, credential }, quiet401: true });
export const loginBegin = () =>
  request<{ ceremony: string; options: WebAuthnOptions }>('POST', '/auth/login/begin', { quiet401: true });
export const loginFinish = (ceremony: string, credential: unknown) =>
  request<{ user: User }>('POST', '/auth/login/finish', { body: { ceremony, credential }, quiet401: true });
export const logout = () => request<{ ok: boolean }>('POST', '/auth/logout', { quiet401: true });

// --- overview / catalog ---
export const getOverview = () => request<Overview>('GET', '/overview');
export const getCatalog = () => request<CatalogEntry[]>('GET', '/catalog');

// --- servers ---
export const listServers = () => request<Server[]>('GET', '/servers');
export const getServer = (id: string) => request<Server>('GET', `/servers/${enc(id)}`);
export const createServer = (s: Server & { rules?: Rule[] }) => request<Server>('POST', '/servers', { body: s });
export const updateServer = (id: string, s: Server) => request<Server>('PUT', `/servers/${enc(id)}`, { body: s });
export const deleteServer = (id: string) => request<{ ok: boolean }>('DELETE', `/servers/${enc(id)}`);
export const listServerTools = (id: string) => request<ToolPin[]>('GET', `/servers/${enc(id)}/tools`);
export const testServer = (id: string, shared = false) =>
  request<{ ok: boolean; tools?: number; error?: string }>('POST', `/servers/${enc(id)}/test${shared ? '?as=shared' : ''}`);
export const listCredentials = (id: string) => request<CredentialInfo[]>('GET', `/servers/${enc(id)}/credentials`);
export const setCredential = (id: string, scope: 'me' | 'shared', c: Credential) =>
  request<{ ok: boolean }>('PUT', `/servers/${enc(id)}/credential`, { body: { scope, ...c } });
export const deleteCredential = (id: string, scope: 'me' | 'shared') =>
  request<{ ok: boolean }>('DELETE', `/servers/${enc(id)}/credential${qs({ scope })}`);
export const setOAuthApp = (
  id: string,
  app: { auth_url: string; token_url: string; client_id: string; client_secret?: string; scopes: string[] },
) => request<{ ok: boolean }>('PUT', `/servers/${enc(id)}/oauth-app`, { body: app });
export const connectServer = (id: string) => request<{ authorize_url: string }>('POST', `/servers/${enc(id)}/connect`);

// --- clients ---
export const listClients = () => request<Client[]>('GET', '/clients');
export const createClient = (name: string, profile: string) =>
  request<CreatedClient>('POST', '/clients', { body: { name, profile } });
export const setClientProfile = (id: string, profile: string) =>
  request<Client>('PATCH', `/clients/${enc(id)}`, { body: { profile } });
export const revokeClient = (id: string) => request<{ ok: boolean }>('DELETE', `/clients/${enc(id)}`);

// --- profiles ---
export const listProfiles = () => request<Profile[]>('GET', '/profiles');
export const putProfile = (p: Profile) => request<Profile>('PUT', `/profiles/${enc(p.name)}`, { body: p });
export const deleteProfile = (name: string) => request<{ ok: boolean }>('DELETE', `/profiles/${enc(name)}`);
export const simulate = (profile: string, tool: string, readOnly: boolean) =>
  request<{ decision: Decision; server_id: string }>('POST', '/profiles/simulate', {
    body: { profile, tool, read_only: readOnly },
  });

// --- approvals ---
export const listApprovals = (status?: string) => request<Approval[]>('GET', `/approvals${qs({ status })}`);
export const decideApproval = (id: string, approve: boolean, always = false) =>
  request<Approval>('POST', `/approvals/${enc(id)}/decide`, { body: { approve, always } });

// --- tool pins ---
export const listPinChanges = () => request<ToolPin[]>('GET', '/pins/changes');
export const acceptPin = (server: string, tool: string) =>
  request<{ ok: boolean }>('POST', `/pins/${enc(server)}/${enc(tool)}/accept`);
export const rejectPin = (server: string, tool: string) =>
  request<{ ok: boolean }>('POST', `/pins/${enc(server)}/${enc(tool)}/reject`);

// --- audit ---
export const queryAudit = (f: AuditFilter) =>
  request<AuditEvent[]>('GET', `/audit${qs({ server: f.server, client: f.client, decision: f.decision, before: f.before, limit: f.limit })}`);
export const verifyAudit = () => request<ChainResult>('GET', '/audit/verify');

// --- users and keys ---
export const listUsers = () => request<User[]>('GET', '/users');
export const createInvite = (role: Role) => request<{ token: string; url: string }>('POST', '/users/invites', { body: { role } });
export const setUserRole = (id: string, role: Role) => request<{ ok: boolean }>('PATCH', `/users/${enc(id)}`, { body: { role } });
export const deleteUser = (id: string) => request<{ ok: boolean }>('DELETE', `/users/${enc(id)}`);
export const listKeys = () => request<AdminKey[]>('GET', '/keys');
export const createKey = (name: string) => request<{ key: string; meta: AdminKey }>('POST', '/keys', { body: { name } });
export const revokeKey = (id: string) => request<{ ok: boolean }>('DELETE', `/keys/${enc(id)}`);

// --- security and config ---
export const getSecurity = () =>
  request<{ key_provider: KeyProviderInfo; signing_key: SigningKeyInfo }>('GET', '/security');
export const rotateSigningKey = () => request<{ signing_key: SigningKeyInfo }>('POST', '/security/rotate-signing-key');
export const exportConfig = () => request<string>('GET', '/config/export');
export const importConfig = (yaml: string) =>
  request<{ ok: boolean }>('POST', '/config/import', { raw: yaml, contentType: 'application/yaml' });

export const EVENTS_URL = API_BASE + '/events';

// --- helpers ---
const rank: Record<Role, number> = { viewer: 1, member: 2, admin: 3, owner: 4 };
export function atLeast(role: Role | undefined, min: Role): boolean {
  return !!role && rank[role] >= rank[min];
}

/** Go encodes zero times as 0001-01-01T00:00:00Z. */
export function isZeroTime(t: string | undefined): boolean {
  return !t || t.startsWith('0001-01-01');
}
