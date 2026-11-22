// Shared test helpers: Admin API seeding with the bootstrap key, passkey registration
// with Chromium's virtual authenticator, and logged-in browser contexts per role.
import { test as base, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

export { expect };

export type Role = 'owner' | 'admin' | 'member' | 'viewer';

export const env = {
  get url() { return must('GW_URL'); },
  get apiUrl() { return must('GW_API_URL'); },
  get adminKey() { return must('GW_ADMIN_KEY'); },
  get fixtureUrl() { return must('FIXTURE_URL'); },
};

function must(k: string): string {
  const v = process.env[k];
  if (!v) throw new Error(`${k} is not set: is global-setup running?`);
  return v;
}

/** Calls the Admin API with the bootstrap owner key. Throws on non-2xx. */
export async function api<T = unknown>(method: string, p: string, body?: unknown, apiUrl = env.apiUrl, key = env.adminKey): Promise<T> {
  const res = await fetch(apiUrl + '/admin/api/v1' + p, {
    method,
    headers: { Authorization: `Bearer ${key}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${p} -> ${res.status}: ${text}`);
  return (text ? JSON.parse(text) : undefined) as T;
}

let counter = 0;
/** A short unique suffix for names created by tests. */
export function uid(): string {
  counter++;
  return `${process.pid.toString(36)}${counter.toString(36)}${Math.random().toString(36).slice(2, 5)}`;
}

/** Adds a CTAP2 platform authenticator with user verification to the page (CDP). */
export async function addVirtualAuthenticator(context: BrowserContext, page: Page): Promise<string> {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return authenticatorId;
}

/** Registers a new dashboard user through the real invite flow and returns a signed-in context. */
export async function registerViaInvite(browser: Browser, role: Role, name: string, gwUrl = env.url, apiUrl = env.apiUrl, key = env.adminKey) {
  const inv = await api<{ token: string; url: string }>('POST', '/users/invites', { role }, apiUrl, key);
  const context = await browser.newContext({ baseURL: gwUrl });
  const page = await context.newPage();
  await addVirtualAuthenticator(context, page);
  await page.goto(`/admin/invite?token=${encodeURIComponent(inv.token)}`);
  await page.getByLabel('Your name').fill(name);
  await page.getByRole('button', { name: 'Create passkey' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  return { context, page };
}

/** Starts a new MCP session to the gateway with a static client token. */
export async function mcpClient(token: string): Promise<Client> {
  const client = new Client({ name: 'e2e', version: '1.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(env.apiUrl + '/mcp'), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  await client.connect(transport);
  return client;
}

/** Registers an upstream server that points at the MCP fixture and fetches its tools. */
export async function seedFixtureServer(prefix: string, extra: Record<string, unknown> = {}) {
  const id = prefix.replace(/_/g, '-');
  await api('POST', '/servers', {
    id,
    name: `Fixture ${prefix}`,
    prefix,
    transport: 'http',
    url: `${env.fixtureUrl}/mcp/${prefix}`,
    auth_kind: 'none',
    enabled: true,
    ...extra,
  });
  if ((extra.auth_kind ?? 'none') === 'none') {
    const r = await api<{ ok: boolean; error?: string }>('POST', `/servers/${id}/test`);
    if (!r.ok) throw new Error(`fixture server test failed: ${r.error}`);
  }
  return id;
}

type WorkerFixtures = { ownerStatePath: string };
type TestFixtures = { asRole: (role: Role) => Promise<Page> };

export const test = base.extend<TestFixtures, WorkerFixtures>({
  // One owner per worker, registered with a passkey through the invite flow.
  ownerStatePath: [
    async ({ browser }, use, workerInfo) => {
      const { context } = await registerViaInvite(browser, 'owner', `Owner ${workerInfo.workerIndex}-${uid()}`);
      const file = path.join(workerInfo.project.outputDir, `.auth-owner-${workerInfo.workerIndex}.json`);
      await context.storageState({ path: file });
      await context.close();
      await use(file);
    },
    { scope: 'worker' },
  ],
  baseURL: async ({}, use) => {
    await use(env.url);
  },
  storageState: async ({ ownerStatePath }, use) => {
    await use(ownerStatePath);
  },
  // Fresh signed-in page for another role (registers a new user each time).
  asRole: async ({ browser }, use) => {
    const contexts: BrowserContext[] = [];
    await use(async (role) => {
      const { context, page } = await registerViaInvite(browser, role, `${role} ${uid()}`);
      contexts.push(context);
      return page;
    });
    await Promise.all(contexts.map((c) => c.close()));
  },
});
