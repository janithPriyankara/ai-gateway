import { test, expect, api, env, seedFixtureServer, mcpClient, uid } from '../support/fixtures';

const MUTATIONS = /^(Add server|Add your first server|Connect a tool|Connect your first tool|New profile|Create your first profile|Save|Add rule|Delete.*|Edit.*|Revoke.*|Remove.*|Approve.*|Deny.*|Always allow.*|Accept.*|Reject.*|Rotate|Import config…|Export config|Invite user|Create API key|Test connection|Save credential|Replace credential|Connect)$/;

test('[UI-013] a viewer sees every page read-only with no create, edit, delete or decide buttons', async ({ asRole }) => {
  // Seed something on every page so that row-level controls would render if allowed.
  const prefix = 'vw_' + uid();
  const serverId = await seedFixtureServer(prefix, {});
  const profile = 'viewer-' + uid();
  await api('PUT', `/profiles/${profile}`, { name: profile, servers: [serverId], rules: [{ tool: `${prefix}__merge_*`, action: 'ask' }, { tool: `${prefix}__*`, action: 'allow' }] });
  const created = await api<{ token: string }>('POST', '/clients', { name: 'Viewer test bot ' + uid(), profile });
  await fetch(`${env.fixtureUrl}/control/${prefix}/description`, { method: 'POST', body: JSON.stringify({ tool: 'search_code', description: 'changed' }) });
  await api('POST', `/servers/${serverId}/test`);
  const client = await mcpClient(created.token);
  const pending = client.callTool({ name: `${prefix}__merge_pr`, arguments: { number: 3 } }, undefined, { timeout: 60_000 }).catch(() => null);

  const page = await asRole('viewer');
  await expect(page.getByTestId('my-role')).toHaveText('Viewer');
  // Users is admin-only and hidden from the navigation.
  await expect(page.getByRole('navigation').getByRole('link', { name: 'Users' })).toHaveCount(0);

  const pages: [string, string][] = [
    ['/admin/', 'Overview'],
    ['/admin/servers', 'Servers'],
    [`/admin/servers/${serverId}`, `Fixture ${prefix}`],
    ['/admin/clients', 'AI tools'],
    ['/admin/profiles', 'Profiles'],
    ['/admin/approvals', 'Approvals'],
    ['/admin/tool-changes', 'Tool changes'],
    ['/admin/activity', 'Activity'],
    ['/admin/security', 'Security'],
  ];
  for (const [path, title] of pages) {
    await page.goto(path);
    await expect(page.getByRole('heading', { level: 1, name: title })).toBeVisible();
    await expect(page.locator('.loading')).toHaveCount(0);
    if (path === '/admin/approvals') await expect(page.getByTestId('pending-list')).toContainText(`${prefix}__merge_pr`);
    if (path === '/admin/tool-changes') await expect(page.getByTestId(`change-${serverId}-search_code`)).toBeVisible();
    if (path === '/admin/profiles') await expect(page.getByRole('table', { name: 'Rules' })).toBeVisible();
    const names = await page.getByRole('main').getByRole('button').evaluateAll((els) => els.map((e) => (e.getAttribute('aria-label') || e.textContent || '').trim()));
    const offending = names.filter((n) => MUTATIONS.test(n));
    expect(offending, `mutation controls on ${path}`).toEqual([]);
    // Rule editing inputs are read-only text, not form fields.
    if (path === '/admin/profiles') await expect(page.getByLabel(/Rule 1 tool pattern/)).toHaveCount(0);
  }

  // The API agrees: a viewer's mutation is refused (and the UI would show a readable error).
  const res = await page.request.post('/admin/api/v1/servers', { data: {} });
  expect(res.status()).toBe(403);

  // Clean up the pending call so it does not linger.
  const list = await api<{ id: string; tool: string }[]>('GET', '/approvals?status=pending');
  for (const a of list.filter((x) => x.tool === `${prefix}__merge_pr`)) await api('POST', `/approvals/${a.id}/decide`, { approve: false });
  await pending;
  await client.close();
});
