import { test, expect, api, mcpClient, seedFixtureServer, uid } from '../support/fixtures';

test('[UI-010] activity shows audit events newest first with filters, Load more and Verify chain', async ({ page }) => {
  const prefix = 'act_' + uid();
  const serverId = await seedFixtureServer(prefix);
  const profile = 'act-' + uid();
  await api('PUT', `/profiles/${profile}`, {
    name: profile,
    servers: [serverId],
    rules: [{ tool: `${prefix}__merge_*`, action: 'deny' }, { tool: `${prefix}__*`, action: 'allow' }],
  });
  const clientName = 'Activity bot ' + uid();
  const created = await api<{ token: string; client: { id: string } }>('POST', '/clients', { name: clientName, profile });
  const client = await mcpClient(created.token);
  await client.callTool({ name: `${prefix}__list_issues`, arguments: {} });
  const denied = await client.callTool({ name: `${prefix}__merge_pr`, arguments: { number: 1 } });
  expect(denied.isError).toBe(true);
  await client.close();
  // Call events are written to the audit log in batches; wait until both are recorded.
  await expect.poll(async () => (await api<unknown[]>('GET', `/audit?client=${created.client.id}`)).length, { timeout: 15_000 }).toBe(2);

  // Make sure there is more than one page of events (each profile save is audited).
  for (let i = 0; i < 55; i++) {
    await api('PUT', `/profiles/${profile}-filler`, { name: `${profile}-filler`, servers: [], rules: [{ tool: `x${i}__*`, action: 'deny' }] });
  }

  await page.goto('/admin/activity');
  await expect(page.getByRole('heading', { level: 1, name: 'Activity' })).toBeVisible();
  const rows = page.getByTestId('audit-row');
  await expect(rows).toHaveCount(50);
  // Newest first: the last filler save is at the top.
  await expect(rows.first()).toContainText(`put profile ${profile}-filler`);

  await page.getByRole('button', { name: 'Load more' }).click();
  await expect.poll(() => rows.count()).toBeGreaterThan(50);

  // Filter by client and decision.
  await page.getByLabel('AI tool').selectOption({ label: clientName });
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText(`${prefix}__merge_pr`); // newest first
  await expect(rows.nth(1)).toContainText(`${prefix}__list_issues`);
  await page.getByLabel('Decision').selectOption('deny');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('deny');
  await expect(page).toHaveURL(/decision=deny/);

  await page.getByLabel('AI tool').selectOption('');
  await page.getByLabel('Decision').selectOption('');
  await page.getByLabel('Server').selectOption(serverId);
  await expect(rows).toHaveCount(2);

  await page.getByRole('button', { name: 'Verify chain' }).click();
  await expect(page.getByTestId('verify-result')).toContainText(/Chain intact: \d+ events checked/);
});
