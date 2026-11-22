import { test, expect, api, uid } from '../support/fixtures';

test('[UI-005] connect an AI tool: token shown once with copy and snippets; change profile; revoke with confirmation', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const p1 = 'cli-a-' + uid();
  const p2 = 'cli-b-' + uid();
  for (const name of [p1, p2]) await api('PUT', `/profiles/${name}`, { name, servers: [], rules: [] });
  const name = 'Claude Code ' + uid();

  await page.goto('/admin/clients');
  await expect(page.getByRole('heading', { level: 1, name: 'AI tools' })).toBeVisible();
  await page.getByRole('button', { name: 'Connect a tool' }).click();
  const dialog = page.getByRole('dialog', { name: 'Connect a tool' });
  await dialog.getByLabel('Name').fill(name);
  await dialog.getByLabel('Profile').selectOption(p1);
  await dialog.getByRole('button', { name: 'Create token' }).click();

  const ready = page.getByRole('dialog', { name: `${name} is ready` });
  await expect(ready.getByText('It is shown only once')).toBeVisible();
  const token = (await ready.getByTestId('secret-value').textContent()) ?? '';
  expect(token.length).toBeGreaterThan(20);
  await ready.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect(ready.getByRole('button', { name: 'Copied' })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(token);

  const snippet = ready.getByTestId('snippet');
  await expect(snippet).toContainText('claude mcp add --transport http');
  await expect(snippet).toContainText(token);
  await ready.getByRole('tab', { name: 'Codex' }).click();
  await expect(snippet).toContainText('[mcp_servers.gateway]');
  await ready.getByRole('tab', { name: 'Cursor' }).click();
  await expect(snippet).toContainText('"mcpServers"');
  await ready.getByRole('button', { name: 'Done' }).click();

  // The token is never shown again.
  const row = page.getByTestId(`client-row-${name}`);
  await expect(row).toContainText('Active');
  await expect(row).toContainText('Never');
  await expect(page.getByRole('columnheader', { name: 'Calls' })).toBeVisible();
  await expect(row.getByRole('cell').nth(4)).toHaveText('0');
  expect(await page.content()).not.toContain(token);

  // Change profile.
  await row.getByLabel(`Profile for ${name}`).selectOption(p2);
  await expect.poll(async () => (await api<{ name: string; profile: string }[]>('GET', '/clients')).find((c) => c.name === name)?.profile).toBe(p2);

  // Revoke asks first.
  await row.getByRole('button', { name: `Revoke ${name}` }).click();
  await page.getByRole('dialog', { name: `Revoke ${name}?` }).getByRole('button', { name: 'Revoke' }).click();
  await expect(row).toContainText('Revoked');
  await expect(row.getByRole('button', { name: `Revoke ${name}` })).toHaveCount(0);
});
