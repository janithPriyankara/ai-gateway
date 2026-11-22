import { test, expect, api, env, seedFixtureServer, uid } from '../support/fixtures';

test('[UI-003] servers list shows transport, tools and health; add from the catalog and manually; edit; delete with confirmation', async ({ page }) => {
  await page.goto('/admin/servers');
  await expect(page.getByRole('heading', { level: 1, name: 'Servers' })).toBeVisible();

  // Add from the catalog (GitHub is a remote server; nothing is contacted without a credential).
  const existing = await api<{ id: string }[]>('GET', '/servers');
  if (!existing.some((s) => s.id === 'github')) {
    await page.getByRole('button', { name: 'Add server' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add server' });
    await dialog.getByRole('button', { name: 'Use GitHub' }).click();
    await expect(dialog.getByLabel('Name')).toHaveValue('GitHub');
    await expect(dialog.getByLabel('URL')).toHaveValue(/githubcopilot/);
    await dialog.getByRole('button', { name: 'Add server' }).click();
    await expect(page).toHaveURL(/\/admin\/servers\/github$/);
    await expect(page.getByRole('heading', { level: 1, name: 'GitHub' })).toBeVisible();
    await page.getByRole('link', { name: 'Servers' }).first().click();
  }

  // Add manually, pointing at the MCP fixture.
  const prefix = 'man_' + uid();
  await page.getByRole('button', { name: 'Add server' }).click();
  const dialog = page.getByRole('dialog', { name: 'Add server' });
  await dialog.getByRole('tab', { name: 'Manual' }).click();
  await dialog.getByLabel('Name').fill('Manual fixture');
  await dialog.getByLabel('Tool prefix').fill(prefix);
  await dialog.getByLabel('URL').fill(`${env.fixtureUrl}/mcp/${prefix}`);
  await dialog.getByRole('button', { name: 'Add server' }).click();
  const id = prefix.replace(/_/g, '-');
  await expect(page).toHaveURL(new RegExp(`/admin/servers/${id}$`));
  await page.getByRole('button', { name: 'Test connection' }).click();
  await expect(page.getByText('Connected. 3 tools found.')).toBeVisible();

  // The list shows transport, health and tool count.
  await page.goto('/admin/servers');
  const row = page.getByTestId(`server-row-${id}`);
  await expect(row).toContainText('Manual fixture');
  await expect(row).toContainText('http');
  await expect(row).toContainText('Healthy');
  await expect(row.getByRole('cell').nth(3)).toHaveText('3');
  await expect(page.getByTestId('server-row-github')).toContainText('Unknown');

  // Edit.
  await row.getByRole('button', { name: 'Edit Manual fixture' }).click();
  const edit = page.getByRole('dialog', { name: 'Edit Manual fixture' });
  await edit.getByLabel('Name').fill('Renamed fixture');
  await edit.getByRole('button', { name: 'Save changes' }).click();
  await expect(edit).toHaveCount(0);
  await expect(row).toContainText('Renamed fixture');

  // Delete asks first; cancelling keeps the server.
  await row.getByRole('button', { name: 'Delete Renamed fixture' }).click();
  const confirm = page.getByRole('dialog', { name: 'Delete Renamed fixture?' });
  await confirm.getByRole('button', { name: 'Cancel' }).click();
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Delete Renamed fixture' }).click();
  await confirm.getByRole('button', { name: 'Delete server' }).click();
  await expect(row).toHaveCount(0);
  const after = await api<{ id: string }[]>('GET', '/servers');
  expect(after.some((s) => s.id === id)).toBe(false);
});

test('[UI-004] server detail lists tools with read-only/write and pin badges; a credential is write-only', async ({ page }) => {
  const prefix = 'det_' + uid();
  const id = await seedFixtureServer(prefix);
  await page.goto(`/admin/servers/${id}`);
  await expect(page.getByRole('heading', { level: 1, name: `Fixture ${prefix}` })).toBeVisible();
  await expect(page.getByTestId('tool-row-list_issues')).toContainText('Read-only');
  await expect(page.getByTestId('tool-row-list_issues')).toContainText('Pinned');
  await expect(page.getByTestId('tool-row-merge_pr')).toContainText('Write');
  await expect(page.getByTestId('tool-row-merge_pr')).toContainText('Merge a pull request.');

  // A server that needs a bearer token.
  const bprefix = 'tok_' + uid();
  const bid = await seedFixtureServer(bprefix, { auth_kind: 'bearer' });
  await page.goto(`/admin/servers/${bid}`);
  const card = page.getByRole('region', { name: 'Credential' });
  await expect(card.getByRole('listitem').filter({ hasText: 'Your credential' })).toContainText('Not set');
  const secret = 'ghp_e2e_' + uid() + 'SECRETVALUE';
  await card.getByLabel('Token').fill(secret);
  await card.getByLabel('Who uses it').selectOption('shared');
  await card.getByRole('button', { name: 'Save credential' }).click();
  await expect(card.getByText('Credential saved. For your security it will not be shown again.')).toBeVisible();
  await expect(card.getByLabel('Token')).toHaveValue('');
  await expect(card.getByRole('listitem').filter({ hasText: 'Shared credential' })).toContainText('Set');
  await expect(card.getByRole('button', { name: 'Replace credential' })).toBeVisible();

  // The value never comes back: not in the page, not in the API.
  await page.reload();
  await expect(page.getByRole('heading', { level: 1, name: `Fixture ${bprefix}` })).toBeVisible();
  expect(await page.content()).not.toContain(secret);
  const creds = await api('GET', `/servers/${bid}/credentials`);
  expect(JSON.stringify(creds)).not.toContain(secret);

  // ?connected=1 (OAuth callback) shows a success notice.
  await page.goto(`/admin/servers/${bid}?connected=1`);
  await expect(page.getByText('Connected. The gateway stored your OAuth credential')).toBeVisible();
});
test('[UI-017] [UI-018] a rejected credential is flagged; Username + API token signs in with Basic; a schemeless Authorization value is warned about', async ({ page }) => {
  const prefix = 'basic_' + uid();
  const id = await seedFixtureServer(prefix, { auth_kind: 'bearer' });
  await page.goto(`/admin/servers/${id}`);
  const card = page.getByRole('region', { name: 'Credential' });
  // The credential comes before the tool list.
  const credY = (await card.boundingBox())!.y;
  const toolsY = (await page.getByRole('heading', { name: 'Tools', exact: true }).boundingBox())!.y;
  expect(credY).toBeLessThan(toolsY);
  // A bearer token is the wrong kind for this server: it is rejected and flagged.
  await card.getByLabel('Token').fill('not-what-it-wants');
  await card.getByRole('button', { name: 'Save credential' }).click();
  await expect(card.getByText('Credential saved.')).toBeVisible();
  await page.getByRole('button', { name: 'Test connection' }).click();
  await expect(page.getByText(/Connection failed/)).toBeVisible();
  await page.reload();
  await expect(page.getByText('Credential rejected').first()).toBeVisible();
  await expect(card.getByTestId('cred-rejected')).toContainText('save a new one');
  await page.goto('/admin/servers');
  await expect(page.getByTestId(`server-row-${id}`)).toContainText('Credential rejected');
  // A custom Authorization header without a scheme is warned about before saving.
  await page.goto(`/admin/servers/${id}`);
  await card.getByLabel('Type').selectOption('header');
  await card.getByLabel('Header name').fill('Authorization');
  await card.getByLabel('Header value').fill('ZTJlLXVzZXI6ZTJlLXRva2Vu');
  await expect(card.getByTestId('cred-scheme-warning')).toBeVisible();
  await card.getByLabel('Header value').fill('Basic ZTJlLXVzZXI6ZTJlLXRva2Vu');
  await expect(card.getByTestId('cred-scheme-warning')).toHaveCount(0);
  // Username + API token builds the Basic header; pasted whitespace is trimmed.
  await card.getByLabel('Type').selectOption('basic');
  await expect(card.getByTestId('cred-help')).toContainText('Jenkins');
  await card.getByLabel('Username').fill('e2e-user');
  await card.getByLabel('API token').fill('  e2e-token\n');
  await card.getByRole('button', { name: 'Replace credential' }).click();
  await expect(card.getByText('Credential saved.')).toBeVisible();
  await page.getByRole('button', { name: 'Test connection' }).click();
  await expect(page.getByText(/Connected\. \d+ tools found\./)).toBeVisible();
  await page.reload();
  await expect(page.getByText('Credential rejected')).toHaveCount(0);
  await expect(card.getByRole('listitem').filter({ hasText: 'Your credential' })).toContainText('Set');
});
