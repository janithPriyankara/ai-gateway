import { test, expect, api, env, uid } from '../support/fixtures';

test('[UI-015] API errors appear as readable messages', async ({ page }) => {
  const prefix = 'dup_' + uid();
  await api('POST', '/servers', { name: 'Taken', prefix, transport: 'http', url: `${env.fixtureUrl}/mcp/${prefix}`, auth_kind: 'none', enabled: true });

  await page.goto('/admin/servers');
  await page.getByRole('button', { name: 'Add server' }).click();
  const dialog = page.getByRole('dialog', { name: 'Add server' });
  await dialog.getByRole('tab', { name: 'Manual' }).click();
  await dialog.getByLabel('Name').fill('Duplicate');
  await dialog.getByLabel('Tool prefix').fill(prefix);
  await dialog.getByLabel('URL').fill(`${env.fixtureUrl}/mcp/x`);
  await dialog.getByRole('button', { name: 'Add server' }).click();
  const alert = dialog.getByRole('alert');
  await expect(alert).toContainText('already exists');
  await expect(alert).not.toContainText('{');
});

test('[UI-015] server failures never show raw stack traces', async ({ page }) => {
  const trace = 'panic: runtime error: invalid memory address\n\ngoroutine 1 [running]:\nmain.main()\n\t/src/main.go:12 +0x1d';
  await page.route('**/admin/api/v1/servers', (route) =>
    route.request().method() === 'GET' ? route.fulfill({ status: 500, contentType: 'text/plain', body: trace }) : route.continue(),
  );
  await page.goto('/admin/servers');
  const alert = page.getByRole('alert');
  await expect(alert).toContainText('The gateway hit a problem');
  await expect(page.locator('body')).not.toContainText('goroutine');
  await expect(page.locator('body')).not.toContainText('main.go');

  // A JSON error envelope shows its message.
  await page.route('**/admin/api/v1/catalog', (route) =>
    route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'unavailable', message: 'the catalog is temporarily unavailable' } }) }),
  );
  await page.unroute('**/admin/api/v1/servers');
  await page.reload();
  await page.getByRole('button', { name: 'Add server' }).click();
  await expect(page.getByRole('dialog').getByRole('alert')).toHaveText('The catalog is temporarily unavailable');

  // Network failure.
  await page.route('**/admin/api/v1/profiles', (route) => route.abort('connectionrefused'));
  await page.goto('/admin/profiles');
  await expect(page.getByRole('alert')).toContainText('Could not reach the gateway');
});
