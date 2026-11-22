// First-run setup and passkey login against a separate gateway with NO bootstrap key.
import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import { startGateway, type Gateway } from '../support/gateway';
import { addVirtualAuthenticator } from '../support/fixtures';

test.describe.serial('first run and sign-in', () => {
  let gw: Gateway;
  let context: BrowserContext;
  let page: Page; // its virtual authenticator keeps the owner's passkey between tests

  test.beforeAll(async ({ browser }) => {
    gw = await startGateway({ bootstrap: false });
    context = await browser.newContext({ baseURL: gw.url });
    page = await context.newPage();
    await addVirtualAuthenticator(context, page);
  });
  test.afterAll(async () => {
    await context?.close();
    await gw?.stop();
  });

  test('[UI-002] first-run setup registers the owner with a passkey and lands on the overview', async () => {
    const m = await gw.waitForLog(/\/admin\/setup\?token=([A-Za-z0-9_-]+)/);
    const token = m[1];

    // Before setup, the dashboard sends visitors to the setup page.
    await page.goto('/admin/');
    await expect(page.getByRole('heading', { level: 1, name: 'Set up mcp-gateway' })).toBeVisible();
    await expect(page.getByText('Open the setup link printed in the gateway log')).toBeVisible();

    await page.goto(`/admin/setup?token=${token}`);
    await page.getByLabel('Your name').fill('Ada Owner');
    await page.getByRole('button', { name: 'Create passkey' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
    await expect(page).toHaveURL(/\/admin\/$/);
    await expect(page.getByTestId('my-role')).toHaveText('Owner');

    // The setup token is single-use.
    const again = await context.request.post(`${gw.url}/admin/api/v1/auth/setup/begin`, { data: { token, name: 'Eve' } });
    expect(again.ok()).toBe(false);
  });

  test('[UI-001] without a session /admin shows the login page; passkey login lands on the overview with metrics', async ({ browser }) => {
    // A browser without a session sees the login page.
    const anon = await browser.newContext({ baseURL: gw.url });
    const anonPage = await anon.newPage();
    await anonPage.goto('/admin/');
    await expect(anonPage.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
    await expect(anonPage).toHaveURL(/\/admin\/login$/);
    await anon.close();

    // Sign out, then sign in again with the registered passkey.
    await page.goto('/admin/');
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
    await page.goto('/admin/');
    await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
    await page.getByRole('button', { name: 'Sign in with a passkey' }).click();

    await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
    for (const id of ['metric-servers', 'metric-clients', 'metric-calls', 'metric-blocked']) {
      await expect(page.getByTestId(id)).toBeVisible();
    }
    await expect(page.getByTestId('metric-servers')).toContainText('Servers');
    await expect(page.getByTestId('metric-clients')).toContainText('AI tools');
    await expect(page.getByTestId('metric-calls')).toContainText('Calls today');
    await expect(page.getByTestId('metric-blocked')).toContainText('Blocked today');
    await expect(page.getByRole('heading', { name: 'Needs your attention' })).toBeVisible();
  });

  test('[UI-001] login respects ?next= with a full page navigation (OAuth consent flow)', async () => {
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
    await page.goto('/admin/login?next=' + encodeURIComponent('/admin/servers?from=login'));
    await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Servers' })).toBeVisible();
    await expect(page).toHaveURL(/\/admin\/servers\?from=login$/);

    // Off-site destinations are ignored.
    await page.getByRole('button', { name: 'Sign out' }).click();
    await page.goto('/admin/login?next=' + encodeURIComponent('//evil.example/'));
    await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  });
});
