import { test, expect, api, seedFixtureServer, uid } from '../support/fixtures';

test('[UI-014] usable at 375 px: the sidebar collapses into a menu and nothing scrolls sideways', async ({ page }) => {
  // Wide content (tables with many columns) must scroll inside its own box, not the page.
  const prefix = 'm_' + uid();
  const serverId = await seedFixtureServer(prefix);
  const name = 'mobile-' + uid();
  await api('PUT', `/profiles/${name}`, {
    name,
    servers: [serverId],
    rules: [{ tool: `${prefix}__merge_*`, when: 'write', action: 'ask' }, { tool: `${prefix}__*`, action: 'allow' }],
  });
  await page.setViewportSize({ width: 375, height: 760 });
  for (const path of ['/admin/', '/admin/servers', `/admin/servers/${serverId}`, '/admin/profiles', '/admin/activity', '/admin/clients', '/admin/approvals', '/admin/tool-changes', '/admin/security', '/admin/users']) {
    await page.goto(path);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.locator('.loading')).toHaveCount(0);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `horizontal overflow on ${path}`).toBeLessThanOrEqual(0);
  }
  await page.goto('/admin/');
  const nav = page.getByRole('navigation');
  await expect(nav).toBeHidden();
  await page.getByRole('button', { name: 'Open menu' }).click();
  await expect(nav).toBeVisible();
  await nav.getByRole('link', { name: 'Servers' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Servers' })).toBeVisible();
  await expect(nav).toBeHidden();
});

test('[UI-014] every control is reachable by keyboard with a visible focus ring', async ({ page }) => {
  await page.goto('/admin/servers');
  await expect(page.getByRole('heading', { level: 1, name: 'Servers' })).toBeVisible();
  await expect(page.locator('.loading')).toHaveCount(0);

  // Tab through the page and record what receives focus and whether it has an outline.
  const seen: { label: string; outline: string }[] = [];
  for (let i = 0; i < 40; i++) {
    await page.keyboard.press('Tab');
    const info = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body) return null;
      const cs = getComputedStyle(el);
      return { label: (el.getAttribute('aria-label') || el.textContent || '').trim(), outline: `${cs.outlineStyle} ${cs.outlineWidth}` };
    });
    if (info) seen.push(info);
  }
  const labels = seen.map((s) => s.label);
  for (const want of ['Overview', 'Servers', 'AI tools', 'Profiles', 'Approvals', 'Activity', 'Security', 'Sign out', 'Add server']) {
    expect(labels.some((l) => l.startsWith(want)), `${want} reachable by Tab`).toBe(true);
  }
  for (const s of seen) expect(s.outline, `focus ring on ${s.label}`).not.toMatch(/^none|0px$/);

  // Keyboard-only flow: open the add-server dialog, switch tab with arrows, close with Escape.
  await page.getByRole('button', { name: 'Add server' }).focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', { name: 'Add server' });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('tab', { name: 'From catalog' }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(dialog.getByRole('tab', { name: 'Manual' })).toBeFocused();
  await expect(dialog.getByLabel('Name')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Add server' })).toBeFocused();
});

test('[UI-014] light and dark mode both render with their own palette', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto('/admin/');
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  const light = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  await page.emulateMedia({ colorScheme: 'dark' });
  const dark = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(light).not.toBe(dark);
  const textDark = await page.evaluate(() => getComputedStyle(document.body).color);
  expect(textDark).not.toBe(dark);
});
