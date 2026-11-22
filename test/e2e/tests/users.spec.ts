import { test, expect, api, registerViaInvite, uid } from '../support/fixtures';

interface User { id: string; name: string; role: string }

test('[UI-012] users page lists users and roles, changes a role, creates an invite and an admin API key', async ({ page, browser }) => {
  const memberName = 'Mia Member ' + uid();
  const member = await registerViaInvite(browser, 'member', memberName);
  await member.context.close();

  await page.goto('/admin/users');
  await expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible();
  const row = page.getByTestId(`user-row-${memberName}`);
  await expect(row.getByLabel(`Role for ${memberName}`)).toHaveValue('member');

  await row.getByLabel(`Role for ${memberName}`).selectOption('admin');
  await expect(page.getByText(`${memberName} is now admin.`)).toBeVisible();
  const users = await api<User[]>('GET', '/users');
  expect(users.find((u) => u.name === memberName)?.role).toBe('admin');

  // Invite link.
  await page.getByRole('button', { name: 'Invite user' }).click();
  const inv = page.getByRole('dialog', { name: 'Invite user' });
  await inv.getByLabel('Role').selectOption('viewer');
  await inv.getByRole('button', { name: 'Create invite link' }).click();
  await expect(inv.getByTestId('secret-value')).toContainText('/admin/invite?token=');
  await inv.getByRole('button', { name: 'Done' }).click();

  // Admin API key: shown once, works, can be revoked.
  const keyName = 'ci-' + uid();
  await page.getByRole('button', { name: 'Create API key' }).click();
  const dlg = page.getByRole('dialog', { name: 'Create API key' });
  await dlg.getByLabel('Name').fill(keyName);
  await dlg.getByRole('button', { name: 'Create key' }).click();
  const key = (await dlg.getByTestId('secret-value').textContent()) ?? '';
  expect(key).toMatch(/^gwa_/);
  await dlg.getByRole('button', { name: 'Done' }).click();
  const keyRow = page.getByTestId(`key-row-${keyName}`);
  await expect(keyRow).toContainText('Active');
  expect(await page.content()).not.toContain(key);
  await api('GET', '/servers', undefined, undefined, key); // the new key works

  await keyRow.getByRole('button', { name: `Revoke key ${keyName}` }).click();
  await page.getByRole('dialog', { name: `Revoke ${keyName}?` }).getByRole('button', { name: 'Revoke key' }).click();
  await expect(keyRow).toContainText('Revoked');
});
