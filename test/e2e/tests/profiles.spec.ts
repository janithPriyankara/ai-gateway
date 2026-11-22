import { test, expect, api, seedFixtureServer, uid } from '../support/fixtures';

interface Profile { name: string; servers: string[]; rules: { tool: string; when?: string; action: string }[] }

test('[UI-006] edit profile rules in a table: add, reorder, delete, save; server-side validation errors show inline', async ({ page }) => {
  const prefix = 'prf_' + uid();
  const serverId = await seedFixtureServer(prefix);
  const name = 'edit-' + uid();

  await page.goto('/admin/profiles');
  await page.getByRole('button', { name: 'New profile' }).click();
  const dlg = page.getByRole('dialog', { name: 'New profile' });
  await dlg.getByLabel('Name').fill(name);
  await dlg.getByRole('button', { name: 'Create profile' }).click();
  await expect(page.getByRole('heading', { name: `Profile: ${name}` })).toBeVisible();

  await page.getByRole('checkbox', { name: `Fixture ${prefix}` }).check();
  await page.getByRole('button', { name: 'Add rule' }).click();
  await page.getByLabel('Rule 1 tool pattern').fill(`${prefix}__*`);
  await page.getByLabel('Rule 1 action').selectOption('allow');
  await page.getByRole('button', { name: 'Add rule' }).click();
  await page.getByLabel('Rule 2 tool pattern').fill(`${prefix}__merge_*`);
  await page.getByLabel('Rule 2 action').selectOption('ask');
  await page.getByRole('button', { name: 'Add rule' }).click();
  await page.getByLabel('Rule 3 tool pattern').fill(`${prefix}__list_*`);
  await page.getByLabel('Rule 3 when').selectOption('read_only');
  await page.getByLabel('Rule 3 action').selectOption('deny');

  // Reorder: the specific merge rule must come before the catch-all.
  await page.getByRole('button', { name: 'Move rule 2 up' }).click();
  await expect(page.getByLabel('Rule 1 tool pattern')).toHaveValue(`${prefix}__merge_*`);
  await page.getByRole('button', { name: 'Move rule 2 down' }).click();
  await expect(page.getByLabel('Rule 3 tool pattern')).toHaveValue(`${prefix}__*`);
  // Delete the deny rule (now rule 2).
  await page.getByRole('button', { name: 'Delete rule 2' }).click();
  await expect(page.getByTestId('rule-row-2')).toHaveCount(0);

  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(page.getByText('Profile saved.')).toBeVisible();
  const saved = (await api<Profile[]>('GET', '/profiles')).find((p) => p.name === name);
  expect(saved?.servers).toEqual([serverId]);
  expect(saved?.rules).toEqual([
    { tool: `${prefix}__merge_*`, action: 'ask' },
    { tool: `${prefix}__*`, action: 'allow' },
  ]);

  // An empty pattern is rejected by the server; the error is shown on the offending row.
  await page.getByRole('button', { name: 'Add rule' }).click();
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  const bad = page.getByTestId('rule-row-2');
  await expect(bad).toHaveClass(/row-error/);
  await expect(bad).toContainText('rule 3: tool pattern is required');
  await expect(page.getByRole('alert').first()).toContainText('tool pattern is required');
  const unchanged = (await api<Profile[]>('GET', '/profiles')).find((p) => p.name === name);
  expect(unchanged?.rules).toHaveLength(2);
});

test('[UI-007] rule simulator shows the decision and the matching rule', async ({ page }) => {
  const prefix = 'sim_' + uid();
  const serverId = await seedFixtureServer(prefix);
  const name = 'sim-' + uid();
  await api('PUT', `/profiles/${name}`, {
    name,
    servers: [serverId],
    rules: [
      { tool: `${prefix}__*`, when: 'read_only', action: 'allow' },
      { tool: `${prefix}__merge_*`, action: 'ask' },
      { tool: `${prefix}__delete_*`, action: 'deny' },
    ],
  });
  await page.goto('/admin/profiles');
  const sim = page.getByRole('region', { name: 'Rule simulator' });
  await sim.getByLabel('Profile').selectOption(name);

  await sim.getByLabel('Tool name').fill(`${prefix}__merge_pr`);
  await sim.getByRole('button', { name: 'Simulate' }).click();
  await expect(sim.getByTestId('sim-decision')).toHaveText('ask');
  await expect(sim.getByTestId('sim-result')).toContainText(`Matched rule 2: ${prefix}__merge_* → ask`);

  await sim.getByLabel('Tool name').fill(`${prefix}__list_issues`);
  await sim.getByLabel('Read-only tool').check();
  await sim.getByRole('button', { name: 'Simulate' }).click();
  await expect(sim.getByTestId('sim-decision')).toHaveText('allow');
  await expect(sim.getByTestId('sim-result')).toContainText('Matched rule 1');

  await sim.getByLabel('Read-only tool').uncheck();
  await sim.getByLabel('Tool name').fill(`${prefix}__push_code`);
  await sim.getByRole('button', { name: 'Simulate' }).click();
  await expect(sim.getByTestId('sim-decision')).toHaveText('deny');
  await expect(sim.getByTestId('sim-result')).toContainText('No rule matched');
});
test('[UI-016] warns when rules name servers that are not checked, and fixes it in one click', async ({ page }) => {
  const a = 'wa_' + uid();
  const b = 'wb_' + uid();
  const idA = await seedFixtureServer(a);
  const idB = await seedFixtureServer(b);
  const name = 'warn-' + uid();
  await api('PUT', `/profiles/${name}`, {
    name,
    servers: [],
    rules: [
      { tool: `${a}__*`, when: 'read_only', action: 'allow' },
      { tool: `${b}__*`, action: 'ask' },
      { tool: '*', action: 'deny' },
    ],
  });
  await page.goto('/admin/profiles');
  await page.getByRole('group', { name: 'Profiles' }).getByRole('button', { name: new RegExp(`^${name}`) }).click();
  const warn = page.getByTestId('profile-server-warning');
  await expect(warn).toContainText('AI tools using this profile see no tools');
  await expect(warn).toContainText(`Fixture ${a}`);
  await expect(warn).toContainText(`Fixture ${b}`);
  // Checking one server by hand narrows the warning to the other.
  await page.getByRole('checkbox', { name: `Fixture ${a}` }).check();
  await expect(warn).not.toContainText('see no tools');
  await expect(warn).not.toContainText(`Fixture ${a}`);
  await expect(warn).toContainText(`Fixture ${b}`);
  await warn.getByRole('button', { name: 'Check these servers' }).click();
  await expect(page.getByRole('checkbox', { name: `Fixture ${b}` })).toBeChecked();
  await expect(warn).toHaveCount(0);
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(page.getByText('Profile saved.')).toBeVisible();
  const saved = (await api<Profile[]>('GET', '/profiles')).find((p) => p.name === name);
  expect(saved?.servers.sort()).toEqual([idA, idB].sort());
});
