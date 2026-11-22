import fs from 'node:fs';
import { test, expect, api } from '../support/fixtures';

test('[UI-011] security page shows the key provider and signing key age, rotates the key, exports and imports config', async ({ page }, testInfo) => {
  await page.goto('/admin/security');
  await expect(page.getByTestId('key-provider')).toHaveText('env');
  await expect(page.getByTestId('key-strength')).not.toBeEmpty();
  await expect(page.getByTestId('signing-age')).toContainText('day');

  const kid = await page.getByTestId('signing-kid').textContent();
  await page.getByRole('button', { name: 'Rotate' }).click();
  await page.getByRole('dialog', { name: 'Rotate the signing key?' }).getByRole('button', { name: 'Rotate key' }).click();
  await expect(page.getByText('Signing key rotated.')).toBeVisible();
  await expect(page.getByTestId('signing-kid')).not.toHaveText(kid ?? '');

  // Export downloads the YAML config.
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export config' }).click()]);
  expect(download.suggestedFilename()).toBe('mcp-gateway-config.yaml');
  const file = testInfo.outputPath('config.yaml');
  await download.saveAs(file);
  const yaml = fs.readFileSync(file, 'utf8');
  expect(yaml).toContain('servers');

  // Import the same file back (a no-op change that exercises the flow).
  const before = await api<unknown[]>('GET', '/profiles');
  await page.locator('#import-file').setInputFiles(file);
  await page.getByRole('dialog', { name: 'Import config.yaml?' }).getByRole('button', { name: 'Import' }).click();
  await expect(page.getByText('Imported config.yaml.')).toBeVisible();
  const after = await api<unknown[]>('GET', '/profiles');
  expect(after.length).toBe(before.length);

  // A broken file shows the server's validation message.
  await page.locator('#import-file').setInputFiles({ name: 'broken.yaml', mimeType: 'application/yaml', buffer: Buffer.from('version: 99\n') });
  await page.getByRole('dialog', { name: 'Import broken.yaml?' }).getByRole('button', { name: 'Import' }).click();
  await expect(page.getByRole('dialog').getByRole('alert')).toContainText(/version/i);
});
