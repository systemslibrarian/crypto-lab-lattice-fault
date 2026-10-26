import { expect, test } from '@playwright/test';

test('unpacking research preserves the physical model and estimated budget', async ({ page }) => {
  await page.goto('.');
  const note = page.locator('#unpacking-research-note');
  await expect(note).toBeVisible();
  for (const text of ['ML-DSA-65', 'Cortex-M4', 'physical traces', '6 MHz', '1,000 traces', 'estimated enumeration', '99%', '270', 'not reproduced']) {
    await expect(note).toContainText(text);
  }
  await expect(note.locator('a')).toHaveAttribute('href', 'https://eprint.iacr.org/2026/2643');
});
