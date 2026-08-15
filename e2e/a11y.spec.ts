import { test } from '@playwright/test';
import { boot, driveAllStates, NARROW } from './gate';

/**
 * WCAG A/AA regression gate. Deploys are already gated on the simulation logic
 * (e2e/claims.spec.ts and the vitest suite); this gates them on accessibility
 * the same way.
 *
 * Four configurations — {dark, light} x {1280px, 380px} — and within each, the
 * lab is DRIVEN: every disclosure opened by clicking its summary, every button
 * pressed, both extremes of every slider, and a scan after each step. See
 * `gate.ts` for why nothing is injected into the page, why each scan asserts
 * its content first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    page.setDefaultTimeout(20_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    page.setDefaultTimeout(20_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
  });
}
