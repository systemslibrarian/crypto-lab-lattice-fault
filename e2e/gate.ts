import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The spec this replaces
 *     called a `revealAll()` helper that force-set `details.open = true`,
 *     stripped `[hidden]`, and added `.active`/`.open` to every panel — and
 *     then scanned. On this lab that fabricates a page no visitor can reach:
 *     Attacks 2, 3 and 4 live inside `.attack-reveal` `<details>` that ship
 *     CLOSED, and their result boxes ("Recovery panel idle.", "No divide-cycle
 *     measurements collected yet.") only hold real output after a button has
 *     been pressed. It also called `page.emulateMedia({ reducedMotion })` AFTER
 *     `goto`, so first paint was never under the preference at all.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over a `<details>` nobody opened passes having
 *     checked nothing.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead. The only transition on this page is
 * `.butterfly-card.linked`'s 0.1s lift when a trace sample is focused, but the
 * `<details>` disclosures each run their own open animation.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * reduced-motion block collapses durations rather than setting `animation:
 * none`, so it should be safe; the assertion is what makes that a measurement
 * rather than a reading of the stylesheet.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The DEFAULTS are asserted rather than assumed. This lab ships the on-ramp
 * `#lattice-primer` OPEN and the three `.attack-reveal` disclosures CLOSED, and
 * `void generateTraces()` runs at module load so Attack 1's canvases and the
 * butterfly grid are populated at first paint while every other result box
 * still holds its idle placeholder. A gate written against the opposite
 * assumption would scan half the page and never notice.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  // `index.html`'s anti-flash script reads localStorage['theme'] and stamps
  // `data-theme` unconditionally — dark included — so both themes are asserted
  // by attribute here.
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  await expect(page.locator('#attack-1')).toBeVisible();
  await expect(page.locator('#butterfly-grid .butterfly-card').first()).toBeVisible();
  await expect(page.locator('#trace-hover')).not.toBeEmpty();

  // Assert the shipped disclosure defaults, do not assume them.
  await expect(page.locator('#lattice-primer')).toHaveAttribute('open', '');
  for (const id of ['reveal-2', 'reveal-3', 'reveal-4']) {
    expect(
      await page.locator(`#${id}`).evaluate((el) => (el as HTMLDetailsElement).open),
      `#${id} must ship closed — the gate opens it by clicking its summary`
    ).toBe(false);
  }

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 600px-wide canvases, a four-column
 * countermeasure table, and long unbroken monospace formulae
 * (`c⁻¹z − s₁ ≡ Σ y·(c⁻¹xⁱ)`).
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. This lab does not have
    // that rule today, which is exactly why the check has to look for it: a
    // later "fix" that adds it would otherwise make this oracle permanently
    // green instead of failing.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That is
    // a live risk here: `.comparison-table-wrap` is precisely such a scroller.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Anything inside a real scroller is reachable and is not a finding; only
    // what escapes the viewport with no way back is.
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll. This page has four candidates —
 * `.comparison-table-wrap`, `.warmup-code`, `.formula-line` and
 * `.algebra-walk` — and the ones that carry `tabindex="0"` in the markup are
 * the reason this assertion is a regression test rather than a discovery.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set prints every finding as it happens
 * and then FAILS at the end via `reportCollected`, so a green collection run
 * cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *    Load-bearing here: axe files nearly every surface on this page under
 *    `incomplete` because the panels are translucent over a body gradient.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/** Open a `<details>` the way a visitor does — by clicking its summary. */
async function openDisclosure(page: Page, id: string): Promise<void> {
  await page.locator(`#${id} > summary`).click();
  await expect(page.locator(`#${id}`)).toHaveAttribute('open', '');
}

/** Set a range input and dispatch the events its listeners are bound to. */
async function setRange(page: Page, selector: string, value: string): Promise<void> {
  await page.locator(selector).evaluate((el, v) => {
    const input = el as HTMLInputElement;
    input.value = v;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }, value);
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * The order mirrors the page: the on-ramp primer's closed state (a real state —
 * its summary invites you to collapse it), then each of the four attacks. Every
 * result box starts holding a placeholder and only fills after a button press,
 * so each button is pressed and scanned; the sliders are driven to BOTH
 * extremes, because the Attack-4 readout and the Attack-1 trace redraw are
 * functions of the slider value and the shipped defaults (m = 8, sigma = 0.5)
 * are not the interesting ones. Every wait is on a real completion signal —
 * the readout text changing, the button leaving its busy state — never a fixed
 * timeout.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint`);

  // --- the on-ramp primer, collapsed and re-expanded ------------------------
  await page.locator('#lattice-primer > summary').click();
  expect(
    await page.locator('#lattice-primer').evaluate((el) => (el as HTMLDetailsElement).open)
  ).toBe(false);
  await scan(page, `${theme} / primer collapsed`);
  await openDisclosure(page, 'lattice-primer');
  await scan(page, `${theme} / primer re-expanded`);

  // --- Attack 1: sliders at both extremes, generate, CPA --------------------
  // Count last: every slider's `change` re-runs `generateTraces()` at whatever
  // count is current, so raising it first would pay for 500 traces four times.
  await setRange(page, '#sk-slider', '3328');
  await setRange(page, '#ct-slider', '3328');
  await setRange(page, '#noise-slider', '1');
  await setRange(page, '#trace-count-slider', '500');
  await expect(page.locator('#sk-value')).toHaveText('3328');
  await expect(page.locator('#cpa-results')).toContainText('Traces generated');
  await scan(page, `${theme} / attack 1 sliders at max`);

  await setRange(page, '#sk-slider', '0');
  await setRange(page, '#ct-slider', '0');
  await setRange(page, '#noise-slider', '0.1');
  await setRange(page, '#trace-count-slider', '10');
  await expect(page.locator('#sk-value')).toHaveText('0');
  await scan(page, `${theme} / attack 1 sliders at min`);

  await page.locator('#generate-traces-btn').click();
  await expect(page.locator('#cpa-results')).toContainText('Ready to test');
  await scan(page, `${theme} / attack 1 traces generated`);

  // The trace readout is keyboard-operable; the focused sample lights up a
  // butterfly card and one `.linked-row` inside it. Both are states no visitor
  // sees without interacting, and both paint their own colours.
  await page.locator('#trace-canvas').focus();
  await page.locator('#trace-canvas').press('ArrowRight');
  await expect(page.locator('#trace-hover')).toContainText('Highlighted below');
  await expect(page.locator('.butterfly-card.linked')).toBeVisible();
  await scan(page, `${theme} / attack 1 trace sample focused`);

  await page.locator('#run-cpa-btn').click();
  await expect(page.locator('#cpa-results')).toContainText('Best correlation', {
    timeout: 120_000,
  });
  await expect(page.locator('#run-cpa-btn')).toBeEnabled();
  await scan(page, `${theme} / attack 1 CPA complete`);

  // --- Attack 2: fault injection on rejection sampling ----------------------
  await openDisclosure(page, 'reveal-2');
  await scan(page, `${theme} / attack 2 revealed (idle panels)`);

  await page.locator('#normal-sign-btn').click();
  await expect(page.locator('#normal-log')).toContainText('attempts accepted');
  await scan(page, `${theme} / attack 2 normal signing`);

  await page.locator('#faulted-sign-btn').click();
  await expect(page.locator('#faulted-log')).toContainText('released signatures');
  await scan(page, `${theme} / attack 2 faulted signing`);

  await page.locator('#recover-btn').click();
  await expect(page.locator('#recovery-panel')).toContainText('Recovery rate', {
    timeout: 180_000,
  });
  await expect(page.locator('#recover-btn')).toBeEnabled();
  await scan(page, `${theme} / attack 2 key recovered`);

  // --- Attack 3: KyberSlash timing -----------------------------------------
  await openDisclosure(page, 'reveal-3');
  await scan(page, `${theme} / attack 3 revealed (idle panel)`);

  await page.locator('#run-vulnerable-btn').click();
  await expect(page.locator('#timing-results')).toContainText('Vulnerable divide', {
    timeout: 120_000,
  });
  await expect(page.locator('#run-vulnerable-btn')).toBeEnabled();
  await scan(page, `${theme} / attack 3 vulnerable divide`);

  await page.locator('#run-constant-btn').click();
  await expect(page.locator('#timing-results')).toContainText('Comparison', {
    timeout: 120_000,
  });
  await expect(page.locator('#run-constant-btn')).toBeEnabled();
  await scan(page, `${theme} / attack 3 both divides`);

  // --- Attack 4: loop-abort fault ------------------------------------------
  await openDisclosure(page, 'reveal-4');
  await scan(page, `${theme} / attack 4 revealed (idle panel)`);

  // m = 256 is the "the fault buys nothing" branch of the readout, and the only
  // one that renders the `no projection is smaller than the ring` wording.
  await setRange(page, '#abort-slider', '256');
  await expect(page.locator('#abort-readout')).toContainText('leaks nothing');
  await scan(page, `${theme} / attack 4 abort at m=256`);

  // Past the in-browser cap the readout grows an extra "models the attack"
  // note, and the run below reports a skipped reduction instead of a recovery.
  await setRange(page, '#abort-slider', '80');
  await expect(page.locator('#abort-readout')).toContainText('models');
  await scan(page, `${theme} / attack 4 abort past the executable cap`);

  await page.locator('#run-loopabort-btn').click();
  await expect(page.locator('#loopabort-results')).toContainText('faulty signature', {
    timeout: 180_000,
  });
  await expect(page.locator('#run-loopabort-btn')).toBeEnabled();
  await scan(page, `${theme} / attack 4 modelled (past cap)`);

  // m = 1 is the other extreme: inside LLL reach, so the run executes the real
  // reduction and renders the `.algebra-walk` panel that only exists then.
  await setRange(page, '#abort-slider', '1');
  await expect(page.locator('#abort-readout')).toContainText('inside LLL reach');
  await scan(page, `${theme} / attack 4 abort at m=1`);

  await page.locator('#run-loopabort-btn').click();
  await expect(page.locator('#loopabort-results .algebra-walk')).toBeVisible({
    timeout: 180_000,
  });
  await expect(page.locator('#run-loopabort-btn')).toBeEnabled();
  await scan(page, `${theme} / attack 4 lattice recovery executed`);

  // --- the skip link, which only paints while focused ----------------------
  await page.locator('.cl-skip-link').focus();
  await expect(page.locator('.cl-skip-link')).toBeFocused();
  await scan(page, `${theme} / skip link focused`);

  reportCollected();
}
