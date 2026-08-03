import { expect, test as base, type Page } from '@playwright/test';

/**
 * Functional gate on the claims this lab makes on screen.
 *
 * The a11y suite proves the page is reachable; this suite proves it is *right*:
 * every headline verdict is re-derived from a number the page itself printed,
 * every failure path is driven for real and asserted to name its cause, and the
 * counters are checked to add up rather than merely to exist.
 *
 * Nothing here hardcodes an expected simulation outcome that the page did not
 * also compute and display — the one exception is the FIPS 204 rejection bound
 * γ₁ − β, which is a standards constant and is separately asserted against the
 * value Attack 4 prints.
 */

/** FIPS 204 Table 1, ML-DSA-44: γ₁ = 2¹⁷, β = τ·η = 78. */
const GAMMA1_MINUS_BETA = (1 << 17) - 78;

/** Any uncaught page exception (or console error) fails the test that caused it. */
const test = base.extend<{ pageErrors: string[] }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        if (message.type() === 'error') {
          errors.push(`console.error: ${message.text()}`);
        }
      });
      await use(errors);
      expect(errors, 'uncaught page errors').toEqual([]);
    },
    { auto: true },
  ],
});

/** Load the lab with every progressive-disclosure <details> already expanded. */
async function open(page: Page): Promise<void> {
  await page.goto('.');
  await page.evaluate(() => {
    for (const d of Array.from(document.querySelectorAll('details'))) {
      d.open = true;
    }
  });
  // The initial trace generation runs on module load; this is its finished state.
  await expect(page.locator('#cpa-results')).toContainText('Traces generated');
}

/** Whitespace-normalised text of a panel, so multi-line HTML matches one regex. */
async function panel(page: Page, selector: string): Promise<string> {
  return (await page.locator(selector).innerText()).replace(/\s+/g, ' ').trim();
}

/** Regex match or a failure naming the panel text that did not match. */
function grab(text: string, pattern: RegExp): RegExpMatchArray {
  const match = text.match(pattern);
  expect(match, `expected ${pattern} in: ${text}`).not.toBeNull();
  return match as RegExpMatchArray;
}

const num = (raw: string): number => Number(raw.replace(/,/g, ''));

/** How many distinct colours a canvas holds — the empty grid is a handful. */
async function canvasColours(page: Page, selector: string): Promise<number> {
  return page.evaluate((sel) => {
    const canvas = document.querySelector<HTMLCanvasElement>(sel);
    if (!canvas) throw new Error(`missing ${sel}`);
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('no 2d context');
    const { data } = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const seen = new Set<string>();
    for (let i = 0; i < data.length; i += 4) {
      seen.add(`${data[i]},${data[i + 1]},${data[i + 2]}`);
    }
    return seen.size;
  }, selector);
}

/** Set a range input and let the page's `input`+`change` handlers run. */
async function setSlider(page: Page, selector: string, value: string): Promise<void> {
  await page.locator(selector).fill(value);
  await expect(page.locator(selector)).toHaveValue(value);
}

// ---------------------------------------------------------------------------
// Attack 1 — CPA power analysis
// ---------------------------------------------------------------------------

test('attack 1: CPA recovers the coefficient the page is holding, and its ranking is self-consistent', async ({
  page,
}) => {
  await open(page);

  // A high-SNR configuration: the exhibit's whole claim is that this recovers.
  await setSlider(page, '#sk-slider', '2500');
  await setSlider(page, '#noise-slider', '0.1');
  await setSlider(page, '#trace-count-slider', '200');

  // The verdict is checked against the secret the page is displaying, not a
  // literal: read it back off the page.
  const secret = Number(await page.locator('#sk-value').innerText());
  expect(secret).toBe(2500);

  await page.locator('#run-cpa-btn').click();
  await expect(page.locator('#cpa-results')).toContainText('Best correlation', { timeout: 120_000 });

  const text = await panel(page, '#cpa-results');
  const best = grab(text, /Best correlation:\s*k = (\d+) \(([\d.]+)\)/);
  const correct = grab(text, /Correct key:\s*sk\[0\] = (\d+)/);
  const lead = grab(text, /Lead over 2nd-best hypothesis: ([\d.]+)/);

  // The "correct key" the panel names is the secret the setup slider holds.
  expect(Number(correct[1])).toBe(secret);
  // The headline verdict: the top hypothesis IS that secret.
  expect(Number(best[1])).toBe(secret);
  expect(text).toContain('✓ RECOVERED');
  expect(text).not.toContain('top guess is off');

  // The ranked list must be the same ranking the headline came from.
  const ranked = [...text.matchAll(/k = (\d+) → ([\d.]+)/g)].map((m) => ({
    key: Number(m[1]),
    score: Number(m[2]),
  }));
  expect(ranked).toHaveLength(5);
  expect(ranked[0]!.key).toBe(Number(best[1]));
  expect(ranked[0]!.score).toBeCloseTo(Number(best[2]), 3);
  for (let i = 1; i < ranked.length; i += 1) {
    expect(ranked[i]!.score, 'ranked list is sorted by descending |correlation|').toBeLessThanOrEqual(
      ranked[i - 1]!.score,
    );
  }
  // The stated lead is exactly the gap between the top two rows.
  expect(Number(lead[1])).toBeCloseTo(ranked[0]!.score - ranked[1]!.score, 2);

  // Both CPA charts actually drew something.
  expect(await canvasColours(page, '#cpa-canvas')).toBeGreaterThan(5);
  expect(await canvasColours(page, '#cpa-growth-canvas')).toBeGreaterThan(5);
});

test('attack 1 failure path: too few traces at maximum noise fails, and says why', async ({ page }) => {
  await open(page);

  await setSlider(page, '#noise-slider', '1');
  await setSlider(page, '#trace-count-slider', '10');
  const secret = Number(await page.locator('#sk-value').innerText());

  await page.locator('#run-cpa-btn').click();
  await expect(page.locator('#cpa-results')).toContainText('Best correlation', { timeout: 120_000 });

  const text = await panel(page, '#cpa-results');
  const best = Number(grab(text, /Best correlation:\s*k = (\d+)/)[1]);

  // 10 traces at σ = 1.0 is below the SNR the attack needs: the top hypothesis
  // is not the secret, and the panel must say so and name the remedy.
  expect(best).not.toBe(secret);
  expect(text).toContain('top guess is off — add traces or lower noise');
  expect(text, 'a failed CPA must not claim recovery').not.toContain('✓ RECOVERED');
  expect(grab(text, /Correct key:\s*sk\[0\] = (\d+)/)[1]).toBe(String(secret));
});

test('attack 1: a focused trace sample decomposes into the exact butterfly Hamming weight below it', async ({
  page,
}) => {
  await open(page);

  await page.locator('#trace-canvas').focus();
  for (let i = 0; i < 4; i += 1) {
    await page.keyboard.press('ArrowRight');
  }

  const readout = await panel(page, '#trace-hover');
  const parsed = grab(
    readout,
    /Sample (\d+) of (\d+) — from butterfly stage (\d+) \((.+?)\): power (-?\d+\.\d+) = Hamming-weight signal (-?\d+\.\d+) ([+−]) noise (\d+\.\d+)\. Highlighted below\./,
  );
  const sample = Number(parsed[1]);
  const stage = Number(parsed[3]);
  const power = Number(parsed[5]);
  const signal = Number(parsed[6]);
  const noise = (parsed[7] === '−' ? -1 : 1) * Number(parsed[8]);

  // power = Hamming-weight signal + noise, to the printed precision.
  expect(power).toBeCloseTo(signal + noise, 2);
  // The readout's stage is the sample's own butterfly (3 samples per stage).
  expect(stage - 1).toBe(Math.floor(sample / 3));

  // Exactly one butterfly card, and one line within it, is lit.
  const card = page.locator('.butterfly-card.linked');
  await expect(card).toHaveCount(1);
  await expect(card).toHaveAttribute('data-stage', String(Math.floor(sample / 3)));
  const row = page.locator('.linked-row');
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute('data-sample', String(sample));

  // The claim the README makes ("the exact butterfly card whose Hamming weight
  // produced it"): the lit line's Hamming weight IS the plotted signal, since
  // the noise-free curve is HW × 0.1.
  const hw = Number(grab((await row.innerText()).replace(/\s+/g, ' '), /\(HW (\d+)\)/)[1]);
  expect(hw / 10).toBeCloseTo(signal, 2);

  // The three samples of a stage are w·b, a + wb, a − wb, in that order.
  expect(parsed[4]).toBe(['w·b', 'a + wb', 'a − wb'][sample % 3]);
});

// ---------------------------------------------------------------------------
// Attack 2 — fault injection on rejection sampling
// ---------------------------------------------------------------------------

test('attack 2: rejection sampling accepts only what is inside the bound; the fault releases what is not', async ({
  page,
}) => {
  await open(page);

  await page.locator('#normal-sign-btn').click();
  await expect(page.locator('#normal-log')).toContainText('attempts accepted', { timeout: 60_000 });

  const normal = await panel(page, '#normal-log');
  const totals = grab(normal, /(\d+) of (\d+) attempts accepted/);
  const accepted = Number(totals[1]);
  const attempts = Number(totals[2]);
  expect(attempts).toBe(300);
  expect(accepted).toBeGreaterThanOrEqual(0);
  expect(accepted).toBeLessThanOrEqual(attempts);

  const normalRows = [...normal.matchAll(/Attempt (\d+): z_max = (\d+) (✓ Accept|✗ Reject)/g)].map((m) => ({
    index: Number(m[1]),
    zMax: Number(m[2]),
    accepted: m[3] === '✓ Accept',
  }));
  expect(normalRows.length).toBeGreaterThan(0);
  for (const row of normalRows) {
    // The panel's own claim: "Every accepted z stays within the γ₁−β bound."
    if (row.accepted) {
      expect(row.zMax, `attempt ${row.index} accepted above the bound`).toBeLessThan(GAMMA1_MINUS_BETA);
    } else {
      expect(row.zMax, `attempt ${row.index} rejected below the bound`).toBeGreaterThanOrEqual(
        GAMMA1_MINUS_BETA,
      );
    }
  }

  await page.locator('#faulted-sign-btn').click();
  await expect(page.locator('#faulted-log')).toContainText('released signatures', { timeout: 60_000 });

  const faulted = await panel(page, '#faulted-log');
  const leakTotals = grab(faulted, /(\d+) of (\d+) released signatures \((\d+)%\) exceed the γ₁−β bound/);
  const leaked = Number(leakTotals[1]);
  const released = Number(leakTotals[2]);
  const pct = Number(leakTotals[3]);
  expect(released).toBe(300);
  expect(leaked).toBeLessThanOrEqual(released);
  // The percentage is the parts over the whole, not a decoration.
  expect(pct).toBe(Math.round((leaked / released) * 100));
  // The exhibit's point: skipping the check releases signatures that a correct
  // signer would have thrown away.
  expect(leaked, 'the faulted signer must leak over-bound signatures').toBeGreaterThan(0);

  const faultRows = [...faulted.matchAll(/Signature (\d+): z_max = (\d+) (⚠ over bound — leaked|• within bound — released)/g)].map(
    (m) => ({ index: Number(m[1]), zMax: Number(m[2]), over: m[3].startsWith('⚠') }),
  );
  expect(faultRows.length).toBeGreaterThan(0);
  for (const row of faultRows) {
    expect(row.over, `signature ${row.index}: z_max ${row.zMax} vs bound ${GAMMA1_MINUS_BETA}`).toBe(
      row.zMax >= GAMMA1_MINUS_BETA,
    );
  }

  expect(await canvasColours(page, '#rejection-canvas')).toBeGreaterThan(5);
});

test('attack 2: key recovery reports a rate that matches its own coefficient count and beats guessing', async ({
  page,
}) => {
  await open(page);

  await page.locator('#recover-btn').click();
  await expect(page.locator('#recovery-panel')).toContainText('Recovery rate', { timeout: 180_000 });

  const text = await panel(page, '#recovery-panel');
  const stats = grab(text, /Recovery rate:\s*([\d.]+)% — (\d+) of (\d+) secret coefficients exactly recovered/);
  const rate = Number(stats[1]);
  const correct = Number(stats[2]);
  const total = Number(stats[3]);

  expect(total).toBe(256);
  expect(correct).toBeLessThanOrEqual(total);
  // Rate is the parts over the whole.
  expect(rate).toBeCloseTo((correct / total) * 100, 1);
  // The panel names 20% as the random-guessing baseline; averaging the nonce out
  // of 8,000 faulted signatures must do far better than that or the exhibit is
  // claiming something it did not show.
  expect(rate, 'recovery must beat the 20% random-guessing baseline it cites').toBeGreaterThan(60);

  // Eight sample coefficients, each printed with the true value beside it.
  const samples = [...text.matchAll(/s₁\[(\d+)\] ≈ (-?\d+) \(actual (-?\d+)\) • confidence ([\d.]+)/g)];
  expect(samples).toHaveLength(8);
  for (const [, index, , actual, confidence] of samples) {
    // ML-DSA-44 secrets live in [−η, η] with η = 2.
    expect(Math.abs(Number(actual)), `s₁[${index}] outside [−2, 2]`).toBeLessThanOrEqual(2);
    expect(Number(confidence)).toBeGreaterThanOrEqual(0);
    expect(Number(confidence)).toBeLessThanOrEqual(1);
  }
});

// ---------------------------------------------------------------------------
// Attack 3 — KyberSlash divide-timing clusters
// ---------------------------------------------------------------------------

test('attack 3: the vulnerable divide separates the secret classes and the constant-time divide collapses them', async ({
  page,
}) => {
  await open(page);

  const cyclesLine = (text: string, label: string) =>
    grab(
      text,
      new RegExp(
        `${label}: bit-0 class ≈ ([\\d.]+) cycles, bit-1 class ≈ ([\\d.]+) cycles, separation = ([\\d.]+) cycles — (.+?)\\.`,
      ),
    );

  await page.locator('#run-vulnerable-btn').click();
  await expect(page.locator('#timing-results')).toContainText('Vulnerable divide', { timeout: 120_000 });

  const afterVulnerable = await panel(page, '#timing-results');
  const vulnerable = cyclesLine(afterVulnerable, 'Vulnerable divide');
  const vulnSmall = Number(vulnerable[1]);
  const vulnLarge = Number(vulnerable[2]);
  const vulnGap = Number(vulnerable[3]);
  // The separation is the gap between the two class means it just printed
  // (each figure is rounded to 0.1, so allow one ulp of display rounding).
  expect(Math.abs(vulnGap - Math.abs(vulnLarge - vulnSmall))).toBeLessThanOrEqual(0.11);
  expect(vulnGap, 'the vulnerable divide must actually differ by secret class').toBeGreaterThan(0);
  expect(vulnerable[4]).toBe('clusters are cleanly distinguishable ✓ the secret bit leaks');
  const vulnerableColours = await canvasColours(page, '#timing-canvas');
  expect(vulnerableColours).toBeGreaterThan(2);

  await page.locator('#run-constant-btn').click();
  await expect(page.locator('#timing-results')).toContainText('Constant-time divide', { timeout: 120_000 });

  const afterConstant = await panel(page, '#timing-results');
  const constant = cyclesLine(afterConstant, 'Constant-time divide');
  const constSmall = Number(constant[1]);
  const constLarge = Number(constant[2]);
  const constGap = Number(constant[3]);

  // The countermeasure's whole claim: the two classes now cost the same.
  expect(Math.abs(constLarge - constSmall)).toBeLessThanOrEqual(0.1);
  expect(Math.abs(constGap - Math.abs(constLarge - constSmall))).toBeLessThanOrEqual(0.11);
  expect(constGap).toBeLessThan(vulnGap);
  expect(constant[4]).toBe('clusters overlap — no usable leak');

  // The comparison paragraph must quote the two figures it is comparing.
  const comparison = grab(
    afterConstant,
    /Comparison: the vulnerable divide separates the two secret classes by ([\d.]+) cycles; the constant-time divide collapses them to ([\d.]+) cycles — one hump, no leak/,
  );
  expect(Number(comparison[1])).toBe(vulnGap);
  expect(Number(comparison[2])).toBe(constGap);
});

// ---------------------------------------------------------------------------
// Attack 4 — loop-abort fault on ExpandMask
// ---------------------------------------------------------------------------

const abortReadout = async (page: Page) => {
  const text = await panel(page, '#abort-readout');
  const alive = grab(text, /Nonce coefficients still alive: (\d+) of 256 \((\d+) left at zero\)/);
  const dimension = grab(text, /Embedding dimension required: ℓ\+1 ≈ (\d+) — (.+?)\./);
  return {
    text,
    alive: Number(alive[1]),
    zeros: Number(alive[2]),
    dimension: Number(dimension[1]),
    reach: dimension[2],
  };
};

test('attack 4: the abort readout accounts for all 256 coefficients and grades its own dimension', async ({
  page,
}) => {
  await open(page);

  let previousDimension = 0;
  for (const m of ['1', '8', '16', '40', '100', '256']) {
    await setSlider(page, '#abort-slider', m);
    await expect(page.locator('#abort-value')).toHaveText(m);

    const readout = await abortReadout(page);
    // Parts sum to the whole: sampled + never-written = the ring degree.
    expect(readout.alive).toBe(Number(m));
    expect(readout.alive + readout.zeros, `m = ${m} must account for all 256 coefficients`).toBe(256);

    // Required dimension grows with the abort point — the "fault buys dimension"
    // claim the exhibit is built on.
    expect(readout.dimension, `dimension must rise with m (m = ${m})`).toBeGreaterThan(previousDimension);
    previousDimension = readout.dimension;

    // The verdict wording must match the number it just printed.
    const expectedReach =
      readout.dimension > 256
        ? 'no projection is smaller than the ring — the signature leaks nothing'
        : readout.dimension <= 70
          ? 'inside LLL reach'
          : readout.dimension <= 115
            ? 'needs BKZ'
            : 'beyond the reduction reach reported in the paper';
    expect(readout.reach, `reach verdict for dimension ${readout.dimension}`).toBe(expectedReach);

    // The in-browser cap is disclosed exactly when it applies.
    expect(readout.text.includes('models the attack rather than running it')).toBe(Number(m) > 16);
  }

  // The unfaulted signature is the control: it leaks nothing.
  const full = await abortReadout(page);
  expect(full.alive).toBe(256);
  expect(full.zeros).toBe(0);
  expect(full.reach).toContain('leaks nothing');

  expect(await canvasColours(page, '#nonce-canvas')).toBeGreaterThan(5);
  expect(await canvasColours(page, '#dimension-canvas')).toBeGreaterThan(5);
});

test('attack 4: an executable abort point runs a real LLL and recovers the planted key', async ({ page }) => {
  await open(page);

  await setSlider(page, '#abort-slider', '8');
  await page.locator('#run-loopabort-btn').click();
  await expect(page.locator('#loopabort-results')).toContainText('Recovered s₁', { timeout: 180_000 });

  const text = await panel(page, '#loopabort-results');

  const signer = grab(
    text,
    /ExpandMask stopped after (\d+) coefficients, so y has (\d+) non-zero coefficients and (\d+) zeros/,
  );
  expect(Number(signer[1])).toBe(8);
  expect(Number(signer[2])).toBe(8);
  // Parts sum to the whole.
  expect(Number(signer[2]) + Number(signer[3])).toBe(256);

  // The signer's release decision must agree with the two numbers beside it,
  // and the bound must be the FIPS 204 one.
  const bound = grab(text, /‖z‖∞ = ([\d,]+) against the FIPS 204 bound γ₁ − β = ([\d,]+) — (yes|no)/);
  const zNorm = num(bound[1]);
  expect(num(bound[2])).toBe(GAMMA1_MINUS_BETA);
  expect(bound[3], `‖z‖∞ = ${zNorm} vs bound ${GAMMA1_MINUS_BETA}`).toBe(
    zNorm >= GAMMA1_MINUS_BETA ? 'no' : 'yes',
  );

  // The attacker walk-through, checked against itself.
  expect(text).toContain('c is invertible mod q? yes');
  const lattice = grab(
    text,
    /a lattice spanned by only (\d+) vectors instead of 256/,
  );
  expect(Number(lattice[1])).toBe(8);

  const projection = grab(
    text,
    /Projected onto index blocks of size (\d+) \(eq\. \(2\) asked for ℓ\+1 ≈ (\d+)\), built the Kannan embedding, and ran LLL on each: (\d+) of (\d+) blocks returned a short vector/,
  );
  const blockSize = Number(projection[1]);
  const required = Number(projection[2]);
  const solved = Number(projection[3]);
  const blocks = Number(projection[4]);
  // The projection actually used must be at least the size eq. (2) asked for.
  expect(blockSize).toBeGreaterThanOrEqual(required - 1);
  expect(solved).toBeLessThanOrEqual(blocks);
  expect(blocks).toBeGreaterThan(0);
  // 256 coefficients covered by blocks of this size.
  expect(blocks).toBe(Math.ceil(256 / blockSize));
  expect(solved, 'every projection block must reduce at m = 8').toBe(blocks);

  const recovery = grab(text, /Recovered s₁: (\d+) of (\d+) coefficients exact \(([\d.]+)%\) — (.+?)\./);
  const recovered = Number(recovery[1]);
  const total = Number(recovery[2]);
  const rate = Number(recovery[3]);
  expect(total).toBe(256);
  expect(rate).toBeCloseTo((recovered / total) * 100, 1);
  // The headline verdict must match the count that produced it.
  expect(recovery[4]).toBe(recovered === total ? 'full key recovery ✓' : 'partial');
  expect(recovered, 'one faulty signature at m = 8 must recover the whole key').toBe(256);

  // "the s₁ printed above is what lattice reduction actually returned" — at full
  // recovery the two printed vectors are identical.
  const vectors = grab(text, /recovered \[([^\]]*)\] vs actual \[([^\]]*)\]/);
  expect(vectors[1].split(', ')).toHaveLength(12);
  expect(vectors[1]).toBe(vectors[2]);

  const latticeMs = grab(text, /Lattice time: (\d+) ms, from one faulty signature/);
  expect(Number(latticeMs[1])).toBeGreaterThanOrEqual(0);
});

test('attack 4 failure path: past the in-browser cap the lattice step is skipped and says exactly why', async ({
  page,
}) => {
  await open(page);

  await setSlider(page, '#abort-slider', '40');
  await page.locator('#run-loopabort-btn').click();
  await expect(page.locator('#loopabort-results')).toContainText('Recovery not executed', {
    timeout: 180_000,
  });

  const text = await panel(page, '#loopabort-results');

  // The signer half still ran for real…
  const signer = grab(
    text,
    /ExpandMask stopped after (\d+) coefficients, so y has (\d+) non-zero coefficients and (\d+) zeros/,
  );
  expect(Number(signer[1])).toBe(40);
  expect(Number(signer[2]) + Number(signer[3])).toBe(256);

  // …and the skipped half names the cause: which m, what dimension it needs, and
  // what the page's cap is.
  const reason = grab(
    text,
    /Recovery not executed: m = (\d+) needs an LLL of dimension ≈ (\d+), past this page's in-browser limit of m = (\d+)\./,
  );
  expect(Number(reason[1])).toBe(40);
  expect(Number(reason[3])).toBe(16);
  expect(Number(reason[2])).toBeGreaterThan(Number(reason[3]));
  expect(text).toContain('only the lattice step was skipped');

  // A skipped reduction must not report a recovery.
  expect(text, 'a skipped lattice step must not claim recovered coefficients').not.toContain('Recovered s₁');
  expect(text).not.toContain('full key recovery');
});
