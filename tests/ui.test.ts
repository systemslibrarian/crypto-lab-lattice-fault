// @vitest-environment jsdom
import { beforeAll, describe, expect, it } from 'vitest';
import { webcrypto } from 'node:crypto';

/**
 * Integration coverage for the UI glue in src/main.ts: boot the real module
 * into jsdom, click each control, and assert the on-screen panels actually
 * update. The unit suites prove the simulations are correct; this proves the
 * buttons are wired to them.
 *
 * jsdom ships no canvas or rAF, so we install a *recording* 2D context (captures
 * every draw call so tests can assert real drawing happened, not just that the
 * code didn't throw) and a setTimeout-backed requestAnimationFrame before the
 * module's import-time side effects run.
 */

type DrawLog = { calls: Record<string, number>; ops: Array<[string, unknown[]]> };
const recorders = new WeakMap<HTMLCanvasElement, DrawLog>();

/** Draw-call counts recorded for a given canvas, e.g. drawCalls('#trace-canvas').lineTo. */
const drawCalls = (selector: string): Record<string, number> =>
  recorders.get($<HTMLCanvasElement>(selector))?.calls ?? {};

const tick = (ms = 0): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate: () => boolean, timeoutMs = 30000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error('Timed out waiting for UI condition');
    }
    await tick(15);
  }
}

const $ = <T extends Element>(selector: string): T => {
  const el = document.querySelector<T>(selector);
  if (!el) throw new Error(`Missing ${selector}`);
  return el;
};

const text = (selector: string): string => $(selector).textContent ?? '';

beforeAll(async () => {
  // Web Crypto with subtle (KECCAK exhibit needs digest); Node's webcrypto has both.
  if (!globalThis.crypto?.subtle) {
    Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  }

  // jsdom in this environment exposes no localStorage; the theme toggle writes
  // to it. Real browsers always have it, so an in-memory stub is enough.
  if (!globalThis.localStorage) {
    const store = new Map<string, string>();
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      value: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => store.set(k, String(v)),
        removeItem: (k: string) => store.delete(k),
        clear: () => store.clear(),
      },
    });
  }

  // requestAnimationFrame backed by timers so withBusy()/nextFrame() resolve.
  globalThis.requestAnimationFrame = ((cb: FrameRequestCallback) =>
    setTimeout(() => cb(performance.now()), 0) as unknown as number) as typeof requestAnimationFrame;
  globalThis.cancelAnimationFrame = ((id: number) => clearTimeout(id)) as typeof cancelAnimationFrame;

  // Recording 2D context: method calls are tallied per-canvas (so tests can
  // assert the drawing code actually emitted ops), property sets are swallowed.
  // The drawing code never reads back from the context.
  (HTMLCanvasElement.prototype as unknown as { getContext: unknown }).getContext = function (
    this: HTMLCanvasElement,
  ) {
    let log = recorders.get(this);
    if (!log) {
      log = { calls: {}, ops: [] };
      recorders.set(this, log);
    }
    const rec = log;
    return new Proxy(
      {},
      {
        get: (_target, prop: string) =>
          (...args: unknown[]) => {
            rec.calls[prop] = (rec.calls[prop] ?? 0) + 1;
            rec.ops.push([prop, args]);
            return undefined;
          },
        set: () => true,
      },
    );
  };

  document.body.innerHTML = '<div id="app"></div>';

  // Import runs main.ts's top-level wiring + the initial generateTraces().
  await import('../src/main.ts');
  await tick(50);
});

describe('initial render', () => {
  it('renders all five exhibits and the controls', () => {
    expect(document.querySelectorAll('.exhibit').length).toBe(5);
    expect(text('#attack-1')).toContain('NTT POWER ANALYSIS');
    expect(document.querySelector('#sk-slider')).toBeTruthy();
    expect(document.querySelector('#run-cpa-btn')).toBeTruthy();
  });

  it('auto-generates traces and the butterfly grid on load', async () => {
    await waitFor(() => $('#butterfly-grid').children.length > 0);
    expect($('#butterfly-grid').querySelectorAll('.butterfly-card').length).toBeGreaterThan(0);
    expect(text('#cpa-results')).toMatch(/Traces generated|hypotheses/);
  });

  it('actually renders the power-trace polylines to the canvas', () => {
    const c = drawCalls('#trace-canvas');
    expect(c.clearRect ?? 0).toBeGreaterThan(0);
    // 5 trace series × many samples each → lots of lineTo segments.
    expect(c.lineTo ?? 0).toBeGreaterThan(20);
    expect(c.stroke ?? 0).toBeGreaterThan(0);
  });
});

describe('slider wiring', () => {
  it('reflects slider input into the readout', () => {
    const slider = $<HTMLInputElement>('#sk-slider');
    slider.value = '2048';
    slider.dispatchEvent(new Event('input'));
    expect(text('#sk-value')).toBe('2048');
  });
});

describe('Attack 1 — CPA button recovers the key into the panel', () => {
  it('shows a recovered/best-correlation result after running CPA', async () => {
    // Pin a known secret so the panel can assert recovery.
    const sk = $<HTMLInputElement>('#sk-slider');
    sk.value = '1234';
    sk.dispatchEvent(new Event('input'));
    $<HTMLButtonElement>('#generate-traces-btn').click();
    await waitFor(() => text('#cpa-results').includes('Traces generated'));

    $<HTMLButtonElement>('#run-cpa-btn').click();
    await waitFor(() => /Best correlation/.test(text('#cpa-results')));
    expect(text('#cpa-results')).toContain('sk[0] = 1234');
    expect(text('#cpa-results')).toContain('RECOVERED');
    // The correlation plot was actually drawn (line + the true-key spike).
    const c = drawCalls('#cpa-canvas');
    expect(c.lineTo ?? 0).toBeGreaterThan(0);
    expect(c.stroke ?? 0).toBeGreaterThan(0);
  }, 30000);
});

describe('Attack 2 — signing + recovery panels', () => {
  it('normal signing reports accepted attempts', async () => {
    $<HTMLButtonElement>('#normal-sign-btn').click();
    await waitFor(() => /accepted/.test(text('#normal-log')));
    expect(text('#normal-log')).toMatch(/of 300 attempts accepted/);
  }, 30000);

  it('faulted signing reports leaked signatures and draws the histogram', async () => {
    $<HTMLButtonElement>('#faulted-sign-btn').click();
    await waitFor(() => /released signatures/.test(text('#faulted-log')));
    expect(text('#faulted-log')).toMatch(/exceed the/);
    // Distribution histogram bars were rendered.
    expect(drawCalls('#rejection-canvas').fillRect ?? 0).toBeGreaterThan(0);
  }, 30000);

  it('key recovery reports a recovery rate', async () => {
    $<HTMLButtonElement>('#recover-btn').click();
    await waitFor(() => /Recovery rate/.test(text('#recovery-panel')), 60000);
    expect(text('#recovery-panel')).toMatch(/secret coefficients exactly recovered/);
  }, 60000);
});

describe('Attack 3 — timing buttons update the report', () => {
  it('running the constant-time experiment fills the panel and redraws the chart', async () => {
    const before = drawCalls('#timing-canvas').lineTo ?? 0;
    $<HTMLButtonElement>('#run-constant-btn').click();
    await waitFor(() => /Constant-time/.test(text('#timing-results')), 30000);
    expect(text('#timing-results')).toMatch(/gap =/);
    // The timing overlay was re-rendered with the measured series.
    expect(drawCalls('#timing-canvas').lineTo ?? 0).toBeGreaterThan(before);
  }, 30000);
});

describe('Attack 4 — KECCAK button reports a recovery', () => {
  it('running the simulation recovers s1 into the panel and draws both sponge states', async () => {
    $<HTMLButtonElement>('#run-keccak-btn').click();
    await waitFor(() => /Recovered s/.test(text('#keccak-results')));
    expect(text('#keccak-results')).toContain('match found');
    // 5×5 lane grid for both runs (fillRect) plus the two titles (fillText).
    const c = drawCalls('#keccak-canvas');
    expect(c.fillRect ?? 0).toBeGreaterThan(40);
    expect(c.fillText ?? 0).toBeGreaterThan(0);
  }, 30000);
});

describe('theme toggle', () => {
  it('flips the document theme attribute', () => {
    const before = document.documentElement.getAttribute('data-theme') ?? 'dark';
    $<HTMLButtonElement>('#theme-toggle').click();
    const after = document.documentElement.getAttribute('data-theme');
    expect(after).not.toBe(before);
  });
});

describe('accessibility (axe-core regression guard)', () => {
  it('the populated exhibit markup has no structural a11y violations', async () => {
    // jsdom has no layout, so color-contrast/region rules can't run here — those
    // are covered by the browser-based audit. This guards the structural rules
    // (labels, roles, names, list/heading structure) against regressions.
    const axe = (await import('axe-core')).default;
    const results = await axe.run(document.body, {
      resultTypes: ['violations'],
      rules: {
        'color-contrast': { enabled: false },
        region: { enabled: false },
      },
    });
    const summary = results.violations.map((v) => `${v.id} (${v.nodes.length})`);
    expect(summary).toEqual([]);
  }, 30000);
});
