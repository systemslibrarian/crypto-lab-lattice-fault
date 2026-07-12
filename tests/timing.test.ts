import { describe, expect, it } from 'vitest';
import { Q } from '../src/ntt';
import {
  decodeMessageBitConstantTime,
  decodeMessageBitVulnerable,
  measureDecodingTime,
  runClusterExperiment,
  softwareDivideCycles,
  timingExperiment,
} from '../src/timing';

describe('message-bit decoding (KyberSlash, Attack 3)', () => {
  it('the constant-time decoder agrees with the vulnerable one on every coefficient', () => {
    for (let v = 0; v < Q; v += 1) {
      expect(decodeMessageBitConstantTime(v)).toBe(decodeMessageBitVulnerable(v));
    }
  });

  it('decodes to a clean 0/1 bit', () => {
    for (let v = 0; v < Q; v += 13) {
      const bit = decodeMessageBitVulnerable(v);
      expect(bit === 0 || bit === 1).toBe(true);
    }
  });
});

describe('measureDecodingTime', () => {
  it('reports finite, non-negative timing statistics', async () => {
    const result = await measureDecodingTime(1500, 'vulnerable', 4);
    expect(result.samples).toHaveLength(4);
    expect(Number.isFinite(result.meanUs)).toBe(true);
    expect(result.meanUs).toBeGreaterThanOrEqual(0);
    expect(result.stdUs).toBeGreaterThanOrEqual(0);
  });
});

describe('softwareDivideCycles (the real KyberSlash mechanism)', () => {
  it('cycle count grows with the (secret-dependent) dividend once it exceeds the divisor', () => {
    // A larger dividend has more significant bits ⇒ more shift-subtract steps.
    // (Below the divisor the divide is trivially one step, as in real hardware.)
    const q = 3329;
    const small = softwareDivideCycles(q * 2, q);
    const large = softwareDivideCycles(q * 200, q);
    expect(large).toBeGreaterThan(small);
    expect(small).toBeGreaterThan(0);
  });
});

describe('runClusterExperiment (two-cluster leak / constant-time collapse)', () => {
  it('vulnerable divide separates the two secret classes', () => {
    const exp = runClusterExperiment('vulnerable', 500);
    expect(exp.small).toHaveLength(500);
    expect(exp.large).toHaveLength(500);
    expect(exp.meanLarge).toBeGreaterThan(exp.meanSmall);
    expect(exp.separated).toBe(true);
  });

  it('constant-time divide collapses both classes onto one value (no leak)', () => {
    const exp = runClusterExperiment('constant-time', 500);
    expect(exp.meanSmall).toBe(exp.meanLarge);
    expect(exp.separated).toBe(false);
  });
});

describe('timingExperiment', () => {
  it('produces one timing per coefficient and finite class means', async () => {
    const result = await timingExperiment('constant-time', 2);
    expect(result.timings).toHaveLength(Q);
    expect(Number.isFinite(result.mean0)).toBe(true);
    expect(Number.isFinite(result.mean1)).toBe(true);
    expect(Number.isFinite(result.difference)).toBe(true);
  });
});
