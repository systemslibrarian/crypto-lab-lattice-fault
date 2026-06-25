import { describe, expect, it } from 'vitest';
import { Q } from '../src/ntt';
import {
  decodeMessageBitConstantTime,
  decodeMessageBitVulnerable,
  measureDecodingTime,
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

describe('timingExperiment', () => {
  it('produces one timing per coefficient and finite class means', async () => {
    const result = await timingExperiment('constant-time', 2);
    expect(result.timings).toHaveLength(Q);
    expect(Number.isFinite(result.mean0)).toBe(true);
    expect(Number.isFinite(result.mean1)).toBe(true);
    expect(Number.isFinite(result.difference)).toBe(true);
  });
});
