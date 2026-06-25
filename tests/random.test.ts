import { describe, expect, it } from 'vitest';
import {
  randomIntInclusive,
  randomNormal,
  randomUint32,
  randomUnit,
} from '../src/random';

describe('randomUint32', () => {
  it('stays inside the unsigned 32-bit range', () => {
    for (let i = 0; i < 1000; i += 1) {
      const value = randomUint32();
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThanOrEqual(0xffffffff);
    }
  });
});

describe('randomUnit', () => {
  it('returns values strictly inside (0, 1)', () => {
    for (let i = 0; i < 1000; i += 1) {
      const value = randomUnit();
      expect(value).toBeGreaterThan(0);
      expect(value).toBeLessThan(1);
    }
  });
});

describe('randomIntInclusive', () => {
  it('covers both endpoints and never escapes the range', () => {
    let sawMin = false;
    let sawMax = false;
    for (let i = 0; i < 5000; i += 1) {
      const value = randomIntInclusive(-2, 2);
      expect(value).toBeGreaterThanOrEqual(-2);
      expect(value).toBeLessThanOrEqual(2);
      if (value === -2) sawMin = true;
      if (value === 2) sawMax = true;
    }
    expect(sawMin).toBe(true);
    expect(sawMax).toBe(true);
  });

  it('handles a single-value range', () => {
    expect(randomIntInclusive(7, 7)).toBe(7);
  });

  it('rejects invalid ranges', () => {
    expect(() => randomIntInclusive(5, 1)).toThrow();
    expect(() => randomIntInclusive(0.5, 2)).toThrow();
  });

  it('is approximately uniform', () => {
    const counts = new Array<number>(5).fill(0);
    const draws = 50000;
    for (let i = 0; i < draws; i += 1) {
      counts[randomIntInclusive(0, 4)] += 1;
    }
    // Each bucket should be near draws/5; allow a generous ±25% band.
    const expected = draws / 5;
    for (const count of counts) {
      expect(count).toBeGreaterThan(expected * 0.75);
      expect(count).toBeLessThan(expected * 1.25);
    }
  });
});

describe('randomNormal', () => {
  it('produces a roughly zero-mean sample with the requested sigma', () => {
    const sigma = 2;
    const n = 20000;
    let sum = 0;
    let sumSq = 0;
    for (let i = 0; i < n; i += 1) {
      const value = randomNormal(sigma);
      sum += value;
      sumSq += value * value;
    }
    const mean = sum / n;
    const std = Math.sqrt(sumSq / n - mean * mean);
    expect(Math.abs(mean)).toBeLessThan(0.15);
    expect(std).toBeGreaterThan(sigma * 0.85);
    expect(std).toBeLessThan(sigma * 1.15);
  });
});
