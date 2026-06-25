import { describe, expect, it } from 'vitest';
import {
  Q,
  N,
  barrettReduce,
  correlationPowerAnalysis,
  hammingWeight,
  montgomeryReduce,
  nttButterfly,
  nttForward,
  nttInverse,
  simulatePowerTrace,
} from '../src/ntt';

const mod = (value: number): number => ((value % Q) + Q) % Q;

describe('hammingWeight', () => {
  it('counts set bits', () => {
    expect(hammingWeight(0)).toBe(0);
    expect(hammingWeight(1)).toBe(1);
    expect(hammingWeight(0b1011)).toBe(3);
    expect(hammingWeight(0xff)).toBe(8);
  });

  it('uses magnitude for negative and fractional inputs', () => {
    expect(hammingWeight(-7)).toBe(hammingWeight(7));
    expect(hammingWeight(5.9)).toBe(hammingWeight(5));
  });
});

describe('modular reductions', () => {
  it('barrettReduce matches a mod q across the working range', () => {
    for (let a = -5000; a < 50000; a += 7) {
      expect(barrettReduce(a)).toBe(mod(a));
    }
  });

  it('montgomeryReduce lands in [0, q)', () => {
    for (let a = 0; a < 100000; a += 137) {
      const r = montgomeryReduce(a);
      expect(r).toBeGreaterThanOrEqual(0);
      expect(r).toBeLessThan(Q);
    }
  });
});

describe('nttButterfly', () => {
  it('returns reduced outputs and the three leaking intermediates', () => {
    const { a_out, b_out, intermediates } = nttButterfly(1234, 567, 17);
    expect(intermediates).toHaveLength(3);
    expect(intermediates[0]).toBe(17 * 567); // w·b, unreduced (this is what leaks)
    expect(a_out).toBe(mod(1234 + 17 * 567));
    expect(b_out).toBe(mod(1234 - 17 * 567));
  });
});

describe('NTT transform', () => {
  it('forward then inverse is the identity on Z_q^256', () => {
    const poly = new Int32Array(N);
    for (let i = 0; i < N; i += 1) {
      poly[i] = (i * 7 + 3) % Q;
    }
    const round = nttInverse(nttForward(poly));
    for (let i = 0; i < N; i += 1) {
      expect(mod(round[i]!)).toBe(poly[i]);
    }
  });

  it('rejects polynomials of the wrong length', () => {
    expect(() => nttForward(new Int32Array(128))).toThrow();
    expect(() => nttInverse(new Int32Array(255))).toThrow();
  });
});

describe('CPA attack (Attack 1)', () => {
  it('recovers the secret coefficient as the top hypothesis', async () => {
    const secret = 1234;
    const base = 567;
    const noise = 0.5;
    const count = 150;
    const ciphertexts = Array.from({ length: count }, (_, i) => (base + i * 37) % Q);
    const traces: Float64Array[] = [];
    for (const ct of ciphertexts) {
      traces.push(await simulatePowerTrace(secret, ct, noise));
    }

    const scores = correlationPowerAnalysis(traces, ciphertexts, 1);

    let bestKey = 0;
    let bestScore = -1;
    for (let k = 0; k < scores.length; k += 1) {
      const magnitude = Math.abs(scores[k]!);
      if (magnitude > bestScore) {
        bestScore = magnitude;
        bestKey = k;
      }
    }

    expect(bestKey).toBe(secret);
  });

  it('rejects mismatched trace/ciphertext counts', () => {
    expect(() =>
      correlationPowerAnalysis([new Float64Array(3)], [1, 2], 1),
    ).toThrow();
  });
});
