import { describe, expect, it } from 'vitest';
import { shake256 } from '../src/shake256';
import {
  EMBED_B,
  EXECUTABLE_ABORT_LIMIT,
  ML_DSA_44,
  centered,
  expandMaskPoly,
  invNtt,
  ntt,
  projectionSize,
  requiredEmbeddingDimension,
  ringInverse,
  ringMul,
  runLoopAbortAttack,
  sampleInBall,
} from '../src/loopabort';

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

describe('SHAKE256 (FIPS 202)', () => {
  it('matches the published digest of the empty string', () => {
    expect(toHex(shake256(new Uint8Array(0), 32))).toBe(
      '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f',
    );
  });

  it('matches the published digest of "abc"', () => {
    expect(toHex(shake256(new TextEncoder().encode('abc'), 32))).toBe(
      '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739',
    );
  });

  it('is an extendable-output function: a longer squeeze extends the shorter one', () => {
    const short = shake256(new Uint8Array(0), 32);
    const long = shake256(new Uint8Array(0), 200);
    expect(toHex(long.subarray(0, 32))).toBe(toHex(short));
  });
});

describe('ML-DSA-44 parameters (FIPS 204, Table 1)', () => {
  it('uses the standardised values', () => {
    expect(ML_DSA_44.q).toBe(8380417);
    expect(ML_DSA_44.q).toBe(2 ** 23 - 2 ** 13 + 1);
    expect(ML_DSA_44.zeta).toBe(1753);
    expect(ML_DSA_44.gamma1).toBe(2 ** 17);
    expect(ML_DSA_44.tau).toBe(39);
    expect(ML_DSA_44.eta).toBe(2);
    expect(ML_DSA_44.beta).toBe(ML_DSA_44.tau * ML_DSA_44.eta);
    expect(ML_DSA_44.beta).toBe(78);
    expect(ML_DSA_44.ell).toBe(4);
  });

  it('ζ is a 512th root of unity mod q', () => {
    let power = 1n;
    const q = BigInt(ML_DSA_44.q);
    for (let i = 0; i < 512; i += 1) {
      power = (power * BigInt(ML_DSA_44.zeta)) % q;
    }
    expect(power).toBe(1n);
  });
});

describe('NTT (FIPS 204 Algorithms 41–42)', () => {
  it('round-trips a polynomial', () => {
    const poly = Int32Array.from({ length: 256 }, (_, i) => (i * 7919) % ML_DSA_44.q);
    const back = invNtt(ntt(poly));
    expect(Array.from(back)).toEqual(Array.from(poly));
  });

  it('multiplies in Z_q[x]/(x^256+1): x^255 · x = −1', () => {
    const a = new Int32Array(256);
    a[255] = 1;
    const b = new Int32Array(256);
    b[1] = 1;
    const product = ringMul(a, b);
    expect(centered(product[0]!)).toBe(-1);
    for (let i = 1; i < 256; i += 1) {
      expect(product[i]).toBe(0);
    }
  });

  it('inverts a challenge polynomial: c · c⁻¹ = 1', () => {
    const c = sampleInBall(new Uint8Array(32).fill(7));
    const inverse = ringInverse(c);
    expect(inverse).not.toBeNull();
    const product = ringMul(c, inverse!);
    expect(product[0]).toBe(1);
    for (let i = 1; i < 256; i += 1) {
      expect(product[i]).toBe(0);
    }
  });
});

describe('SampleInBall (FIPS 204 Algorithm 29)', () => {
  it('produces exactly τ coefficients in {−1, +1} and the rest zero', () => {
    const c = sampleInBall(new Uint8Array(32).fill(3));
    const nonzero = Array.from(c).filter((value) => value !== 0);
    expect(nonzero).toHaveLength(ML_DSA_44.tau);
    expect(nonzero.every((value) => value === 1 || value === -1)).toBe(true);
  });

  it('is deterministic in its seed', () => {
    const seed = new Uint8Array(32).fill(11);
    expect(Array.from(sampleInBall(seed))).toEqual(Array.from(sampleInBall(seed)));
  });
});

describe('ExpandMask (FIPS 204 Algorithm 34) under a loop-abort fault', () => {
  const rho = new Uint8Array(64).fill(5);

  it('an unfaulted run fills every coefficient inside [−γ1+1, γ1]', () => {
    const y = expandMaskPoly(rho, 0);
    expect(y).toHaveLength(256);
    for (const value of y) {
      expect(value).toBeGreaterThanOrEqual(-ML_DSA_44.gamma1 + 1);
      expect(value).toBeLessThanOrEqual(ML_DSA_44.gamma1);
    }
  });

  it('aborting after m iterations leaves the tail at the buffer value (zero)', () => {
    const m = 12;
    const full = expandMaskPoly(rho, 0);
    const faulted = expandMaskPoly(rho, 0, m);
    // The coefficients that DID get generated are unchanged by the abort…
    for (let i = 0; i < m; i += 1) {
      expect(faulted[i]).toBe(full[i]);
    }
    // …and everything after the abort point is zero.
    for (let i = m; i < 256; i += 1) {
      expect(faulted[i]).toBe(0);
    }
  });
});

describe('projection sizing (Espitau et al. eq. 2)', () => {
  it('needs a dimension only slightly larger than the number of surviving coefficients', () => {
    for (const m of [4, 8, 16, 32]) {
      const dimension = requiredEmbeddingDimension(m);
      expect(dimension).toBeGreaterThan(m);
      expect(dimension).toBeLessThan(1.4 * (m + 2));
      expect(projectionSize(m)).toBeGreaterThan(m);
    }
  });

  it('a dense (unfaulted) nonce pushes the required dimension past n = 256', () => {
    expect(requiredEmbeddingDimension(256)).toBeGreaterThan(256);
  });

  it('uses the paper embedding constant B = ⌈σ⌉', () => {
    expect(EMBED_B).toBe(2);
  });
});

describe('the loop-abort attack itself', () => {
  it('recovers all 256 coefficients of s1 from ONE faulty signature', () => {
    const result = runLoopAbortAttack(6);
    expect(result.skippedReason).toBeUndefined();
    expect(result.challengeInvertible).toBe(true);
    expect(result.nonzeroY).toBeLessThanOrEqual(6);
    expect(result.recoveredCount).toBe(256);
    expect(result.success).toBe(true);
    expect(Array.from(result.recovered)).toEqual(Array.from(result.secret));
  }, 30000);

  it('still works at a later abort point', () => {
    const result = runLoopAbortAttack(16);
    expect(result.success).toBe(true);
  }, 60000);

  it('checks the real FIPS 204 rejection bound ‖z‖∞ ≥ γ1 − β', () => {
    const result = runLoopAbortAttack(6);
    expect(result.rejectionBound).toBe(ML_DSA_44.gamma1 - ML_DSA_44.beta);
    expect(result.wouldReject).toBe(result.zInfinityNorm >= result.rejectionBound);
  }, 30000);

  it('declines to run LLL past the in-browser abort limit, and says why', () => {
    const result = runLoopAbortAttack(EXECUTABLE_ABORT_LIMIT + 1);
    expect(result.skippedReason).toBeTruthy();
    expect(result.success).toBe(false);
  }, 30000);
});
