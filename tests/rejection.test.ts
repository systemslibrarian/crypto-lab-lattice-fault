import { describe, expect, it } from 'vitest';
import {
  ML_DSA_PARAMS,
  recoverFromFaultySignatures,
  rejectionCheck,
  sampleNonce,
  signWithFaultedRejection,
  signWithRejection,
} from '../src/rejection';
import { randomIntInclusive } from '../src/random';

const bound = ML_DSA_PARAMS.gamma1 - ML_DSA_PARAMS.beta;

function freshSecret(): Int32Array {
  return new Int32Array(
    Array.from({ length: 256 }, () =>
      randomIntInclusive(-ML_DSA_PARAMS.eta, ML_DSA_PARAMS.eta),
    ),
  );
}

function freshChallenge(): Int32Array {
  return new Int32Array(
    Array.from({ length: 256 }, () => (randomIntInclusive(0, 1) === 0 ? -1 : 1)),
  );
}

describe('rejectionCheck', () => {
  it('accepts a vector strictly under the bound', () => {
    const z = new Int32Array([0, 10, -10, bound - 1]);
    const result = rejectionCheck(z, ML_DSA_PARAMS);
    expect(result.accepted).toBe(true);
    expect(result.violatingIndex).toBeNull();
    expect(result.maxCoeff).toBe(bound - 1);
  });

  it('rejects and reports the first coefficient at or over the bound', () => {
    const z = new Int32Array([0, bound, 5]);
    const result = rejectionCheck(z, ML_DSA_PARAMS);
    expect(result.accepted).toBe(false);
    expect(result.violatingIndex).toBe(1);
  });
});

describe('sampleNonce', () => {
  it('produces 256 coefficients inside the nonce range', async () => {
    const y = await sampleNonce(ML_DSA_PARAMS.gamma1);
    expect(y).toHaveLength(256);
    for (const value of y) {
      expect(value).toBeGreaterThanOrEqual(-(ML_DSA_PARAMS.gamma1 - 1));
      expect(value).toBeLessThanOrEqual(ML_DSA_PARAMS.gamma1);
    }
  });
});

describe('normal signing (Attack 2 baseline)', () => {
  it('only ever marks coefficients under the bound as accepted', async () => {
    const secret = freshSecret();
    const challenge = freshChallenge();
    const entries = await signWithRejection(secret, challenge, ML_DSA_PARAMS, 300);
    expect(entries).toHaveLength(300);
    for (const entry of entries) {
      if (entry.status === 'accepted') {
        expect(entry.maxCoeff).toBeLessThan(bound);
      }
    }
  });
});

describe('faulted signing + key recovery (Attack 2)', () => {
  it('releases signatures that a correct signer would reject', async () => {
    const secret = freshSecret();
    const challenge = freshChallenge();
    const entries = await signWithFaultedRejection(secret, challenge, ML_DSA_PARAMS, 300);
    const leaked = entries.filter((entry) => entry.wouldReject).length;
    // The whole point of the fault: a meaningful fraction spill past the bound.
    expect(leaked).toBeGreaterThan(0);
  });

  it('recovers the secret far better than random guessing', async () => {
    const secret = freshSecret();
    const challenge = freshChallenge();
    const entries = await signWithFaultedRejection(secret, challenge, ML_DSA_PARAMS, 8000);
    const recovery = recoverFromFaultySignatures(
      entries.map((entry) => entry.z),
      Array.from({ length: entries.length }, () => challenge),
      ML_DSA_PARAMS,
    );

    let correct = 0;
    for (let i = 0; i < secret.length; i += 1) {
      if (recovery.recovered[i] === secret[i]) {
        correct += 1;
      }
    }
    const rate = correct / secret.length;
    // Random guessing over {-2..2} is ~20%; the attack should clear 60%.
    expect(rate).toBeGreaterThan(0.6);
    for (const c of recovery.confidence) {
      expect(c).toBeGreaterThanOrEqual(0);
      expect(c).toBeLessThanOrEqual(1);
    }
  });

  it('rejects mismatched signature/challenge counts', () => {
    expect(() =>
      recoverFromFaultySignatures([new Int32Array(4)], [], ML_DSA_PARAMS),
    ).toThrow();
  });
});
