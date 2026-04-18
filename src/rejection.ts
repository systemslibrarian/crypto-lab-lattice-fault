import { N } from './ntt';
import { randomIntInclusive } from './random';

/**
 * ML-DSA rejection sampling parameters (FIPS 204).
 * Using Dilithium-2 (ML-DSA-44) parameters.
 */
export const ML_DSA_PARAMS = {
  q: 8380417,
  gamma1: 1 << 17,
  gamma2: (8380417 - 1) / 88,
  beta: 78,
  tau: 49,
  eta: 2,
  omega: 80,
} as const;

const SECRET_INFLUENCE = 2560;

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function computeZ(secretKey: Int32Array, challenge: Int32Array, y: Int32Array): Int32Array {
  const z = new Int32Array(secretKey.length);

  for (let i = 0; i < secretKey.length; i += 1) {
    const c = challenge[i] ?? 0;
    const s = secretKey[i] ?? 0;
    const nonce = y[i] ?? 0;
    z[i] = nonce + c * s * SECRET_INFLUENCE;
  }

  return z;
}

/**
 * Sample a random nonce polynomial y.
 * Each coefficient in range [-(γ₁-1), γ₁] (uniform).
 */
export async function sampleNonce(gamma1: number): Promise<Int32Array> {
  const out = new Int32Array(N);

  for (let i = 0; i < N; i += 1) {
    out[i] = randomIntInclusive(-(gamma1 - 1), gamma1);
  }

  return out;
}

/**
 * Rejection sampling check on z = y + cs₁.
 * Returns true (accept) if all conditions pass.
 * Returns false (reject/abort) if any coefficient is too large.
 *
 * Conditions:
 *   max|z_i| < γ₁ - β
 *   (hint vector weight ≤ ω — simplified here)
 */
export function rejectionCheck(
  z: Int32Array,
  params: typeof ML_DSA_PARAMS,
): { accepted: boolean; maxCoeff: number; violatingIndex: number | null } {
  let maxCoeff = 0;
  let violatingIndex: number | null = null;

  for (let i = 0; i < z.length; i += 1) {
    const absolute = Math.abs(z[i] ?? 0);
    if (absolute > maxCoeff) {
      maxCoeff = absolute;
    }
    if (absolute >= params.gamma1 - params.beta && violatingIndex === null) {
      violatingIndex = i;
    }
  }

  return {
    accepted: violatingIndex === null,
    maxCoeff,
    violatingIndex,
  };
}

/**
 * Simulate signing with rejection sampling intact.
 * Returns array of (z, status) pairs.
 * status: 'accepted' | 'rejected'
 */
export async function signWithRejection(
  secretKey: Int32Array,
  challenge: Int32Array,
  params: typeof ML_DSA_PARAMS,
  numAttempts: number,
): Promise<Array<{
  y: Int32Array;
  z: Int32Array;
  status: 'accepted' | 'rejected';
  maxCoeff: number;
}>> {
  const attempts: Array<{
    y: Int32Array;
    z: Int32Array;
    status: 'accepted' | 'rejected';
    maxCoeff: number;
  }> = [];

  for (let i = 0; i < numAttempts; i += 1) {
    const y = await sampleNonce(params.gamma1);
    const z = computeZ(secretKey, challenge, y);
    const check = rejectionCheck(z, params);

    attempts.push({
      y,
      z,
      status: check.accepted ? 'accepted' : 'rejected',
      maxCoeff: check.maxCoeff,
    });
  }

  return attempts;
}

/**
 * Simulate signing WITH rejection bypass (fault injected).
 * rejection check is skipped — returns z even when too large.
 */
export async function signWithFaultedRejection(
  secretKey: Int32Array,
  challenge: Int32Array,
  params: typeof ML_DSA_PARAMS,
  numSignatures: number,
): Promise<Array<{
  y: Int32Array;
  z: Int32Array;
  maxCoeff: number;
  faulted: boolean;
}>> {
  const outputs: Array<{
    y: Int32Array;
    z: Int32Array;
    maxCoeff: number;
    faulted: boolean;
  }> = [];

  let attempts = 0;
  const maxAttempts = Math.max(numSignatures * 64, 512);

  while (outputs.length < numSignatures && attempts < maxAttempts) {
    attempts += 1;
    const y = await sampleNonce(params.gamma1);
    const z = computeZ(secretKey, challenge, y);
    const check = rejectionCheck(z, params);

    if (check.accepted) {
      continue;
    }

    outputs.push({
      y,
      z,
      maxCoeff: check.maxCoeff,
      faulted: true,
    });
  }

  return outputs;
}

/**
 * Key recovery from faulty signatures.
 * Given k faulty signatures where rejection was bypassed:
 * For each i: z_i = y_i + c·s₁_i
 * Since y_i is random and c·s₁_i is small, the distribution of z_i
 * is shifted — the mean reveals c·s₁_i.
 *
 * Simplified recovery: with enough signatures, the mode of (z - E[y])
 * reveals c·s₁ coefficient-wise.
 * Returns recovered estimate of s₁.
 */
export function recoverFromFaultySignatures(
  faultySignatures: Int32Array[],
  challenges: Int32Array[],
  params: typeof ML_DSA_PARAMS,
): { recovered: Int32Array; confidence: number[] } {
  if (faultySignatures.length === 0 || faultySignatures.length !== challenges.length) {
    throw new Error('Faulty signatures and challenges must have the same non-zero length');
  }

  const width = faultySignatures[0]?.length ?? N;
  const recovered = new Int32Array(width);
  const confidence = new Array<number>(width).fill(0);

  for (let coeffIndex = 0; coeffIndex < width; coeffIndex += 1) {
    let weightedSum = 0;
    let observations = 0;

    for (let sigIndex = 0; sigIndex < faultySignatures.length; sigIndex += 1) {
      const z = faultySignatures[sigIndex]?.[coeffIndex] ?? 0;
      const c = challenges[sigIndex]?.[coeffIndex] ?? 0;
      if (c === 0) {
        continue;
      }
      weightedSum += z * c;
      observations += Math.abs(c);
    }

    const estimate = observations === 0 ? 0 : weightedSum / observations / SECRET_INFLUENCE;
    const rounded = clamp(Math.round(estimate), -params.eta, params.eta);
    recovered[coeffIndex] = rounded;
    const residual = Math.abs(estimate - rounded);
    confidence[coeffIndex] = Math.max(0, Math.min(1, 1 - residual / (params.eta + 0.5)));
  }

  return { recovered, confidence };
}
