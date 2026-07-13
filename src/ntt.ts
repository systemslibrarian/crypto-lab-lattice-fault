import { randomNormal } from './random';

/**
 * Number Theoretic Transform for ML-KEM (q = 3329).
 * All arithmetic exact integers mod q.
 */
export const Q = 3329;
export const N = 256;

const ROOT = 17;
const ROOT_INV = 1175;
const N_INV = 3316;

function modQ(value: number): number {
  const reduced = value % Q;
  return reduced < 0 ? reduced + Q : reduced;
}

function modPow(base: number, exponent: number): number {
  let result = 1;
  let factor = modQ(base);
  let power = exponent;

  while (power > 0) {
    if ((power & 1) === 1) {
      result = modQ(result * factor);
    }
    factor = modQ(factor * factor);
    power >>= 1;
  }

  return result;
}

function bitReverse(value: number, bits: number): number {
  let reversed = 0;
  for (let i = 0; i < bits; i += 1) {
    reversed = (reversed << 1) | ((value >> i) & 1);
  }
  return reversed;
}

function bitReverseCopy(poly: Int32Array): Int32Array {
  const out = new Int32Array(poly.length);
  const bits = Math.log2(poly.length);

  for (let i = 0; i < poly.length; i += 1) {
    out[bitReverse(i, bits)] = modQ(poly[i] ?? 0);
  }

  return out;
}

/**
 * Barrett reduction: fast mod q using precomputed factor.
 * Used in NTT butterfly operations.
 */
export function barrettReduce(a: number): number {
  const v = Math.floor((1 << 26) / Q + 0.5);
  const t = Math.floor((v * a + (1 << 25)) / (1 << 26)) * Q;
  return modQ(a - t);
}

/**
 * Montgomery form multiplication mod q.
 * Used in NTT to avoid repeated mod operations.
 */
export function montgomeryReduce(a: number): number {
  const qInv = 62209;
  const u = (a * qInv) & 0xffff;
  const t = (a + u * Q) >>> 16;
  return modQ(t);
}

/**
 * NTT butterfly operation: the core leaky computation.
 * Returns { a_out, b_out, intermediates }
 * intermediates: all values computed during the butterfly
 * (these are what leak through Hamming weight)
 */
export function nttButterfly(
  a: number,
  b: number,
  zeta: number,
): {
  a_out: number;
  b_out: number;
  intermediates: number[];
} {
  const wB = zeta * b;
  const plus = a + wB;
  const minus = a - wB;

  return {
    a_out: barrettReduce(plus),
    b_out: barrettReduce(minus),
    intermediates: [wB, plus, minus],
  };
}

/**
 * Hamming weight: number of 1 bits in value.
 * This is the leakage model for power analysis.
 */
export function hammingWeight(v: number): number {
  let x = Math.abs(Math.trunc(v)) >>> 0;
  let count = 0;
  while (x > 0) {
    count += x & 1;
    x >>>= 1;
  }
  return count;
}

const ZETAS = Array.from({ length: N }, (_, i) => modPow(ROOT, i));

function nttCore(poly: Int32Array, rootTable: number[]): Int32Array {
  const arr = bitReverseCopy(poly);

  for (let len = 2; len <= arr.length; len <<= 1) {
    const half = len >> 1;
    const step = N / len;

    for (let start = 0; start < arr.length; start += len) {
      for (let j = 0; j < half; j += 1) {
        const twiddle = rootTable[j * step] ?? 1;
        const u = arr[start + j] ?? 0;
        const v = arr[start + j + half] ?? 0;
        const t = barrettReduce(twiddle * v);
        arr[start + j] = barrettReduce(u + t);
        arr[start + j + half] = barrettReduce(u - t);
      }
    }
  }

  return arr;
}

/**
 * NTT forward transform.
 * Input: polynomial coefficients in Z_q^256
 * Output: NTT representation
 * Uses standard Cooley-Tukey butterfly with precomputed zeta values.
 */
export function nttForward(poly: Int32Array): Int32Array {
  if (poly.length !== N) {
    throw new Error(`Expected polynomial length ${N}`);
  }

  return nttCore(poly, ZETAS);
}

/**
 * NTT inverse transform.
 */
export function nttInverse(poly: Int32Array): Int32Array {
  if (poly.length !== N) {
    throw new Error(`Expected polynomial length ${N}`);
  }

  const inverseRoots = Array.from({ length: N }, (_, i) => modPow(ROOT_INV, i));
  const arr = nttCore(poly, inverseRoots);

  for (let i = 0; i < arr.length; i += 1) {
    arr[i] = barrettReduce(arr[i] * N_INV);
  }

  return arr;
}

/** One butterfly's worth of the leakage sequence, tagged so the UI can render a
 * card per stage and map trace sample i → stage floor(i/3), intermediate i%3. */
export type LeakageStage = {
  zeta: number;
  wB: number;
  plus: number;
  minus: number;
  /** Hamming weights of [wB, plus, minus] — the exact numbers the trace leaks. */
  weights: [number, number, number];
};

/**
 * The per-stage leakage breakdown behind simulatePowerTrace / hammingWeightCurve.
 * Stage s contributes samples 3s, 3s+1, 3s+2 to the trace (w·b, a+wb, a−wb), so
 * the UI can highlight the exact butterfly card a hovered sample came from.
 */
export function leakageStages(secretCoeff: number, cipherCoeff: number): LeakageStage[] {
  const state = new Int32Array([
    modQ(secretCoeff),
    modQ(cipherCoeff),
    modQ(secretCoeff + cipherCoeff),
    modQ(secretCoeff + 2 * cipherCoeff),
    modQ(2 * secretCoeff + cipherCoeff),
    modQ(3 * secretCoeff + cipherCoeff),
    modQ(secretCoeff + 3 * cipherCoeff),
    modQ(2 * secretCoeff + 3 * cipherCoeff),
  ]);
  const stageZetas = [17, 3312, 2761, 568, 583, 2746, 2649, 680];
  const stages: LeakageStage[] = [];

  for (let len = 4; len >= 1; len >>= 1) {
    for (let start = 0; start < state.length; start += len * 2) {
      for (let j = 0; j < len; j += 1) {
        const idx = start + j;
        const zeta = stageZetas[(idx + len + j) % stageZetas.length] ?? 17;
        const result = nttButterfly(state[idx] ?? 0, state[idx + len] ?? 0, zeta);
        state[idx] = result.a_out;
        state[idx + len] = result.b_out;
        const [wB, plus, minus] = result.intermediates as [number, number, number];
        stages.push({
          zeta,
          wB,
          plus,
          minus,
          weights: [hammingWeight(wB), hammingWeight(plus), hammingWeight(minus)],
        });
      }
    }
  }

  return stages;
}

function leakageSequence(secretCoeff: number, cipherCoeff: number): number[] {
  const state = new Int32Array([
    modQ(secretCoeff),
    modQ(cipherCoeff),
    modQ(secretCoeff + cipherCoeff),
    modQ(secretCoeff + 2 * cipherCoeff),
    modQ(2 * secretCoeff + cipherCoeff),
    modQ(3 * secretCoeff + cipherCoeff),
    modQ(secretCoeff + 3 * cipherCoeff),
    modQ(2 * secretCoeff + 3 * cipherCoeff),
  ]);

  const traceIntermediates: number[] = [];
  const stageZetas = [17, 3312, 2761, 568, 583, 2746, 2649, 680];

  for (let len = 4; len >= 1; len >>= 1) {
    for (let start = 0; start < state.length; start += len * 2) {
      for (let j = 0; j < len; j += 1) {
        const idx = start + j;
        const zeta = stageZetas[(idx + len + j) % stageZetas.length] ?? 17;
        const result = nttButterfly(state[idx] ?? 0, state[idx + len] ?? 0, zeta);
        state[idx] = result.a_out;
        state[idx + len] = result.b_out;
        traceIntermediates.push(...result.intermediates);
      }
    }
  }

  return traceIntermediates;
}

/**
 * The noise-free leakage the chip WOULD draw for this (secret, cipher) pair:
 * exactly hammingWeight(intermediate)·0.1 at every sample, with no Gaussian
 * noise added. This is the "true" signal the power trace wiggles around — the
 * quantity a CPA attack is trying to correlate against. The UI overlays this
 * curve under the noisy trace so "power = Hamming weight + noise" is *seen*.
 *
 * Same leakage model and scaling as simulatePowerTrace, minus randomNormal.
 */
export function hammingWeightCurve(secretCoeff: number, cipherCoeff: number): Float64Array {
  const intermediates = leakageSequence(secretCoeff, cipherCoeff);
  const curve = new Float64Array(intermediates.length);
  for (let i = 0; i < intermediates.length; i += 1) {
    curve[i] = hammingWeight(intermediates[i] ?? 0) * 0.1;
  }
  return curve;
}

/**
 * Generate simulated power trace for NTT computation.
 * trace[i] = hammingWeight(intermediate_value[i]) + Gaussian_noise(σ)
 * Uses crypto.getRandomValues for noise generation.
 *
 * secretCoeff: one coefficient of the secret key polynomial
 * cipherCoeff: one coefficient of the ciphertext polynomial
 * noiseLevel: standard deviation of Gaussian noise (default 0.5)
 */
export async function simulatePowerTrace(
  secretCoeff: number,
  cipherCoeff: number,
  noiseLevel = 0.5,
): Promise<Float64Array> {
  const intermediates = leakageSequence(secretCoeff, cipherCoeff);
  const trace = new Float64Array(intermediates.length);

  for (let i = 0; i < intermediates.length; i += 1) {
    const leakage = hammingWeight(intermediates[i] ?? 0) * 0.1;
    trace[i] = leakage + randomNormal(noiseLevel);
  }

  return trace;
}

function pearson(xs: number[], ys: number[]): number {
  const n = xs.length;
  if (n === 0 || ys.length !== n) {
    return 0;
  }

  let sumX = 0;
  let sumY = 0;
  let sumXY = 0;
  let sumXX = 0;
  let sumYY = 0;

  for (let i = 0; i < n; i += 1) {
    const x = xs[i] ?? 0;
    const y = ys[i] ?? 0;
    sumX += x;
    sumY += y;
    sumXY += x * y;
    sumXX += x * x;
    sumYY += y * y;
  }

  const numerator = n * sumXY - sumX * sumY;
  const denomLeft = n * sumXX - sumX * sumX;
  const denomRight = n * sumYY - sumY * sumY;
  const denominator = Math.sqrt(Math.max(denomLeft * denomRight, 0));

  return denominator === 0 ? 0 : numerator / denominator;
}

/**
 * Correlation Power Analysis.
 * traces: N_traces × trace_length matrix of power measurements
 * For each key hypothesis k (0 to q-1):
 *   hypothetical_power[i] = hammingWeight(ntt_intermediate(ct[i], k))
 *   correlation[k] = pearson(hypothetical_power, traces_column)
 *
 * Returns correlation scores for each key hypothesis.
 * Correct key hypothesis has highest absolute correlation.
 */
/**
 * Correlation-vs-trace-count growth curve for the "why this works" strip.
 *
 * At each checkpoint we run the SAME CPA over only the first `n` traces and
 * record two numbers: the |correlation| the attack assigns to the TRUE secret,
 * and the largest |correlation| any WRONG hypothesis reaches (the noise floor).
 * With few traces the noise floor rides high and can even overtake the truth;
 * as traces accumulate the noise averages down and the true key pulls clear.
 *
 * Nothing here is faked — it is the real Pearson correlation on real simulated
 * traces, just evaluated at growing prefixes so the learner sees SNR improve.
 */
export function cpaCorrelationGrowth(
  traces: Float64Array[],
  ciphertextCoeffs: number[],
  secretKey: number,
  targetIndex: number,
  checkpoints = 14,
): { counts: number[]; trueScores: number[]; noiseFloor: number[] } {
  const total = traces.length;
  const counts: number[] = [];
  const trueScores: number[] = [];
  const noiseFloor: number[] = [];
  if (total === 0) {
    return { counts, trueScores, noiseFloor };
  }

  for (let step = 1; step <= checkpoints; step += 1) {
    const n = Math.max(2, Math.round((total * step) / checkpoints));
    const scores = correlationPowerAnalysis(
      traces.slice(0, n),
      ciphertextCoeffs.slice(0, n),
      targetIndex,
    );
    const trueScore = Math.abs(scores[secretKey] ?? 0);
    let floor = 0;
    for (let k = 0; k < scores.length; k += 1) {
      if (k === secretKey) continue;
      const m = Math.abs(scores[k] ?? 0);
      if (m > floor) floor = m;
    }
    counts.push(n);
    trueScores.push(trueScore);
    noiseFloor.push(floor);
  }

  return { counts, trueScores, noiseFloor };
}

export function correlationPowerAnalysis(
  traces: Float64Array[],
  ciphertextCoeffs: number[],
  targetIndex: number,
): Float64Array {
  if (traces.length === 0 || traces.length !== ciphertextCoeffs.length) {
    throw new Error('Trace count must match ciphertext count');
  }

  const correlations = new Float64Array(Q);
  const window = [targetIndex - 1, targetIndex, targetIndex + 1].filter((index) => index >= 0);

  for (let k = 0; k < Q; k += 1) {
    let combinedScore = 0;

    for (const sampleIndex of window) {
      const actualColumn = traces.map((trace) => trace[sampleIndex] ?? 0);
      const hypothetical = ciphertextCoeffs.map((ct) => {
        const sequence = leakageSequence(k, ct);
        return hammingWeight(sequence[sampleIndex] ?? 0) * 0.1;
      });
      combinedScore += pearson(hypothetical, actualColumn);
    }

    correlations[k] = combinedScore / window.length;
  }

  return correlations;
}
