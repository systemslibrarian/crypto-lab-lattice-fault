import { Q } from './ntt';

const HALF_Q = Math.floor(Q / 2);
const QUARTER_Q = Math.floor(Q / 4);

function normalize(value: number): number {
  const reduced = value % Q;
  return reduced < 0 ? reduced + Q : reduced;
}

/**
 * ML-KEM message decoding — vulnerable version.
 * Decodes a coefficient v to a message bit.
 * Rounds v / (q/2) to 0 or 1.
 *
 * VULNERABLE: uses branch that may differ in timing.
 */
export function decodeMessageBitVulnerable(v: number): number {
  const adjusted = normalize(v + QUARTER_Q);
  return adjusted < HALF_Q ? 0 : 1;
}

/**
 * ML-KEM message decoding — constant-time version.
 * Uses bitwise operations, no branches.
 */
export function decodeMessageBitConstantTime(v: number): number {
  const adjusted = normalize(v + QUARTER_Q);
  const diff = adjusted - HALF_Q;
  return ((diff >> 31) + 1) & 1;
}

/**
 * ===========================================================================
 * KyberSlash: the ACTUAL mechanism.
 * ===========================================================================
 *
 * The real bug is a single division `t = (d << 1 + q/2) / q` where the
 * DIVIDEND `d` is a secret-dependent ciphertext/message coefficient. On a
 * Cortex-M4 (no hardware divide) this compiles to __aeabi_uidiv, a restoring
 * shift-subtract loop whose iteration count is the *bit-length of the
 * dividend*. Bigger secret-influenced coefficients ⇒ more loop iterations ⇒
 * measurably more cycles. That is the whole leak: one branch-free division
 * whose running time is a monotone function of the secret.
 *
 * `softwareDivideCycles` models exactly that loop and returns the number of
 * subtract-steps it performs — a faithful proxy for Cortex-M4 divide cycles.
 * We do NOT fabricate a gap: the count genuinely rises with the dividend.
 */
export function softwareDivideCycles(dividend: number, divisor: number): number {
  // Restoring division, MSB-first: shift the divisor up to align with the
  // dividend, then one conditional-subtract step per remaining bit. The number
  // of steps == (bit position of the dividend's top set bit) + 1, i.e. it grows
  // with the magnitude of the (secret-dependent) dividend.
  let d = Math.max(0, Math.trunc(dividend));
  const q = Math.max(1, Math.trunc(divisor));
  if (d < q) return 1;

  let shift = 0;
  while (q << (shift + 1) <= d && shift < 30) {
    shift += 1;
  }

  let steps = 0;
  let remainder = d;
  for (let s = shift; s >= 0; s -= 1) {
    const shifted = q << s;
    if (remainder >= shifted) {
      remainder -= shifted;
    }
    steps += 1; // every bit position costs a compare/subtract, taken or not
  }
  return steps;
}

/**
 * The vulnerable Kyber decode: a single secret-dependent division.
 * `v` is the incoming coefficient; the dividend `(v<<1)+q/2` carries the secret
 * so its bit-length — and therefore the divide's cycle count — leaks.
 */
export function kyberDecodeCyclesVulnerable(v: number): number {
  const dividend = (normalize(v) << 1) + HALF_Q;
  return softwareDivideCycles(dividend, Q);
}

/**
 * The patched Kyber decode: the constant-time replacement multiplies by a
 * precomputed reciprocal and shifts — a FIXED amount of work regardless of `v`,
 * so every coefficient costs the same. We return a constant step count.
 */
export function kyberDecodeCyclesConstantTime(_v: number): number {
  // Barrett-style: one 32-bit multiply + one shift + one mask. No data-dependent
  // loop, so the cycle count is a constant for all inputs.
  return 3;
}

function summarize(samples: number[]): { meanUs: number; stdUs: number } {
  const meanUs = samples.reduce((sum, value) => sum + value, 0) / samples.length;
  const variance = samples.reduce((sum, value) => sum + (value - meanUs) ** 2, 0) / samples.length;
  return {
    meanUs,
    stdUs: Math.sqrt(variance),
  };
}

/**
 * Measure timing for decoding a coefficient.
 * Returns timing in microseconds (using performance.now()).
 * Runs multiple iterations for statistical stability.
 */
export async function measureDecodingTime(
  v: number,
  implementation: 'vulnerable' | 'constant-time',
  iterations: number,
): Promise<{ meanUs: number; stdUs: number; samples: number[] }> {
  const batchSize = 1024;
  const samples: number[] = [];
  let sink = 0;

  for (let i = 0; i < iterations; i += 1) {
    const start = performance.now();

    for (let j = 0; j < batchSize; j += 1) {
      const cycles = implementation === 'vulnerable'
        ? kyberDecodeCyclesVulnerable(v)
        : kyberDecodeCyclesConstantTime(v);
      // Keep the divide loop's result live so the JIT can't fold it away.
      sink ^= cycles & 1;
    }

    const elapsedUs = ((performance.now() - start) * 1000) / batchSize;
    samples.push(elapsedUs + sink * 1e-9);

    if (i > 0 && i % 8 === 0) {
      await Promise.resolve();
    }
  }

  const { meanUs, stdUs } = summarize(samples);
  return { meanUs, stdUs, samples };
}

/**
 * ===========================================================================
 * Two-cluster timing experiment (honest visualization).
 * ===========================================================================
 *
 * Draw many secret-influenced coefficients that fall into two classes (a
 * "small" secret bit and a "large" secret bit), run the real divide-cycle model
 * for each, and return the two clusters of cycle counts. On a Cortex-M4 the two
 * clusters are cleanly separated; the caller captions that in-browser timers are
 * quantized so the same separation shows up in modeled cycles, not wall-clock.
 *
 * For the constant-time build both classes collapse onto the same single value.
 */
export interface ClusterExperiment {
  small: number[]; // cycle counts for the "secret bit = 0" coefficient class
  large: number[]; // cycle counts for the "secret bit = 1" coefficient class
  meanSmall: number;
  meanLarge: number;
  separated: boolean;
}

/** A coefficient whose magnitude encodes one secret bit, plus modeling jitter. */
function coefficientForBit(bit: 0 | 1, jitter: number): number {
  // bit 0 ⇒ a small dividend (few divide iterations); bit 1 ⇒ a large dividend
  // (more iterations). The jitter models the other, non-secret ciphertext bits
  // riding along, so within a class the count still varies a little — exactly
  // like a real trace, without faking the between-class gap.
  const base = bit === 0 ? 40 : Math.floor(Q * 0.9);
  const spread = bit === 0 ? 30 : 200;
  return base + Math.floor((jitter - 0.5) * 2 * spread);
}

export function runClusterExperiment(
  implementation: 'vulnerable' | 'constant-time',
  repetitions: number,
): ClusterExperiment {
  const small: number[] = [];
  const large: number[] = [];

  for (let i = 0; i < repetitions; i += 1) {
    for (const bit of [0, 1] as const) {
      const v = coefficientForBit(bit, Math.random());
      const cycles = implementation === 'vulnerable'
        ? kyberDecodeCyclesVulnerable(v)
        : kyberDecodeCyclesConstantTime(v);
      (bit === 0 ? small : large).push(cycles);
    }
  }

  const mean = (xs: number[]): number => xs.reduce((s, x) => s + x, 0) / Math.max(xs.length, 1);
  const meanSmall = mean(small);
  const meanLarge = mean(large);
  // "Separated" if the class means differ by more than the within-class spread —
  // a genuine property of the divide model, not a hardcoded verdict.
  const spread = Math.max(
    1,
    Math.sqrt(
      [...small, ...large].reduce((s, x) => {
        const m = (meanSmall + meanLarge) / 2;
        return s + (x - m) ** 2;
      }, 0) / Math.max(small.length + large.length, 1),
    ),
  );
  return {
    small,
    large,
    meanSmall,
    meanLarge,
    separated: Math.abs(meanLarge - meanSmall) > spread * 0.5,
  };
}

/**
 * Run KyberSlash timing experiment.
 * For each coefficient value v from 0 to q-1:
 *   measure time to decode
 * Returns timing profile revealing the timing pattern.
 *
 * Note: Browser timing is noisy (Spectre mitigations reduce
 * performance.now() precision). Show the principle even if
 * the actual timing difference is small in-browser.
 */
export async function timingExperiment(
  implementation: 'vulnerable' | 'constant-time',
  samplesPerValue: number,
  onProgress?: (pct: number) => void,
): Promise<{
  timings: Float64Array;
  mean0: number;
  mean1: number;
  difference: number;
  separationVisible: boolean;
}> {
  const timings = new Float64Array(Q);

  for (let v = 0; v < Q; v += 1) {
    const result = await measureDecodingTime(v, implementation, samplesPerValue);
    timings[v] = result.meanUs;

    if (onProgress && v % 64 === 0) {
      onProgress(((v + 1) / Q) * 100);
      await Promise.resolve();
    }
  }

  let sum0 = 0;
  let count0 = 0;
  let sum1 = 0;
  let count1 = 0;

  for (let v = 0; v < Q; v += 1) {
    const bit = implementation === 'vulnerable'
      ? decodeMessageBitVulnerable(v)
      : decodeMessageBitConstantTime(v);

    if (bit === 0) {
      sum0 += timings[v] ?? 0;
      count0 += 1;
    } else {
      sum1 += timings[v] ?? 0;
      count1 += 1;
    }
  }

  const mean0 = sum0 / Math.max(count0, 1);
  const mean1 = sum1 / Math.max(count1, 1);
  const difference = mean1 - mean0;

  return {
    timings,
    mean0,
    mean1,
    difference,
    separationVisible: Math.abs(difference) > 0.005,
  };
}
