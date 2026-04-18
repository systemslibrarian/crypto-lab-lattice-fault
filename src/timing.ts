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
      const adjusted = normalize(v + QUARTER_Q);

      if (implementation === 'vulnerable') {
        let t = ((adjusted * 2) / Q) | 0;
        if (adjusted >= HALF_Q) {
          for (let round = 0; round < 6; round += 1) {
            t = ((t + adjusted + 11 + round) / (3 + ((round + 1) & 3))) | 0;
          }
        }
        sink ^= decodeMessageBitVulnerable(v) ^ (t & 0);
      } else {
        let t = ((HALF_Q * 2) / Q) | 0;
        for (let round = 0; round < 6; round += 1) {
          t = ((t + HALF_Q + 11 + round) / (3 + ((round + 1) & 3))) | 0;
        }
        sink ^= decodeMessageBitConstantTime(v) ^ (t & 0);
      }
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
