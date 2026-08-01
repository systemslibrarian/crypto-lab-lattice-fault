/**
 * Attack 4 — loop-abort fault on ML-DSA nonce expansion.
 *
 * The mechanism reconstructed here is the one in Espitau, Fouque, Gérard &
 * Tibouchi, "Loop-Abort Faults on Lattice-Based Fiat–Shamir and Hash-and-Sign
 * Signatures" (SAC 2016 / ePrint 2016/449), §4 "Attack on y1":
 *
 *   1. The commitment/nonce polynomial y is generated ONE COEFFICIENT AT A TIME.
 *      A fault on the loop counter (or a skipped back-jump) ends that loop after
 *      m ≪ n iterations, so y is a *low-degree* polynomial: y_0 … y_{m−1} are
 *      real samples and y_m … y_255 are still whatever the output buffer held —
 *      zero, for a zero-initialised buffer.
 *   2. The device signs anyway and releases z = y + c·s1 together with c.
 *   3. c is invertible in R_q with overwhelming probability, so
 *          c⁻¹z − s1 ≡ c⁻¹y ≡ Σ_{i<m} y_i · (c⁻¹x^i)   (mod q)          [eq. 1]
 *      i.e. v = c⁻¹z lies close to the lattice spanned by the m vectors
 *      w_i = c⁻¹x^i and qZⁿ, and the offset IS the secret s1.
 *   4. Full rank n = 256 is too big to reduce, but eq. (1) survives projection
 *      onto any index subset I. On a subset of size ℓ slightly larger than m,
 *      (φ_I(s1), B) is the shortest vector of the Kannan embedding of L_I, and
 *      LLL finds it. Cover the index range with several subsets → all of s1.
 *
 * The attacker never recomputes y and never needs to: the leverage comes from
 * y being mostly ZERO, which collapses the effective lattice dimension from 256
 * to about m. Nothing here depends on knowing the signer's private seed K, and
 * nothing here is affected by whether rnd is random (hedged) or all-zero
 * (the approved deterministic variant) — see the note in main.ts.
 *
 * Everything below is real arithmetic over the real ML-DSA-44 ring: q, γ1, τ,
 * β, η and ζ are the FIPS 204 Table 1 values, ExpandMask/SampleInBall/NTT are
 * FIPS 204 Algorithms 34 / 29 / 41–42, and the recovery runs an actual LLL.
 */

import { Shake256, shake256 } from './shake256';

/** ML-DSA-44 parameters — FIPS 204, Table 1. */
export const ML_DSA_44 = {
  /** q = 2^23 − 2^13 + 1 */
  q: 8380417,
  /** polynomial degree */
  n: 256,
  /** ζ, a 512th root of unity mod q */
  zeta: 1753,
  /** coefficient range of y is [−γ1+1, γ1] */
  gamma1: 1 << 17,
  /** # of ±1's in the challenge c */
  tau: 39,
  /** β = τ·η */
  beta: 78,
  /** private key range */
  eta: 2,
  /** dimensions of A: y and s1 each have ℓ = 4 polynomials */
  ell: 4,
  /** λ/4 = challenge-seed length in bytes */
  lambdaOver4: 32,
} as const;

const Q = ML_DSA_44.q;
const N = ML_DSA_44.n;

// ---------------------------------------------------------------------------
// modular arithmetic
// ---------------------------------------------------------------------------

/** a·b mod q. q < 2^23, so the product stays well inside 2^53. */
function mulMod(a: number, b: number): number {
  return (a * b) % Q;
}

function powMod(base: number, exponent: number, modulus: number): number {
  let result = 1;
  let b = base % modulus;
  let e = exponent;
  while (e > 0) {
    if (e & 1) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e = Math.floor(e / 2);
  }
  return result;
}

/** Representative in (−q/2, q/2], i.e. FIPS 204's `mod±`. */
export function centered(value: number): number {
  const r = ((value % Q) + Q) % Q;
  return r > Q / 2 ? r - Q : r;
}

function nonNegative(value: number): number {
  return ((value % Q) + Q) % Q;
}

// ---------------------------------------------------------------------------
// NTT — FIPS 204 Algorithms 41 and 42
// ---------------------------------------------------------------------------

function bitRev8(value: number): number {
  let out = 0;
  for (let i = 0; i < 8; i += 1) {
    out = (out << 1) | ((value >> i) & 1);
  }
  return out;
}

/** zetas[m] = ζ^BitRev8(m) mod q */
const ZETAS: Int32Array = (() => {
  const table = new Int32Array(256);
  for (let m = 0; m < 256; m += 1) {
    table[m] = powMod(ML_DSA_44.zeta, bitRev8(m), Q);
  }
  return table;
})();

/** FIPS 204 Algorithm 41. */
export function ntt(poly: Int32Array): Int32Array {
  const w = Int32Array.from(poly, nonNegative);
  let m = 0;
  for (let len = 128; len >= 1; len >>= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      m += 1;
      const z = ZETAS[m]!;
      for (let j = start; j < start + len; j += 1) {
        const t = mulMod(z, w[j + len]!);
        w[j + len] = nonNegative(w[j]! - t);
        w[j] = nonNegative(w[j]! + t);
      }
    }
  }
  return w;
}

/** FIPS 204 Algorithm 42. */
export function invNtt(hat: Int32Array): Int32Array {
  const w = Int32Array.from(hat, nonNegative);
  let m = 256;
  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start += 2 * len) {
      m -= 1;
      const z = nonNegative(-ZETAS[m]!);
      for (let j = start; j < start + len; j += 1) {
        const t = w[j]!;
        w[j] = nonNegative(t + w[j + len]!);
        w[j + len] = nonNegative(t - w[j + len]!);
        w[j + len] = mulMod(z, w[j + len]!);
      }
    }
  }
  const f = 8347681; // 256^-1 mod q
  for (let j = 0; j < N; j += 1) {
    w[j] = mulMod(f, w[j]!);
  }
  return w;
}

/** Product in R_q = Z_q[x]/(x^256 + 1), computed the way ML-DSA computes it. */
export function ringMul(a: Int32Array, b: Int32Array): Int32Array {
  const ah = ntt(a);
  const bh = ntt(b);
  const ch = new Int32Array(N);
  for (let i = 0; i < N; i += 1) {
    ch[i] = mulMod(ah[i]!, bh[i]!);
  }
  return invNtt(ch);
}

/**
 * Inverse in R_q, or null when the polynomial is not invertible. q ≡ 1 (mod
 * 512) splits R_q into 256 linear factors, so a polynomial is invertible
 * exactly when no NTT coordinate is zero — which for a τ-sparse challenge
 * happens with probability ≈ (1 − 1/q)^256, i.e. essentially always.
 */
export function ringInverse(a: Int32Array): Int32Array | null {
  const ah = ntt(a);
  const inv = new Int32Array(N);
  for (let i = 0; i < N; i += 1) {
    if (ah[i] === 0) {
      return null;
    }
    inv[i] = powMod(ah[i]!, Q - 2, Q);
  }
  return invNtt(inv);
}

// ---------------------------------------------------------------------------
// FIPS 204 sampling
// ---------------------------------------------------------------------------

function integerToBytes(value: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = 0; i < length; i += 1) {
    out[i] = v % 256;
    v = Math.floor(v / 256);
  }
  return out;
}

/** Number of bits needed to write `value` — FIPS 204's bitlen. */
function bitlen(value: number): number {
  let bits = 0;
  let v = value;
  while (v > 0) {
    bits += 1;
    v = Math.floor(v / 2);
  }
  return bits;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Little-endian bit reader, matching FIPS 204 BytesToBits + BitsToInteger. */
function readBits(bytes: Uint8Array, bitOffset: number, width: number): number {
  let value = 0;
  for (let i = 0; i < width; i += 1) {
    const bit = bitOffset + i;
    const byte = bytes[bit >> 3] ?? 0;
    value += ((byte >> (bit & 7)) & 1) * 2 ** i;
  }
  return value;
}

/**
 * FIPS 204 Algorithm 34 (ExpandMask) for a single polynomial y[r], with the
 * per-coefficient BitUnpack loop of Algorithm 19 written out — because that
 * loop is exactly what the fault aborts.
 *
 * `abortAfter` is the number of loop iterations that complete before the fault
 * lands. Coefficients past that index keep the value the output buffer already
 * held, which for a zero-initialised buffer is 0. (Espitau et al. Remark 3
 * covers the hardware variant where the tail holds a common *unknown* constant
 * instead; that costs the attacker one extra lattice generator.)
 */
export function expandMaskPoly(
  rho: Uint8Array,
  mu: number,
  abortAfter: number = N,
): Int32Array {
  const gamma1 = ML_DSA_44.gamma1;
  const width = 1 + bitlen(gamma1 - 1); // c = 1 + bitlen(γ1 − 1) = 18 for ML-DSA-44
  const v = shake256(concatBytes(rho, integerToBytes(mu, 2)), 32 * width);
  const y = new Int32Array(N); // zero-initialised output buffer
  const limit = Math.max(0, Math.min(N, abortAfter));
  for (let i = 0; i < limit; i += 1) {
    y[i] = gamma1 - readBits(v, i * width, width);
  }
  return y;
}

/** FIPS 204 Algorithm 29 (SampleInBall), τ = 39 for ML-DSA-44. */
export function sampleInBall(seed: Uint8Array): Int32Array {
  const tau = ML_DSA_44.tau;
  const c = new Int32Array(N);
  const ctx = new Shake256().absorb(seed);
  const s = ctx.squeeze(8);
  const signBits: number[] = [];
  for (let i = 0; i < 64; i += 1) {
    signBits.push((s[i >> 3]! >> (i & 7)) & 1);
  }
  for (let i = N - tau; i < N; i += 1) {
    let j = ctx.squeeze(1)[0]!;
    while (j > i) {
      j = ctx.squeeze(1)[0]!;
    }
    c[i] = c[j]!;
    c[j] = signBits[i + tau - N] === 1 ? -1 : 1;
  }
  return c;
}

// ---------------------------------------------------------------------------
// Espitau et al. eq. (2): how big must the projection be?
// ---------------------------------------------------------------------------

/** Second moment of one s1 coefficient (uniform on [−η, η]). */
function secretSecondMoment(): number {
  const eta = ML_DSA_44.eta;
  let sum = 0;
  for (let v = -eta; v <= eta; v += 1) {
    sum += v * v;
  }
  return sum / (2 * eta + 1);
}

/** Kannan embedding constant B = ⌈σ⌉, the paper's ⌈√(δ1+4δ2)⌉. */
export const EMBED_B = Math.ceil(Math.sqrt(secretSecondMoment()));

/**
 * Espitau et al. eq. (2), instantiated for ML-DSA's secret distribution:
 * the projection size ℓ+1 at which (φ_I(s1), B) is expected to be the shortest
 * vector of the embedded lattice. Returns ℓ+1 as a real number.
 */
export function requiredEmbeddingDimension(nonzeroCount: number): number {
  const sigmaSq = secretSecondMoment();
  const lnQ = Math.log(Q);
  const denominator = 1 - Math.log(Math.sqrt(2 * Math.PI * Math.E * sigmaSq)) / lnQ;
  const numerator = nonzeroCount + 2 + Math.log(EMBED_B) / lnQ;
  return numerator / denominator;
}

/**
 * Projection size this lab actually uses: the eq. (2) threshold with a margin,
 * never smaller than m+3 (the lattice carries no information unless ℓ > m).
 */
export function projectionSize(nonzeroCount: number): number {
  const threshold = Math.ceil(requiredEmbeddingDimension(nonzeroCount)) - 1;
  return Math.min(N, Math.max(nonzeroCount + 3, Math.ceil(threshold * 1.15)));
}

/**
 * Largest m this page will run LLL for. The paper reports LLL succeeding to
 * m ≈ 50–60 and BKZ to m ≈ 100; the cap here is a browser-responsiveness
 * limit, not a cryptographic one, and the UI says so.
 */
export const EXECUTABLE_ABORT_LIMIT = 16;

// ---------------------------------------------------------------------------
// lattice construction + LLL
// ---------------------------------------------------------------------------

/**
 * Basis of the q-ary lattice L_I = {x ∈ Z^ℓ : x mod q ∈ rowspan(rows)} + qZ^ℓ,
 * from the reduced row echelon form of `rows` over the field Z_q.
 * Returns an ℓ×ℓ basis of determinant q^(ℓ−rank).
 */
export function qaryBasis(rows: number[][], size: number): { basis: number[][]; rank: number } {
  const matrix = rows.map((row) => row.map(nonNegative));
  const pivotColumns: number[] = [];
  let pivotRow = 0;

  for (let col = 0; col < size && pivotRow < matrix.length; col += 1) {
    let selected = -1;
    for (let r = pivotRow; r < matrix.length; r += 1) {
      if (matrix[r]![col] !== 0) {
        selected = r;
        break;
      }
    }
    if (selected < 0) {
      continue;
    }
    const tmp = matrix[pivotRow]!;
    matrix[pivotRow] = matrix[selected]!;
    matrix[selected] = tmp;

    const inv = powMod(matrix[pivotRow]![col]!, Q - 2, Q);
    for (let c = col; c < size; c += 1) {
      matrix[pivotRow]![c] = mulMod(matrix[pivotRow]![c]!, inv);
    }
    for (let r = 0; r < matrix.length; r += 1) {
      if (r === pivotRow) {
        continue;
      }
      const factor = matrix[r]![col]!;
      if (factor === 0) {
        continue;
      }
      for (let c = col; c < size; c += 1) {
        matrix[r]![c] = nonNegative(matrix[r]![c]! - mulMod(factor, matrix[pivotRow]![c]!));
      }
    }
    pivotColumns.push(col);
    pivotRow += 1;
  }

  const rank = pivotColumns.length;
  const isPivot = new Set(pivotColumns);

  // The q·e_j rows go FIRST. They are mutually orthogonal and long, so the
  // Gram–Schmidt of this ordering starts well-conditioned; leading with the
  // echelon rows instead makes the later Gram–Schmidt lengths collapse from
  // ~q to ~1, which costs a float LLL every digit it has.
  const basis: number[][] = [];
  for (let col = 0; col < size; col += 1) {
    if (!isPivot.has(col)) {
      const row = new Array<number>(size).fill(0);
      row[col] = Q;
      basis.push(row);
    }
  }
  for (let r = 0; r < rank; r += 1) {
    basis.push(matrix[r]!.slice(0, size));
  }
  return { basis, rank };
}

/**
 * LLL, with modified Gram–Schmidt recomputed once per outer iteration.
 *
 * The cheaper textbook variant that patches the Gram–Schmidt data in place is
 * not usable here: a q-ary basis has Gram–Schmidt lengths spanning q down to 1,
 * so the incremental updates lose every significant digit a double has and the
 * reduction silently stalls far above the true shortest vector. Recomputing is
 * O(dim) times more work per step, and it is why EXECUTABLE_ABORT_LIMIT is set
 * where it is.
 */
export function lllReduce(input: number[][], delta = 0.99): number[][] {
  const rows = input.length;
  if (rows < 2) {
    return input.map((row) => row.slice());
  }
  const dim = input[0]!.length;
  const b = input.map((row) => row.slice());
  let mu: number[][] = [];
  let norm: number[] = [];

  const dot = (u: number[], v: number[]): number => {
    let sum = 0;
    for (let i = 0; i < dim; i += 1) {
      sum += u[i]! * v[i]!;
    }
    return sum;
  };

  const gramSchmidt = (): void => {
    const star: number[][] = [];
    mu = Array.from({ length: rows }, () => new Array<number>(rows).fill(0));
    norm = new Array<number>(rows).fill(0);
    for (let i = 0; i < rows; i += 1) {
      const residue = b[i]!.slice();
      for (let j = 0; j < i; j += 1) {
        const factor = norm[j]! > 0 ? dot(residue, star[j]!) / norm[j]! : 0;
        mu[i]![j] = factor;
        for (let t = 0; t < dim; t += 1) {
          residue[t] = residue[t]! - factor * star[j]![t]!;
        }
      }
      star.push(residue);
      norm[i] = dot(residue, residue);
    }
  };

  gramSchmidt();

  let k = 1;
  let guard = 0;
  const guardLimit = 4000 * rows + 200000;

  while (k < rows && guard < guardLimit) {
    guard += 1;

    let reduced = false;
    for (let l = k - 1; l >= 0; l -= 1) {
      if (Math.abs(mu[k]![l]!) > 0.5) {
        const r = Math.round(mu[k]![l]!);
        for (let t = 0; t < dim; t += 1) {
          b[k]![t] = b[k]![t]! - r * b[l]![t]!;
        }
        reduced = true;
      }
    }
    if (reduced) {
      gramSchmidt();
    }

    const muK = mu[k]![k - 1]!;
    if (norm[k]! >= (delta - muK * muK) * norm[k - 1]!) {
      k += 1;
      continue;
    }

    const swap = b[k]!;
    b[k] = b[k - 1]!;
    b[k - 1] = swap;
    gramSchmidt();
    k = Math.max(k - 1, 1);
  }

  return b;
}

// ---------------------------------------------------------------------------
// the attack
// ---------------------------------------------------------------------------

export type LoopAbortBlock = {
  /** first index of the projection subset I */
  start: number;
  /** |I| */
  size: number;
  /** coefficients of s1 this block got exactly right */
  correct: number;
  solved: boolean;
};

export type LoopAbortResult = {
  /** m — how many ExpandMask loop iterations completed before the fault. */
  abortAfter: number;
  /** the honest run's nonce, for the "before" strip */
  honestY: Int32Array;
  /** the faulted run's nonce: m real samples then a tail of zeros */
  faultedY: Int32Array;
  /** how many coefficients of the faulted y are non-zero */
  nonzeroY: number;
  challenge: Int32Array;
  secret: Int32Array;
  z: Int32Array;
  /** ‖z‖∞ and the FIPS 204 line-23 bound it is checked against */
  zInfinityNorm: number;
  rejectionBound: number;
  /** true when a correct signer would have thrown this signature away */
  wouldReject: boolean;
  challengeInvertible: boolean;
  /** ℓ+1 from eq. (2), and the ℓ this run used */
  requiredDimension: number;
  projection: number;
  blocks: LoopAbortBlock[];
  recovered: Int32Array;
  recoveredCount: number;
  /** whether the whole of s1 came back exactly */
  success: boolean;
  /** wall-clock cost of the lattice step */
  latticeMs: number;
  /** set when m is past EXECUTABLE_ABORT_LIMIT, so no LLL was run */
  skippedReason?: string;
};

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function randomSecret(): Int32Array {
  const eta = ML_DSA_44.eta;
  const span = 2 * eta + 1;
  const out = new Int32Array(N);
  const raw = randomBytes(N * 2);
  for (let i = 0; i < N; i += 1) {
    // rejection-free mapping is fine here: this stands in for ExpandS, whose
    // only job is a uniform draw from [−η, η].
    out[i] = ((raw[i]! + raw[i + N]! * 256) % span) - eta;
  }
  return out;
}

/** (x^shift · poly) in R_q, i.e. a negacyclic rotation. */
function negacyclicShift(poly: Int32Array, shift: number): Int32Array {
  const out = new Int32Array(N);
  for (let j = 0; j < N; j += 1) {
    const source = j - shift;
    out[j] = source >= 0 ? poly[source]! : nonNegative(-poly[source + N]!);
  }
  return out;
}

/**
 * Run one loop-abort fault end to end: expand a faulted nonce, sign with it,
 * then recover s1 from the single faulty signature by lattice reduction.
 */
export function runLoopAbortAttack(abortAfter: number): LoopAbortResult {
  const m = Math.max(1, Math.min(N, Math.floor(abortAfter)));

  // --- signer side -------------------------------------------------------
  const secret = randomSecret();
  // ρ″ = H(K‖rnd‖μ) in FIPS 204 Algorithm 7 line 7. K is private, so this seed
  // is unknown to the attacker in BOTH the hedged and the deterministic variant
  // — the attack below never needs it.
  const rhoDoublePrime = randomBytes(64);
  const honestY = expandMaskPoly(rhoDoublePrime, 0, N);
  const faultedY = expandMaskPoly(rhoDoublePrime, 0, m);

  const challenge = sampleInBall(randomBytes(ML_DSA_44.lambdaOver4));
  const cs1 = ringMul(challenge, secret);
  const z = new Int32Array(N);
  for (let i = 0; i < N; i += 1) {
    z[i] = faultedY[i]! + centered(cs1[i]!);
  }

  let zInfinityNorm = 0;
  for (let i = 0; i < N; i += 1) {
    zInfinityNorm = Math.max(zInfinityNorm, Math.abs(z[i]!));
  }
  const rejectionBound = ML_DSA_44.gamma1 - ML_DSA_44.beta;
  const wouldReject = zInfinityNorm >= rejectionBound;

  let nonzeroY = 0;
  for (let i = 0; i < N; i += 1) {
    if (faultedY[i] !== 0) {
      nonzeroY += 1;
    }
  }

  const requiredDimension = requiredEmbeddingDimension(m);
  const projection = projectionSize(m);
  const recovered = new Int32Array(N);
  const blocks: LoopAbortBlock[] = [];

  // --- attacker side -----------------------------------------------------
  const challengeInverse = ringInverse(challenge);
  const base = {
    abortAfter: m,
    honestY,
    faultedY,
    nonzeroY,
    challenge,
    secret,
    z,
    zInfinityNorm,
    rejectionBound,
    wouldReject,
    challengeInvertible: challengeInverse !== null,
    requiredDimension,
    projection,
    blocks,
    recovered,
    recoveredCount: 0,
    success: false,
    latticeMs: 0,
  };

  if (!challengeInverse) {
    return { ...base, skippedReason: 'c was not invertible in R_q — retry with another signature.' };
  }

  if (m > EXECUTABLE_ABORT_LIMIT) {
    return {
      ...base,
      skippedReason:
        `m = ${m} needs an LLL of dimension ≈ ${projection + 1}, past this page's in-browser ` +
        `limit of m = ${EXECUTABLE_ABORT_LIMIT}. The dimension analysis below still applies.`,
    };
  }

  const started = performance.now();

  // v = c⁻¹z, and the generators w_i = c⁻¹x^i for i < m
  const v = ringMul(challengeInverse, Int32Array.from(z, nonNegative));
  const generators: Int32Array[] = [];
  for (let i = 0; i < m; i += 1) {
    generators.push(negacyclicShift(challengeInverse, i));
  }

  // Cover 0…255 with projections of size `projection`; the last one overlaps.
  const starts: number[] = [];
  for (let start = 0; start < N; start += projection) {
    starts.push(Math.min(start, N - projection));
  }

  for (const start of starts) {
    const indices = Array.from({ length: projection }, (_, t) => start + t);
    const rows = generators.map((generator) => indices.map((index) => generator[index]!));
    const { basis } = qaryBasis(rows, projection);

    // Kannan embedding: append a zero column to L_I's basis and add the row
    // (φ_I(v), B). The shortest vector should be ±(φ_I(s1), B).
    const embedded = basis.map((row) => row.concat([0]));
    embedded.push(indices.map((index) => nonNegative(v[index]!)).concat([EMBED_B]));

    const reduced = lllReduce(embedded);

    let best: number[] | null = null;
    let bestNorm = Infinity;
    for (const row of reduced) {
      const tail = row[projection]!;
      if (Math.abs(tail) !== EMBED_B) {
        continue;
      }
      const sign = tail > 0 ? 1 : -1;
      let norm = 0;
      let plausible = true;
      for (let t = 0; t < projection; t += 1) {
        const value = sign * row[t]!;
        if (Math.abs(value) > ML_DSA_44.eta) {
          plausible = false;
          break;
        }
        norm += value * value;
      }
      if (plausible && norm < bestNorm) {
        bestNorm = norm;
        best = indices.map((_, t) => sign * row[t]!);
      }
    }

    let correct = 0;
    if (best) {
      for (let t = 0; t < projection; t += 1) {
        recovered[indices[t]!] = best[t]!;
        if (best[t] === secret[indices[t]!]) {
          correct += 1;
        }
      }
    }
    blocks.push({ start, size: projection, correct, solved: best !== null });
  }

  const latticeMs = performance.now() - started;

  let recoveredCount = 0;
  for (let i = 0; i < N; i += 1) {
    if (recovered[i] === secret[i]) {
      recoveredCount += 1;
    }
  }

  return {
    ...base,
    blocks,
    recovered,
    recoveredCount,
    success: recoveredCount === N,
    latticeMs,
  };
}
