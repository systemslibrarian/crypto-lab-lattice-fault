/**
 * SHAKE256 (FIPS 202) — a real KECCAK-f[1600] sponge.
 *
 * ML-DSA derives *everything* pseudorandom through H(·) = SHAKE256 (FIPS 204
 * §3.7), so Attack 4 needs the genuine XOF rather than a stand-in: ExpandMask
 * (Algorithm 34) and SampleInBall (Algorithm 29) are only faithful if the bytes
 * they consume are really SHAKE256 bytes. Lanes are held as BigInt so the
 * 64-bit rotations are exact; the volumes this lab squeezes (a few hundred
 * bytes per signature) make the BigInt cost irrelevant.
 */

const MASK64 = (1n << 64n) - 1n;

const ROUND_CONSTANTS: readonly bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

/** rho offsets r[x][y] from the KECCAK specification. */
const ROTATION: readonly (readonly number[])[] = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rotl64(value: bigint, shift: number): bigint {
  if (shift === 0) {
    return value;
  }
  const s = BigInt(shift);
  return ((value << s) | (value >> (64n - s))) & MASK64;
}

/** The KECCAK-f[1600] permutation, in place, on 25 lanes indexed x + 5y. */
export function keccakF1600(state: bigint[]): void {
  const c = new Array<bigint>(5).fill(0n);
  const d = new Array<bigint>(5).fill(0n);
  const b = new Array<bigint>(25).fill(0n);

  for (let round = 0; round < 24; round += 1) {
    // theta
    for (let x = 0; x < 5; x += 1) {
      c[x] = state[x]! ^ state[x + 5]! ^ state[x + 10]! ^ state[x + 15]! ^ state[x + 20]!;
    }
    for (let x = 0; x < 5; x += 1) {
      d[x] = c[(x + 4) % 5]! ^ rotl64(c[(x + 1) % 5]!, 1);
    }
    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        state[x + 5 * y] = state[x + 5 * y]! ^ d[x]!;
      }
    }

    // rho + pi
    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y]!, ROTATION[x]![y]!);
      }
    }

    // chi
    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        state[x + 5 * y] =
          b[x + 5 * y]! ^ (~b[((x + 1) % 5) + 5 * y]! & b[((x + 2) % 5) + 5 * y]!) & MASK64;
      }
    }

    // iota
    state[0] = state[0]! ^ ROUND_CONSTANTS[round]!;
  }
}

/** SHAKE256 rate in bytes (1600 − 2·256 bits). */
export const SHAKE256_RATE = 136;

/**
 * Incremental SHAKE256, mirroring the H.Init / H.Absorb / H.Squeeze interface
 * FIPS 204 uses (SampleInBall squeezes byte by byte, so a one-shot API is not
 * enough).
 */
export class Shake256 {
  private readonly state: bigint[] = new Array<bigint>(25).fill(0n);
  private readonly block = new Uint8Array(SHAKE256_RATE);
  private blockLength = 0;
  private squeezing = false;
  private squeezeOffset = SHAKE256_RATE;

  absorb(input: Uint8Array): this {
    if (this.squeezing) {
      throw new Error('SHAKE256: cannot absorb after squeezing');
    }
    for (let i = 0; i < input.length; i += 1) {
      this.block[this.blockLength] = input[i]!;
      this.blockLength += 1;
      if (this.blockLength === SHAKE256_RATE) {
        this.absorbBlock();
      }
    }
    return this;
  }

  squeeze(outputLength: number): Uint8Array {
    if (!this.squeezing) {
      this.pad();
    }
    const out = new Uint8Array(outputLength);
    for (let i = 0; i < outputLength; i += 1) {
      if (this.squeezeOffset === SHAKE256_RATE) {
        keccakF1600(this.state);
        this.squeezeOffset = 0;
      }
      out[i] = this.laneByte(this.squeezeOffset);
      this.squeezeOffset += 1;
    }
    return out;
  }

  private laneByte(index: number): number {
    const lane = this.state[Math.floor(index / 8)]!;
    return Number((lane >> BigInt((index % 8) * 8)) & 0xffn);
  }

  private absorbBlock(): void {
    for (let i = 0; i < SHAKE256_RATE; i += 1) {
      const laneIndex = Math.floor(i / 8);
      this.state[laneIndex] =
        this.state[laneIndex]! ^ (BigInt(this.block[i]!) << BigInt((i % 8) * 8));
    }
    keccakF1600(this.state);
    this.blockLength = 0;
  }

  private pad(): void {
    // SHAKE domain separator 0x1F, then the 0x80 final bit (FIPS 202 §6.2).
    this.block.fill(0, this.blockLength);
    this.block[this.blockLength] = 0x1f;
    this.block[SHAKE256_RATE - 1] = this.block[SHAKE256_RATE - 1]! ^ 0x80;
    for (let i = 0; i < SHAKE256_RATE; i += 1) {
      const laneIndex = Math.floor(i / 8);
      this.state[laneIndex] =
        this.state[laneIndex]! ^ (BigInt(this.block[i]!) << BigInt((i % 8) * 8));
    }
    this.squeezing = true;
    this.squeezeOffset = SHAKE256_RATE;
  }

  /** The 25 sponge lanes, for the exhibit's state readout. */
  lanes(): bigint[] {
    return this.state.slice();
  }
}

/** One-shot SHAKE256: `H(str, outputLength)` in FIPS 204's notation. */
export function shake256(input: Uint8Array, outputLength: number): Uint8Array {
  return new Shake256().absorb(input).squeeze(outputLength);
}
