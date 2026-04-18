const encoder = new TextEncoder();

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

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function pseudoShake256(input: Uint8Array, outBytes = 32): Promise<Uint8Array> {
  const out = new Uint8Array(outBytes);
  let offset = 0;
  let counter = 0;

  while (offset < outBytes) {
    const suffix = new Uint8Array(4);
    new DataView(suffix.buffer).setUint32(0, counter, true);
    const payload = concatBytes(input, suffix);
    const buffer = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', buffer as ArrayBuffer));
    out.set(digest.subarray(0, Math.min(digest.length, outBytes - offset)), offset);
    offset += digest.length;
    counter += 1;
  }

  return out;
}

function deriveMask(seed: Uint8Array, length: number): Int32Array {
  const out = new Int32Array(length);

  for (let i = 0; i < length; i += 1) {
    const hi = seed[(i * 2) % seed.length] ?? 0;
    const lo = seed[(i * 2 + 1) % seed.length] ?? 0;
    const word = (hi << 8) | lo;
    out[i] = (word % 2001) - 1000;
  }

  return out;
}

function lanesFromSeed(seed: Uint8Array): bigint[] {
  const lanes: bigint[] = [];

  for (let laneIndex = 0; laneIndex < 25; laneIndex += 1) {
    let lane = 0n;
    for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
      const source = seed[(laneIndex * 8 + byteIndex) % seed.length] ?? 0;
      lane |= BigInt(source) << BigInt(byteIndex * 8);
    }
    lanes.push(lane);
  }

  return lanes;
}

export async function simulateFaultyKeccakAttack(): Promise<{
  normalInput: string;
  faultedInput: string;
  normalRho: string;
  faultedRho: string;
  normalY: Int32Array;
  faultedY: Int32Array;
  challenge: Int32Array;
  secret: Int32Array;
  z: Int32Array;
  recovered: Int32Array;
  candidateCount: number;
  success: boolean;
  normalLanes: bigint[];
  faultedLanes: bigint[];
}> {
  const secret = Int32Array.from([1, -2, 0, 1, -1, 2, -1, 0]);
  const challenge = Int32Array.from([1, -1, 1, 1, -1, 1, -1, 1]);
  const message = encoder.encode('Implementation security matters.');
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);

  const secretBytes = Uint8Array.from(Array.from(secret, (value) => value + 2));
  const zeroBytes = new Uint8Array(32);

  const normalSeed = concatBytes(secretBytes, message, randomBytes);
  const faultedSeed = concatBytes(secretBytes, message, zeroBytes);

  const normalRhoBytes = await pseudoShake256(normalSeed, 32);
  const faultedRhoBytes = await pseudoShake256(faultedSeed, 32);

  const normalY = deriveMask(normalRhoBytes, secret.length);
  const faultedY = deriveMask(faultedRhoBytes, secret.length);

  const z = new Int32Array(secret.length);
  for (let i = 0; i < secret.length; i += 1) {
    z[i] = faultedY[i] + challenge[i] * secret[i] * 17;
  }

  const recovered = new Int32Array(secret.length);
  for (let i = 0; i < secret.length; i += 1) {
    const c = challenge[i] === 0 ? 1 : challenge[i] ?? 1;
    recovered[i] = Math.round((z[i] - faultedY[i]) / (17 * c));
  }

  return {
    normalInput: `${secretBytes.length}B secret || ${message.length}B msg || 32B random`,
    faultedInput: `${secretBytes.length}B secret || ${message.length}B msg || 32B zeroes`,
    normalRho: toHex(normalRhoBytes),
    faultedRho: toHex(faultedRhoBytes),
    normalY,
    faultedY,
    challenge,
    secret,
    z,
    recovered,
    candidateCount: 256,
    success: Array.from(secret).every((value, index) => value === recovered[index]),
    normalLanes: lanesFromSeed(normalRhoBytes),
    faultedLanes: lanesFromSeed(faultedRhoBytes),
  };
}
