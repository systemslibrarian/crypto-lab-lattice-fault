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
    // Hand digest() a typed-array VIEW, not a raw ArrayBuffer: ArrayBuffer.isView()
    // is realm-safe, so this works whether crypto comes from a browser, Node, or a
    // jsdom test realm. (A raw cross-realm ArrayBuffer is rejected by Node's
    // SubtleCrypto.) The copy also pins the type to Uint8Array<ArrayBuffer>.
    const data = new Uint8Array(payload);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
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
  /** Per-lane flag: true where the faulted sponge byte differs from the normal one. */
  laneChanged: boolean[];
  /** The attacker's prediction of the nonce y in the FAULTED run (they can compute it because the seed randomness was zeroed). */
  predictedFaultedY: Int32Array;
  /** The attacker's (failed) prediction of y for the HONEST run, to show it stays hidden there. */
  predictedNormalY: Int32Array;
  /** True: with the zeroed nonce the attacker's predicted y matches the real one, so y+cs1 masking collapses. */
  maskingCollapsed: boolean;
}> {
  // ML-DSA masks the secret in each signature as  z = y + c·s₁ , where y is a
  // per-signature NONCE the signer expands from a KECCAK/SHAKE call. The public
  // signature reveals z and the challenge c, but NOT y — so s₁ stays hidden.
  //
  // The mask y is derived from  H( μ ‖ κ )  where μ is the (public) message
  // representative and κ is the per-signature randomness. The secret key never
  // enters the y-derivation, so the ATTACKER can recompute y IF (and only if)
  // they know κ. Normally κ is fresh random and hidden, so they can't.
  const secret = Int32Array.from([1, -2, 0, 1, -1, 2, -1, 0]);
  const challenge = Int32Array.from([1, -1, 1, 1, -1, 1, -1, 1]);
  const mu = encoder.encode('public message representative μ'); // known to the attacker
  const kappa = new Uint8Array(32); // per-signature randomness κ (normally secret)
  crypto.getRandomValues(kappa);
  const zeroKappa = new Uint8Array(32); // what a loop-abort fault leaves behind

  // Honest run: y expanded from H(μ ‖ κ). Faulted run: the abort zeroes κ.
  const normalRhoBytes = await pseudoShake256(concatBytes(mu, kappa), 32);
  const faultedRhoBytes = await pseudoShake256(concatBytes(mu, zeroKappa), 32);

  const normalY = deriveMask(normalRhoBytes, secret.length);
  const faultedY = deriveMask(faultedRhoBytes, secret.length);

  // The device signs under the FAULTED run and releases z = y + c·s₁.
  const z = new Int32Array(secret.length);
  for (let i = 0; i < secret.length; i += 1) {
    z[i] = faultedY[i] + challenge[i] * secret[i] * 17;
  }

  // The attacker's move: recompute y from PUBLIC data only. They know μ and know
  // the fault zeroes κ, so they can rederive the faulted nonce WITHOUT any secret
  // — this is the whole point, not a value handed to them. For the honest run
  // they can only guess κ = 0 (their best public guess), which fails.
  const attackerRho = await pseudoShake256(concatBytes(mu, zeroKappa), 32);
  const predictedFaultedY = deriveMask(attackerRho, secret.length);
  const predictedNormalY = deriveMask(attackerRho, secret.length); // same guess; won't match the real random y

  // Now the mask cancels:  s₁ = (z − y_predicted) / (17·c).  This only works
  // because y_predicted == the real faulted y; against the honest nonce the
  // subtraction leaves the random y in place and the quotient is garbage.
  const recovered = new Int32Array(secret.length);
  for (let i = 0; i < secret.length; i += 1) {
    const c = challenge[i] === 0 ? 1 : challenge[i] ?? 1;
    recovered[i] = Math.round((z[i] - predictedFaultedY[i]) / (17 * c));
  }

  const laneChanged = lanesFromSeed(normalRhoBytes).map(
    (lane, index) => (lane & 255n) !== (lanesFromSeed(faultedRhoBytes)[index]! & 255n),
  );

  const maskingCollapsed = predictedFaultedY.every((value, index) => value === faultedY[index]);

  return {
    normalInput: `μ (public) ‖ κ (32B fresh random)`,
    faultedInput: `μ (public) ‖ κ = 32B zeroes (loop-abort fault)`,
    normalRho: toHex(normalRhoBytes),
    faultedRho: toHex(faultedRhoBytes),
    normalY,
    faultedY,
    challenge,
    secret,
    z,
    recovered,
    candidateCount: secret.length,
    success: Array.from(secret).every((value, index) => value === recovered[index]),
    normalLanes: lanesFromSeed(normalRhoBytes),
    faultedLanes: lanesFromSeed(faultedRhoBytes),
    laneChanged,
    predictedFaultedY,
    predictedNormalY,
    maskingCollapsed,
  };
}
