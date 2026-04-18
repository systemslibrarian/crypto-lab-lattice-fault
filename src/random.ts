const UINT32_RANGE = 0x1_0000_0000;

export function randomUint32(): number {
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return buffer[0] ?? 0;
}

export function randomUnit(): number {
  return (randomUint32() + 1) / (UINT32_RANGE + 2);
}

export function randomIntInclusive(min: number, max: number): number {
  if (!Number.isInteger(min) || !Number.isInteger(max) || max < min) {
    throw new Error('Invalid inclusive random integer range');
  }

  const range = max - min + 1;
  const limit = Math.floor(UINT32_RANGE / range) * range;
  let sample = randomUint32();

  while (sample >= limit) {
    sample = randomUint32();
  }

  return min + (sample % range);
}

export function randomNormal(sigma = 1): number {
  const u1 = randomUnit();
  const u2 = randomUnit();
  const mag = Math.sqrt(-2 * Math.log(u1));
  const angle = 2 * Math.PI * u2;
  return sigma * mag * Math.cos(angle);
}
