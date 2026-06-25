import { describe, expect, it } from 'vitest';
import { simulateFaultyKeccakAttack } from '../src/keccak';

describe('faulty KECCAK seed generation (Attack 4)', () => {
  it('zeroing the nonce makes the derived randomness diverge from the honest run', async () => {
    const result = await simulateFaultyKeccakAttack();
    expect(result.normalRho).not.toBe(result.faultedRho);
    expect(result.normalInput).toContain('random');
    expect(result.faultedInput).toContain('zeroes');
  });

  it('recovers every secret coefficient once the randomness is predictable', async () => {
    const result = await simulateFaultyKeccakAttack();
    expect(result.success).toBe(true);
    expect(Array.from(result.recovered)).toEqual(Array.from(result.secret));
  });

  it('exposes a 5x5 sponge state for both runs', async () => {
    const result = await simulateFaultyKeccakAttack();
    expect(result.normalLanes).toHaveLength(25);
    expect(result.faultedLanes).toHaveLength(25);
  });
});
