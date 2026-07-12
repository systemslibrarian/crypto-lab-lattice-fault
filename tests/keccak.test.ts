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

  it('flags exactly the lanes whose bytes truly differ (real diff, not a hardcoded column)', async () => {
    const result = await simulateFaultyKeccakAttack();
    expect(result.laneChanged).toHaveLength(25);
    for (let i = 0; i < 25; i += 1) {
      const differs = (result.normalLanes[i]! & 255n) !== (result.faultedLanes[i]! & 255n);
      expect(result.laneChanged[i]).toBe(differs);
    }
  });

  it('the mask collapses ONLY under the fault: attacker predicts the zeroed nonce but not the random one', async () => {
    const result = await simulateFaultyKeccakAttack();
    // Faulted run: attacker's public-only recomputation of y matches reality.
    expect(result.maskingCollapsed).toBe(true);
    expect(Array.from(result.predictedFaultedY)).toEqual(Array.from(result.faultedY));
    // Honest run: the same public guess does NOT match the real random nonce,
    // so z = y + c*s1 stays blinded (with overwhelming probability).
    expect(Array.from(result.predictedNormalY)).not.toEqual(Array.from(result.normalY));
  });
});
