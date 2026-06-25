# crypto-lab-lattice-fault

## What It Is

This browser demo explains physical implementation attacks against ML-KEM and ML-DSA, the post-quantum asymmetric primitives used for key encapsulation and digital signatures. It shows how power leakage, timing variation, rejection-sampling faults, and faulty KECCAK handling can expose secret-dependent behavior on hardware even when the underlying math remains secure. The demo is simulated and educational, and it does not claim a mathematical break of either standard.

## When to Use It

- Teaching post-quantum implementation risk. It connects concrete ML-KEM and ML-DSA operations to the side-channel and fault surfaces engineers must still defend.
- Explaining why constant-time and masking countermeasures matter. It lets learners compare leaky and hardened behavior in the same browser session.
- Demonstrating the physical-access threat model. It keeps the focus on probes, timing capture, and glitching rather than network-only attacks.
- Not for validating a production device. The traces, recoveries, and timing gaps are simplified browser simulations rather than certified lab measurements.

## Live Demo

Live site: https://systemslibrarian.github.io/crypto-lab-lattice-fault/

In the demo, you can generate simulated power traces, run the CPA exhibit, compare normal and faulted signing behavior, and launch the timing and KECCAK views. Controls include the secret key coefficient, ciphertext coefficient, noise level, number of traces, and action buttons for each exhibit.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-lattice-fault
cd crypto-lab-lattice-fault
npm install
npm run dev      # start the dev server
npm test         # run the test suite (Vitest): simulation logic + UI integration
npm run build    # type-check (tsc) + production build
```

No environment variables are required.

## What the Exhibits Mirror

The standards themselves — [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) and
[FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final), both finalized in 2024 — are not under
attack here. Each exhibit is a simplified, browser-friendly reconstruction of a published
*implementation* attack:

| Exhibit | Real-world basis |
| --- | --- |
| 1 — NTT power analysis | Primas, Pessl & Mangard, *Single-Trace Side-Channel Attacks on Masked Lattice-Based Encryption*, CHES 2017 — [ePrint 2017/594](https://eprint.iacr.org/2017/594) |
| 2 — Rejection-sampling fault | *Key Recovery of CRYSTALS-Dilithium via Side-Channel Attacks*, IACR TCHES 2025 — [ePrint 2025/214](https://eprint.iacr.org/2025/214) |
| 3 — KyberSlash timing | Bernstein et al., *Exploiting secret-dependent division timings in Kyber*, 2024 — [kyberslash.cr.yp.to](https://kyberslash.cr.yp.to/) · [ePrint 2024/1049](https://eprint.iacr.org/2024/1049) |
| 4 — Faulty KECCAK / zeroed nonce | Espitau, Fouque, Gérard & Tibouchi, *Loop-Abort Faults on Lattice-Based Fiat–Shamir and Hash-and-Sign Signatures*, SAC 2016 — [ePrint 2016/449](https://eprint.iacr.org/2016/449) |

The numbers shown in-browser (recovered keys, recovery rates, timing gaps) are produced by the actual
simulation code, which is exercised by the test suite in `tests/` on every CI run.

## Part of the Crypto-Lab Suite

One of 60+ live browser demos at [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*
