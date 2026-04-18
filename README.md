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
npm run dev
```

No environment variables are required.

## Part of the Crypto-Lab Suite

One of 60+ live browser demos at [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*
