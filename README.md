# crypto-lab-lattice-fault

Browser-based educational demo of physical implementation attacks on ML-KEM (FIPS 203) and ML-DSA (FIPS 204) — the NIST post-quantum cryptography standards for key encapsulation and digital signatures.

> "Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."
> — 1 Corinthians 10:31

## What It Is

Browser-based educational demo of physical implementation attacks on
ML-KEM (FIPS 203) and ML-DSA (FIPS 204) — the NIST post-quantum
cryptography standards for key encapsulation and digital signatures.

Covers four concrete attacks demonstrated on real hardware against
ARM Cortex-M-class implementations:

- NTT Correlation Power Analysis using Hamming-weight leakage
- Rejection sampling bypass via fault injection
- KyberSlash timing side-channel behavior
- Faulty KECCAK seed generation during signing

Includes simulated power traces using a Hamming-weight leakage model,
rejection sampling fault simulation with key recovery, a timing
experiment comparing vulnerable versus constant-time decoding, and a
KECCAK sponge visualization with a loop-abort fault demo.

## When to Use It

- Understanding that PQC migration must include implementation security
- Learning why constant-time code is required even for PQC primitives
- Seeing how NTT structure makes lattice schemes vulnerable to CPA
- Understanding realistic physical fault models and their scope

## Live Demo

https://systemslibrarian.github.io/crypto-lab-lattice-fault/

## What Can Go Wrong

- All attacks shown require **physical access** to the target device.
  An attacker with only network access cannot perform these attacks.
- Every attack shown in the app is clearly labeled **SIMULATED**.
  The demo illustrates the principle only; it is not a practical attack tool.
- Power trace simulation uses Hamming weight plus Gaussian noise.
  Real traces require alignment, filtering, and significantly more analysis.
- Browser timing precision is limited by Spectre mitigations.
  The KyberSlash effect is shown as an educational comparison, not as a lab-grade measurement.
- Faulted-signature recovery is intentionally simplified for in-browser learning.

## Real-World Usage

These attacks are implementation attacks, not mathematical breaks.
ML-KEM and ML-DSA are not mathematically broken and remain sound cryptographic constructions.

Relevant lessons from public research:

- **KyberSlash**: constant-time decoding patches were required in production implementations.
- **Fault injection on rejection sampling**: faulty signatures can reveal ML-DSA secret information.
- **Faulty KECCAK**: loop-abort faults can make nonce generation predictable.
- **NTT power leakage**: regular arithmetic still leaks through power and EM channels.

## Stack

- Vite
- TypeScript with `strict: true`
- Vanilla CSS
- Canvas 2D
- WebCrypto SHA-256-based sponge simulation
- GitHub Pages deployment via Actions

## Safety Message

Post-quantum migration is necessary, but it is not sufficient.
Mathematical security does not automatically imply implementation security.
Countermeasures such as masking, shuffling, constant-time code, and
fault-consistency checks must migrate too.
