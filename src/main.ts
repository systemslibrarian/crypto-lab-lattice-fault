import './styles.css';
import { simulateFaultyKeccakAttack } from './keccak';
import {
  ML_DSA_PARAMS,
  recoverFromFaultySignatures,
  signWithFaultedRejection,
  signWithRejection,
} from './rejection';
import {
  Q,
  correlationPowerAnalysis,
  cpaCorrelationGrowth,
  hammingWeight,
  nttButterfly,
  simulatePowerTrace,
} from './ntt';
import { randomIntInclusive } from './random';
import { runClusterExperiment, type ClusterExperiment } from './timing';
import type { TimingWorkerRequest } from './timing.worker';

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App root not found');
}

app.innerHTML = `
  <main class="app-shell">
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">Lattice Fault Lab</h1>
        <p class="cl-hero-sub">Implementation attacks · ML-KEM · ML-DSA</p>
        <p class="cl-hero-desc">
          Simulates power (CPA) analysis, fault injection, and timing leaks against ML-KEM and ML-DSA so
          you can watch a mathematically secure scheme give up its secret key through the hardware running it.
        </p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">
          A cipher can be provably unbreakable on paper and still fall on a real chip. Deployments that
          only check the math ship keys an attacker can extract with a probe or a glitch — implementation
          security is a separate requirement that has to be earned in hardware.
        </p>
      </aside>
      <button id="theme-toggle" class="theme-toggle" style="position: absolute; top: 0; right: 0" aria-label="Switch to light mode">🌙</button>
    </header>

    <section class="sim-warning" role="note">
      ⚠ SIMULATED — every exhibit demonstrates the principle only. Real attacks require
      physical access, specialized probes or glitchers, and significant expertise. ML-KEM
      and ML-DSA are not mathematically broken; these are implementation attacks.
    </section>

    <nav class="toc panel" aria-label="Tour of the four attacks">
      <h2 class="toc-title">Start here — four implementation attacks, in order</h2>
      <p class="toc-lede">
        Each attack targets a different physical leak. Read them top to bottom: the vocabulary
        builds up, and each one is a little more subtle than the last. The last exhibit steps back
        to the big picture.
      </p>
      <ol class="toc-list">
        <li><a href="#attack-1"><span class="toc-num">1</span> <span class="toc-label">Power analysis</span> <span class="toc-what">read the chip's power draw during the NTT multiply</span></a></li>
        <li><a href="#attack-2"><span class="toc-num">2</span> <span class="toc-label">Fault injection</span> <span class="toc-what">glitch away the rejection check so it leaks the key</span></a></li>
        <li><a href="#attack-3"><span class="toc-num">3</span> <span class="toc-label">Timing (KyberSlash)</span> <span class="toc-what">a secret-dependent division runs for a different number of cycles</span></a></li>
        <li><a href="#attack-4"><span class="toc-num">4</span> <span class="toc-label">Fault on hashing</span> <span class="toc-what">glitch KECCAK so the secret nonce becomes predictable</span></a></li>
      </ol>
    </nav>

    <section class="exhibit panel" id="attack-1">
      <div class="exhibit-head">
        <div>
          <p class="kicker">SIMULATED • physical access required</p>
          <h2>ATTACK 1: NTT POWER ANALYSIS</h2>
          <p>Regular, branch-free NTT arithmetic still leaks through Hamming-weight power variations.</p>
        </div>
      </div>

      <div class="primer" role="note" aria-label="Key terms for this exhibit">
        <h3>New to this? Four terms first</h3>
        <dl class="primer-terms">
          <dt>NTT</dt>
          <dd>The <em>Number-Theoretic Transform</em> — the fast multiply step inside lattice crypto. ML-KEM multiplies polynomials by turning them into NTT form, multiplying point-by-point, then transforming back. The secret key flows through it.</dd>
          <dt>Butterfly</dt>
          <dd>One arithmetic step of the NTT: given two numbers <code>a</code> and <code>b</code> and a twiddle <code>w</code>, compute <code>a + w·b</code> and <code>a − w·b</code>. The transform is just thousands of butterflies.</dd>
          <dt>Hamming weight</dt>
          <dd>The number of 1-bits in a value. A chip draws roughly <em>more current when it moves more 1-bits</em> — so power consumption tracks the Hamming weight of the data on the bus.</dd>
          <dt>Side-channel</dt>
          <dd>Information that leaks through a physical channel (power, time, EM) rather than the algorithm's output. Here we <em>read the power draw</em> to guess the secret coefficient that shaped it.</dd>
        </dl>
        <p class="primer-thesis">The math is fine. The chip leaks. Those are two separate promises, and this exhibit breaks only the second.</p>
      </div>

      <p class="attacker-story">
        <strong>You are the attacker:</strong> you have a decapsulation device (a smartcard) doing ML-KEM
        on your bench, a power probe across its supply pin, and an oscilloscope. Each decryption runs the
        same NTT over your chosen ciphertext. You want the one secret coefficient <code>sk[0]</code> it keeps hidden.
      </p>

      <div class="grid-2">
        <div class="panel inset-panel">
          <h3>Setup</h3>
          <label>Secret key coefficient: <span id="sk-value">1234</span>
            <input id="sk-slider" type="range" min="0" max="3328" value="1234" />
          </label>
          <label>Ciphertext base coefficient: <span id="ct-value">567</span>
            <input id="ct-slider" type="range" min="0" max="3328" value="567" />
          </label>
          <label>Noise level σ: <span id="noise-value">0.5</span>
            <input id="noise-slider" type="range" min="0.1" max="1.0" step="0.1" value="0.5" />
          </label>
          <label>Number of traces: <span id="trace-count-value">100</span>
            <input id="trace-count-slider" type="range" min="10" max="500" step="10" value="100" />
          </label>
          <div class="button-row">
            <button id="generate-traces-btn">Generate Traces</button>
            <button id="run-cpa-btn">Run CPA Attack</button>
          </div>
        </div>

        <div class="panel inset-panel">
          <h3>CPA Result</h3>
          <div id="cpa-results" class="result-box" aria-live="polite">Awaiting traces.</div>
        </div>
      </div>

      <canvas id="trace-canvas" width="600" height="220" tabindex="0" role="img" aria-label="Simulated power traces for ML-KEM NTT leakage. Focus and use the arrow keys to read each sample."></canvas>
      <figcaption class="chart-legend">
        <span class="axes">X: NTT sample index &nbsp;·&nbsp; Y: simulated power (Hamming weight + noise)</span>
        <span class="swatch" style="--c:#00ff66">first 5 power traces — one per ciphertext</span>
      </figcaption>
      <div id="trace-hover" class="hint-line">Hover, tap, or focus the trace and use ← → keys to read each sample.</div>
      <div id="butterfly-grid" class="butterfly-grid"></div>
      <canvas id="cpa-canvas" width="600" height="220" role="img" aria-label="CPA histogram for all ML-KEM key hypotheses"></canvas>
      <figcaption class="chart-legend">
        <span class="axes">X: key hypothesis 0–3328 &nbsp;·&nbsp; Y: |correlation|</span>
        <span class="swatch" style="--c:#ffaa00">correlation per key guess</span>
        <span class="swatch" style="--c:#ff3366">true secret key</span>
      </figcaption>

      <div class="why-strip">
        <h3>Why does this work? Watch the signal separate from the noise</h3>
        <p class="small-text">
          As traces accumulate, the correlation for the <em>true</em> key climbs above the scatter of
          every wrong guess. One trace is nearly all noise; many traces average the noise down until
          the correct hypothesis stands alone.
        </p>
        <canvas id="cpa-growth-canvas" width="600" height="150" role="img" aria-label="Correlation of the true key hypothesis rising above the wrong-guess noise floor as traces accumulate"></canvas>
        <figcaption class="chart-legend">
          <span class="axes">X: number of traces used &nbsp;·&nbsp; Y: |correlation|</span>
          <span class="swatch" style="--c:#ff3366">true key</span>
          <span class="swatch swatch-dash" style="--c:#7fd0ff">noise floor (best wrong guess)</span>
        </figcaption>
        <p class="small-text honesty-note">
          <strong>Honest caveat:</strong> real single-trace NTT SCA does not read a full 0–3328 coefficient
          from one sample point. It correlates a leakage model over <em>many time samples</em> of the trace,
          and typically recovers a few key bits per butterfly before combining them. This exhibit compresses
          that into one correlation per hypothesis so the SNR intuition is visible — don't read it as
          "one point reveals the whole secret."
        </p>
      </div>

      <div class="context-bar">
        <strong>Countermeasure:</strong> first-order masking and shuffling reduce leakage at a cost of roughly 2–4× runtime.
      </div>
      <p class="exhibit-ref">
        Real-world basis: Primas, Pessl &amp; Mangard, <em>Single-Trace Side-Channel Attacks on Masked
        Lattice-Based Encryption</em>, CHES 2017 — full key recovery from one NTT trace.
        <a href="https://eprint.iacr.org/2017/594" target="_blank" rel="noopener">ePrint 2017/594</a>
      </p>
    </section>

    <details class="attack-reveal" id="reveal-2">
      <summary>
        <span class="reveal-step">Next attack →</span>
        <span class="reveal-title">Attack 2 · Fault injection on rejection sampling</span>
        <span class="reveal-hint">Now we inject a fault instead of reading one. Expand to continue.</span>
      </summary>
    <section class="exhibit panel" id="attack-2">
      <div class="exhibit-head">
        <div>
          <p class="kicker">SIMULATED • voltage glitch / EM fault</p>
          <h2>ATTACK 2: FAULT INJECTION ON REJECTION SAMPLING</h2>
          <p>If the rejection check is skipped, the returned signature coefficients become statistically leaky.</p>
        </div>
      </div>

      <div class="primer" role="note" aria-label="What's different this time">
        <h3>What's different this time</h3>
        <p class="small-text">
          Attack 1 <em>read</em> a leak passively. This one <em>injects</em> a fault. ML-DSA normally
          <strong>rejection-samples</strong>: it recomputes the signature <code>z = y + c·s₁</code> with a
          fresh random <code>y</code> and throws it away if any coefficient is too big, only releasing the
          safe ones — which decorrelates <code>z</code> from the secret. A voltage glitch that skips that
          check makes the device release the <em>first</em> <code>z</code> unconditionally. Now
          <code>z = y + c·s₁</code> is an unbiased sample; average many, the random <code>y</code> cancels,
          and the secret term <code>c·s₁</code> survives.
        </p>
      </div>

      <p class="attacker-story">
        <strong>You are the attacker:</strong> a signing device (an HSM or smartcard) will sign messages you
        submit. You glitch its power rail right as it evaluates the "is z within the bound?" check, so it
        forgets to resample. You collect thousands of these leaked signatures and average away the nonce.
      </p>

      <div class="sim-warning" role="note">
        ⚠ SIMULATED — this requires invasive fault injection against a signing device. The math is not broken.
      </div>

      <div class="grid-2">
        <div class="panel inset-panel">
          <h3>Normal signing</h3>
          <p class="small-text">All accepted outputs remain below the bound γ₁ − β.</p>
          <button id="normal-sign-btn">Sign 300 messages (rejection sampling)</button>
          <div id="normal-log" class="log-panel" aria-live="polite"></div>
        </div>

        <div class="panel inset-panel">
          <h3>Faulted signing</h3>
          <p class="small-text">Bypassing the rejection check releases signatures that should have been discarded.</p>
          <button id="faulted-sign-btn">Simulate 300 Faulted Signatures</button>
          <div id="faulted-log" class="log-panel" aria-live="polite"></div>
        </div>
      </div>

      <canvas id="rejection-canvas" width="600" height="220" role="img" aria-label="Distribution comparison of normal and faulted ML-DSA signature coefficients"></canvas>
      <figcaption class="chart-legend">
        <span class="axes">X: signature coefficient value &nbsp;·&nbsp; Y: count</span>
        <span class="swatch" style="--c:#00d4ff">accepted (normal signing)</span>
        <span class="swatch" style="--c:#ff3366">faulted (rejection skipped)</span>
        <span class="swatch swatch-dash" style="--c:#ffd166">±(γ₁−β) bound</span>
      </figcaption>
      <div class="button-row">
        <button id="recover-btn">Run Key Recovery from 8,000 Faulty Signatures</button>
      </div>
      <div id="recovery-panel" class="result-box" aria-live="polite">Recovery panel idle.</div>
      <p class="exhibit-ref">
        Real-world basis: <em>Key Recovery of CRYSTALS-Dilithium via rejection-sampling side channels</em>,
        IACR TCHES 2025 — recovers the ML-DSA private key once rejected/leaked responses are observed.
        <a href="https://eprint.iacr.org/2025/214" target="_blank" rel="noopener">ePrint 2025/214</a>
      </p>
    </section>
    </details>

    <details class="attack-reveal" id="reveal-3">
      <summary>
        <span class="reveal-step">Next attack →</span>
        <span class="reveal-title">Attack 3 · KyberSlash timing side-channel</span>
        <span class="reveal-hint">No probe, no glitcher — just a stopwatch. Expand to continue.</span>
      </summary>
    <section class="exhibit panel" id="attack-3">
      <div class="exhibit-head">
        <div>
          <p class="kicker">SIMULATED • timing side-channel</p>
          <h2>ATTACK 3: KYBERSLASH — TIMING SIDE-CHANNEL</h2>
          <p>A single secret-dependent integer division runs for a different number of cycles depending on the secret; constant-time code makes every division cost the same.</p>
        </div>
      </div>

      <div class="primer" role="note" aria-label="What's different this time">
        <h3>What's different this time</h3>
        <p class="small-text">
          Attacks 1–2 needed a probe or a glitcher. This one needs only a <em>stopwatch</em>. The bug is
          one line: Kyber decodes a coefficient with an integer divide <code>(2·v + q/2) / q</code>, and the
          <em>dividend carries the secret</em>. On a CPU with no hardware divider (Cortex-M4), that compiles
          to a shift-subtract loop whose <strong>iteration count grows with the magnitude of the dividend</strong>.
          Bigger secret-influenced value ⇒ more loop iterations ⇒ more cycles. Time the divide, learn the secret.
        </p>
      </div>

      <p class="attacker-story">
        <strong>You are the attacker:</strong> the target signs or decapsulates on request and you can
        measure how long each call takes. You send many ciphertexts, sort the decode times into clusters,
        and each cluster tells you one bit of the secret.
      </p>

      <div class="sim-warning" role="note">
        ⚠ SIMULATED — real exploitation needs repeated timing capture from the target hardware. Browser timers are much noisier.
      </div>

      <div class="button-row">
        <button id="run-vulnerable-btn">Run Divide Model — Vulnerable</button>
        <button id="run-constant-btn">Run Divide Model — Constant Time</button>
      </div>
      <canvas id="timing-canvas" width="600" height="240" role="img" aria-label="Histogram of restoring-division cycle counts, clustered by the secret bit each coefficient encodes"></canvas>
      <figcaption class="chart-legend">
        <span class="axes">X: modeled divide cycles (restoring shift-subtract steps) &nbsp;·&nbsp; Y: count</span>
        <span class="swatch" style="--c:#00d4ff">secret bit = 0 (small dividend)</span>
        <span class="swatch" style="--c:#ff3366">secret bit = 1 (large dividend)</span>
      </figcaption>
      <div class="context-bar">
        <strong>Why a histogram, not wall-clock:</strong> in-browser timers are quantized and Spectre-throttled,
        so <code>performance.now()</code> often hides or even inverts the gap. So we plot the <em>modeled divide-cycle
        count</em> from the real restoring-division routine instead. On a Cortex-M4 these two clusters are cleanly
        separated in actual cycles; the constant-time build collapses them into one.
      </div>
      <div id="timing-results" class="result-box" aria-live="polite">No divide-cycle measurements collected yet.</div>
      <p class="exhibit-ref">
        Real-world basis: Bernstein et al., <em>KyberSlash: Exploiting secret-dependent division timings in
        Kyber implementations</em>, 2024 — recovered ML-KEM keys on Cortex-M4 / Raspberry Pi; since patched
        with constant-time arithmetic.
        <a href="https://kyberslash.cr.yp.to/" target="_blank" rel="noopener">kyberslash.cr.yp.to</a>
        ·
        <a href="https://eprint.iacr.org/2024/1049" target="_blank" rel="noopener">ePrint 2024/1049</a>
      </p>
    </section>
    </details>

    <details class="attack-reveal" id="reveal-4">
      <summary>
        <span class="reveal-step">Next attack →</span>
        <span class="reveal-title">Attack 4 · Fault injection on KECCAK nonce generation</span>
        <span class="reveal-hint">The subtlest one: remove randomness and the signature betrays its own key. Expand to continue.</span>
      </summary>
    <section class="exhibit panel" id="attack-4">
      <div class="exhibit-head">
        <div>
          <p class="kicker">SIMULATED • faulty KECCAK absorption</p>
          <h2>ATTACK 4: FAULT INJECTION ON KECCAK SEED GENERATION</h2>
          <p>A loop-abort fault zeros the per-signature nonce, making the mask predictable — which collapses the y+c·s₁ blinding that hides the signing key.</p>
        </div>
      </div>

      <div class="primer" role="note" aria-label="What's different this time">
        <h3>What's different this time</h3>
        <p class="small-text">
          Attacks 1–3 read a leak; this one <em>removes randomness</em>. ML-DSA hides the secret in every
          signature with a fresh nonce: it releases <code>z = y + c·s₁</code>, where <code>y</code> is a
          one-time mask expanded from a KECCAK/SHAKE call. You see <code>z</code> and the challenge
          <code>c</code>, but not <code>y</code> — so <code>s₁</code> stays hidden. A <em>loop-abort</em>
          fault ends the nonce-expansion loop early, leaving <code>y</code> at a predictable value the
          attacker can recompute from public data. Once <code>y</code> is known, subtract it and solve
          <code>s₁ = (z − y) / (17·c)</code>. The blinding is gone.
        </p>
      </div>

      <p class="attacker-story">
        <strong>You are the attacker:</strong> you have physical access to a smartcard signing with ML-DSA.
        You glitch its clock at the moment it expands the nonce, aborting that loop. The signature it hands
        back is now masked by a nonce <em>you</em> can reconstruct — so its own output betrays the key.
      </p>

      <div class="sim-warning" role="note">
        ⚠ SIMULATED — this is a physical-fault demo, not a practical browser attack tool.
      </div>

      <div class="button-row">
        <button id="run-keccak-btn">Run Attack Simulation</button>
      </div>
      <canvas id="keccak-canvas" width="600" height="260" role="img" aria-label="KECCAK sponge-state comparison: the highlighted lanes are the bytes that actually differ between the honest and faulted nonce derivation"></canvas>
      <figcaption class="chart-legend">
        <span class="axes">5×5 sponge state — left: honest absorb (random κ) &nbsp;·&nbsp; right: faulted absorb (κ zeroed)</span>
        <span class="swatch" style="--c:#00d4ff">lane byte intensity</span>
        <span class="swatch" style="--c:#ff3366">lanes that actually differ (diffed, not hardcoded)</span>
      </figcaption>
      <div class="context-bar">
        <strong>Primitive caveat:</strong> the real derivation uses SHAKE-256 (a KECCAK sponge). This demo
        substitutes SHA-256 in a counter-based XOF as a browser-native stand-in — the sponge <em>diffusion</em>
        is illustrative, but the collapse of the <code>y</code>-mask is the faithful part of the lesson.
      </div>
      <div id="keccak-results" class="result-box" aria-live="polite">Awaiting KECCAK simulation.</div>
      <p class="exhibit-ref">
        Real-world basis: Espitau, Fouque, Gérard &amp; Tibouchi, <em>Loop-Abort Faults on Lattice-Based
        Fiat–Shamir and Hash-and-Sign Signatures</em>, SAC 2016 — a loop-abort fault leaves the commitment
        (nonce) at zero, exposing the signing key.
        <a href="https://eprint.iacr.org/2016/449" target="_blank" rel="noopener">ePrint 2016/449</a>
      </p>
    </section>
    </details>

    <section class="exhibit panel" id="attack-5">
      <div class="exhibit-head">
        <div>
          <p class="kicker">Implementation security</p>
          <h2>ATTACK 5: THE BIGGER PICTURE</h2>
          <p>Mathematical security and implementation security are separate requirements for deployed PQC.</p>
        </div>
      </div>

      <div class="comparison-table-wrap" tabindex="0" role="region" aria-label="Attack and countermeasure comparison">
        <table>
          <thead>
            <tr>
              <th>Attack</th>
              <th>Countermeasure</th>
              <th>Overhead</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>NTT power SCA</td><td>First-order masking</td><td>2–4×</td><td>Available</td></tr>
            <tr><td>NTT power SCA</td><td>Shuffling</td><td>10–20%</td><td>Available</td></tr>
            <tr><td>Rejection bypass</td><td>Output consistency check</td><td>~10%</td><td>Available</td></tr>
            <tr><td>KyberSlash timing</td><td>Constant-time assembly</td><td>0–5%</td><td>Patched</td></tr>
            <tr><td>Faulty KECCAK</td><td>Redundant KECCAK + compare</td><td>~50%</td><td>Research prototype</td></tr>
          </tbody>
        </table>
      </div>

      <div class="grid-2">
        <div class="panel inset-panel">
          <h3>Takeaway</h3>
          <ul>
            <li>ML-KEM and ML-DSA survive the mathematical attack surface.</li>
            <li>Physical side-channels and fault attacks remain relevant on embedded hardware.</li>
            <li>PQC migration must include masking, constant-time code, and fault checks.</li>
          </ul>
        </div>
        <div class="panel inset-panel">
          <h3>Related demos</h3>
          <ul>
            <li>crypto-lab-lll-break</li>
            <li>crypto-lab-kyber-vault</li>
            <li>crypto-lab-dilithium-seal</li>
            <li>crypto-lab-timing-oracle</li>
            <li>crypto-lab-padding-oracle</li>
          </ul>
        </div>
      </div>

      <div class="panel inset-panel">
        <h3>Further reading</h3>
        <p class="small-text">
          Standards: ML-KEM is <a href="https://csrc.nist.gov/pubs/fips/203/final" target="_blank" rel="noopener">NIST FIPS 203</a>;
          ML-DSA is <a href="https://csrc.nist.gov/pubs/fips/204/final" target="_blank" rel="noopener">FIPS 204</a>
          (both finalized 2024). The math is standardized — the attacks below target implementations.
        </p>
        <ul class="references-list">
          <li>
            <strong>NTT power SCA →</strong> Primas, Pessl &amp; Mangard, <em>Single-Trace Side-Channel Attacks
            on Masked Lattice-Based Encryption</em>, CHES 2017.
            <a href="https://eprint.iacr.org/2017/594" target="_blank" rel="noopener">ePrint 2017/594</a>
          </li>
          <li>
            <strong>Rejection-sampling leakage →</strong> <em>Key Recovery of CRYSTALS-Dilithium via
            Side-Channel Attacks</em>, IACR TCHES 2025.
            <a href="https://eprint.iacr.org/2025/214" target="_blank" rel="noopener">ePrint 2025/214</a>
          </li>
          <li>
            <strong>KyberSlash timing →</strong> Bernstein et al., <em>Exploiting secret-dependent division
            timings in Kyber</em>, 2024.
            <a href="https://kyberslash.cr.yp.to/" target="_blank" rel="noopener">kyberslash.cr.yp.to</a> ·
            <a href="https://eprint.iacr.org/2024/1049" target="_blank" rel="noopener">ePrint 2024/1049</a>
          </li>
          <li>
            <strong>Loop-abort faults →</strong> Espitau, Fouque, Gérard &amp; Tibouchi, <em>Loop-Abort Faults
            on Lattice-Based Fiat–Shamir and Hash-and-Sign Signatures</em>, SAC 2016.
            <a href="https://eprint.iacr.org/2016/449" target="_blank" rel="noopener">ePrint 2016/449</a>
          </li>
        </ul>
      </div>
    </section>

  </main>
`;

type Theme = 'dark' | 'light';

type TimingKey = 'vulnerable' | 'constant-time';

type RejectionEntry = {
  y: Int32Array;
  z: Int32Array;
  status?: 'accepted' | 'rejected';
  maxCoeff: number;
  wouldReject?: boolean;
  faulted?: boolean;
};

function must<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) {
    throw new Error(`Missing element: ${selector}`);
  }
  return element;
}

function formatNumber(value: number, digits = 2): string {
  return Number.isFinite(value) ? value.toFixed(digits) : '0.00';
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

/** Yield to the browser so a pending DOM update actually paints before heavy work. */
function nextFrame(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  });
}

/** Run `work` while the button shows a busy state and is disabled, then restore it. */
async function withBusy<T>(button: HTMLButtonElement, label: string, work: () => Promise<T>): Promise<T> {
  const original = button.textContent;
  button.disabled = true;
  button.dataset.busy = 'true';
  button.textContent = label;
  await nextFrame();
  try {
    return await work();
  } finally {
    button.disabled = false;
    delete button.dataset.busy;
    button.textContent = original;
  }
}

function clearPlot(canvas: HTMLCanvasElement): CanvasRenderingContext2D {
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    throw new Error('2D canvas unavailable');
  }

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#041008';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = 'rgba(0, 255, 102, 0.14)';
  ctx.lineWidth = 1;

  for (let x = 0; x <= canvas.width; x += 50) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, canvas.height);
    ctx.stroke();
  }

  for (let y = 0; y <= canvas.height; y += 40) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(canvas.width, y);
    ctx.stroke();
  }

  return ctx;
}

function valueRange(seriesList: number[][]): { min: number; max: number } {
  const values = seriesList.flat();
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (!Number.isFinite(min) || !Number.isFinite(max) || min === max) {
    return { min: -1, max: 1 };
  }
  return { min, max };
}

function drawLineSeries(
  canvas: HTMLCanvasElement,
  seriesList: number[][],
  colors: string[],
  highlights: number[] = [],
  dashes: number[][] = [],
): void {
  const ctx = clearPlot(canvas);
  const { min, max } = valueRange(seriesList);
  const pad = 18;
  const usableHeight = canvas.height - pad * 2;
  const usableWidth = canvas.width - pad * 2;

  seriesList.forEach((series, seriesIndex) => {
    ctx.beginPath();
    ctx.lineWidth = highlights.includes(seriesIndex) ? 2.4 : 1.35;
    ctx.strokeStyle = colors[seriesIndex] ?? '#00ff66';
    // Distinct dash pattern per series so the lines stay distinguishable
    // without relying on color alone (WCAG 1.4.1).
    ctx.setLineDash(dashes[seriesIndex] ?? []);

    series.forEach((value, index) => {
      const x = pad + (index / Math.max(series.length - 1, 1)) * usableWidth;
      const y = pad + usableHeight - ((value - min) / Math.max(max - min, 1e-9)) * usableHeight;
      if (index === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    });

    ctx.stroke();
  });

  ctx.setLineDash([]);
}

function drawHistogram(
  canvas: HTMLCanvasElement,
  values: number[],
  highlightValue?: number,
  secondaryValues?: number[],
): void {
  const ctx = clearPlot(canvas);
  const bins = 48;
  const combined = secondaryValues ? values.concat(secondaryValues) : values;
  const min = Math.min(...combined);
  const max = Math.max(...combined);
  const span = Math.max(max - min, 1);
  const binWidth = span / bins;
  const primary = new Array<number>(bins).fill(0);
  const secondary = new Array<number>(bins).fill(0);

  values.forEach((value) => {
    const idx = clamp(Math.floor((value - min) / binWidth), 0, bins - 1);
    primary[idx] += 1;
  });

  (secondaryValues ?? []).forEach((value) => {
    const idx = clamp(Math.floor((value - min) / binWidth), 0, bins - 1);
    secondary[idx] += 1;
  });

  // Normalize each series to its own peak so the two distributions are
  // compared by shape, not by sample count (the accepted and faulted sets
  // legitimately differ in size).
  const maxPrimary = Math.max(...primary, 1);
  const maxSecondary = Math.max(...secondary, 1);

  for (let i = 0; i < bins; i += 1) {
    const x = 12 + (i / bins) * (canvas.width - 24);
    const width = (canvas.width - 24) / bins - 2;
    const h1 = (primary[i] / maxPrimary) * (canvas.height - 32);
    const h2 = (secondary[i] / maxSecondary) * (canvas.height - 32);

    ctx.fillStyle = 'rgba(0, 212, 255, 0.55)';
    ctx.fillRect(x, canvas.height - 12 - h1, width, h1);

    if (secondaryValues) {
      ctx.fillStyle = 'rgba(255, 51, 102, 0.55)';
      ctx.fillRect(x, canvas.height - 12 - h2, width, h2);
    }
  }

  if (typeof highlightValue === 'number') {
    // Draw the ±bound as dashed guide lines so the faulted tails that spill
    // past the rejection boundary are unmistakable.
    ctx.strokeStyle = '#ffd166';
    ctx.lineWidth = 1.5;
    ctx.setLineDash([5, 4]);
    for (const bound of [highlightValue, -highlightValue]) {
      const x = 12 + ((bound - min) / span) * (canvas.width - 24);
      if (x < 12 || x > canvas.width - 12) {
        continue;
      }
      ctx.beginPath();
      ctx.moveTo(x, 10);
      ctx.lineTo(x, canvas.height - 10);
      ctx.stroke();
    }
    ctx.setLineDash([]);
  }
}

function drawCorrelationPlot(canvas: HTMLCanvasElement, scores: Float64Array, secretKey: number): void {
  const ctx = clearPlot(canvas);
  const values = Array.from(scores, (score) => Math.abs(score));
  const maxValue = Math.max(...values, 1e-9);
  const pad = 16;

  ctx.beginPath();
  ctx.lineWidth = 1.4;
  ctx.strokeStyle = 'rgba(255, 170, 0, 0.5)';

  values.forEach((value, index) => {
    const x = pad + (index / Math.max(values.length - 1, 1)) * (canvas.width - pad * 2);
    const y = canvas.height - pad - (value / maxValue) * (canvas.height - pad * 2);
    if (index === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });

  ctx.stroke();

  const spikeX = pad + (secretKey / Math.max(values.length - 1, 1)) * (canvas.width - pad * 2);
  ctx.strokeStyle = '#ff3366';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(spikeX, 8);
  ctx.lineTo(spikeX, canvas.height - 8);
  ctx.stroke();
}

function drawGrowthPlot(
  canvas: HTMLCanvasElement,
  counts: number[],
  trueScores: number[],
  noiseFloor: number[],
): void {
  const ctx = clearPlot(canvas);
  if (counts.length === 0) {
    return;
  }
  const pad = 20;
  const usableW = canvas.width - pad * 2;
  const usableH = canvas.height - pad * 2;
  const maxCount = Math.max(...counts, 1);
  const maxY = Math.max(...trueScores, ...noiseFloor, 0.1);

  const xAt = (count: number): number => pad + (count / maxCount) * usableW;
  const yAt = (value: number): number => pad + usableH - (value / maxY) * usableH;

  const plot = (values: number[], color: string, dash: number[]): void => {
    ctx.beginPath();
    ctx.lineWidth = 2;
    ctx.strokeStyle = color;
    ctx.setLineDash(dash);
    values.forEach((value, index) => {
      const x = xAt(counts[index] ?? 0);
      const y = yAt(value);
      if (index === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    });
    ctx.stroke();
    ctx.setLineDash([]);
  };

  // Noise floor first (behind), then the true-key curve on top.
  plot(noiseFloor, '#7fd0ff', [7, 5]);
  plot(trueScores, '#ff3366', []);
}

function updateThemeToggle(theme: Theme): void {
  themeButton.textContent = theme === 'dark' ? '🌙' : '☀️';
  themeButton.setAttribute(
    'aria-label',
    theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
  );
}

function toggleTheme(): void {
  const current = (document.documentElement.getAttribute('data-theme') ?? 'dark') as Theme;
  const next: Theme = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  updateThemeToggle(next);
}

const themeButton = must<HTMLButtonElement>('#theme-toggle');
updateThemeToggle((document.documentElement.getAttribute('data-theme') ?? 'dark') as Theme);
themeButton.addEventListener('click', toggleTheme);

const traceCanvas = must<HTMLCanvasElement>('#trace-canvas');
const cpaCanvas = must<HTMLCanvasElement>('#cpa-canvas');
const cpaGrowthCanvas = must<HTMLCanvasElement>('#cpa-growth-canvas');
const rejectionCanvas = must<HTMLCanvasElement>('#rejection-canvas');
const timingCanvas = must<HTMLCanvasElement>('#timing-canvas');
const keccakCanvas = must<HTMLCanvasElement>('#keccak-canvas');
const traceHover = must<HTMLDivElement>('#trace-hover');
const butterflyGrid = must<HTMLDivElement>('#butterfly-grid');
const cpaResults = must<HTMLDivElement>('#cpa-results');
const normalLog = must<HTMLDivElement>('#normal-log');
const faultedLog = must<HTMLDivElement>('#faulted-log');
const recoveryPanel = must<HTMLDivElement>('#recovery-panel');
const timingResults = must<HTMLDivElement>('#timing-results');
const keccakResults = must<HTMLDivElement>('#keccak-results');

const skSlider = must<HTMLInputElement>('#sk-slider');
const ctSlider = must<HTMLInputElement>('#ct-slider');
const noiseSlider = must<HTMLInputElement>('#noise-slider');
const traceCountSlider = must<HTMLInputElement>('#trace-count-slider');
const skValue = must<HTMLSpanElement>('#sk-value');
const ctValue = must<HTMLSpanElement>('#ct-value');
const noiseValue = must<HTMLSpanElement>('#noise-value');
const traceCountValue = must<HTMLSpanElement>('#trace-count-value');

const traceState = {
  secret: 1234,
  baseCipher: 567,
  noise: 0.5,
  count: 100,
  ciphertexts: [] as number[],
  traces: [] as Float64Array[],
};

let rejectionSecret = new Int32Array(Array.from({ length: 256 }, () => randomIntInclusive(-ML_DSA_PARAMS.eta, ML_DSA_PARAMS.eta)));
let rejectionChallenge = new Int32Array(Array.from({ length: 256 }, () => (randomIntInclusive(0, 1) === 0 ? -1 : 1)));
let normalEntries: RejectionEntry[] = [];
let faultedEntries: RejectionEntry[] = [];
const timingState: Partial<Record<TimingKey, ClusterExperiment>> = {};

function renderSliderValues(): void {
  skValue.textContent = skSlider.value;
  ctValue.textContent = ctSlider.value;
  noiseValue.textContent = noiseSlider.value;
  traceCountValue.textContent = traceCountSlider.value;
}

[skSlider, ctSlider, noiseSlider, traceCountSlider].forEach((input) => {
  input.addEventListener('input', renderSliderValues);
});
renderSliderValues();

function renderButterflies(secret: number, cipher: number): void {
  let a = secret;
  let b = cipher;
  const zetas = [17, 3312, 2761, 568, 583, 2746, 2649, 680];

  butterflyGrid.innerHTML = zetas.map((zeta, index) => {
    const result = nttButterfly(a, b, zeta);
    const weights = result.intermediates.map((value) => hammingWeight(value));
    a = result.a_out;
    b = result.b_out;
    const hot = Math.max(...weights) >= 8 ? 'hot' : '';

    return `
      <article class="butterfly-card ${hot}">
        <h4>Stage ${index + 1}</h4>
        <p>zeta = ${zeta}</p>
        <p>w·b = ${result.intermediates[0]} (HW ${weights[0]})</p>
        <p>a + wb = ${result.intermediates[1]} (HW ${weights[1]})</p>
        <p>a − wb = ${result.intermediates[2]} (HW ${weights[2]})</p>
      </article>
    `;
  }).join('');
}

async function generateTraces(): Promise<void> {
  traceState.secret = Number(skSlider.value);
  traceState.baseCipher = Number(ctSlider.value);
  traceState.noise = Number(noiseSlider.value);
  traceState.count = Number(traceCountSlider.value);
  traceState.ciphertexts = Array.from(
    { length: traceState.count },
    (_, index) => (traceState.baseCipher + index * 37) % Q,
  );
  traceState.traces = [];

  for (const ct of traceState.ciphertexts) {
    traceState.traces.push(await simulatePowerTrace(traceState.secret, ct, traceState.noise));
  }

  const visible = traceState.traces.slice(0, 5).map((trace) => Array.from(trace));
  drawLineSeries(traceCanvas, visible, ['#00ff66', '#24d97a', '#47c98a', '#8be3a8', '#d0ffde']);
  renderButterflies(traceState.secret, traceState.ciphertexts[0] ?? traceState.baseCipher);
  cpaResults.innerHTML = '<p>Traces generated. Ready to test all 3,329 hypotheses.</p>';
}

// Power-trace readout, reachable by mouse, touch, AND keyboard so the exhibit
// meets WCAG 2.1.1 and works on mobile. `traceCursor` is the focused sample.
let traceCursor = 0;

function showTraceSample(sampleIndex: number): void {
  const trace = traceState.traces[0];
  if (!trace) {
    return;
  }
  traceCursor = clamp(sampleIndex, 0, trace.length - 1);
  const power = trace[traceCursor] ?? 0;
  traceHover.textContent = `Sample ${traceCursor} of ${trace.length - 1}: measured power ${formatNumber(power, 3)} — see the butterfly cards below for the exact Hamming weights.`;
}

function sampleFromClientX(clientX: number): number {
  const trace = traceState.traces[0];
  if (!trace) {
    return 0;
  }
  const rect = traceCanvas.getBoundingClientRect();
  return Math.round(((clientX - rect.left) / Math.max(rect.width, 1)) * (trace.length - 1));
}

traceCanvas.addEventListener('mousemove', (event) => {
  showTraceSample(sampleFromClientX(event.clientX));
});

traceCanvas.addEventListener('touchmove', (event) => {
  const touch = event.touches[0];
  if (!touch) {
    return;
  }
  event.preventDefault(); // keep the readout from scrolling the page
  showTraceSample(sampleFromClientX(touch.clientX));
}, { passive: false });

traceCanvas.addEventListener('keydown', (event) => {
  const trace = traceState.traces[0];
  if (!trace) {
    return;
  }
  const step = event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1
    : event.key === 'Home' ? -trace.length : event.key === 'End' ? trace.length : 0;
  if (step === 0) {
    return;
  }
  event.preventDefault();
  showTraceSample(traceCursor + step);
});

must<HTMLButtonElement>('#generate-traces-btn').addEventListener('click', () => {
  void generateTraces();
});

const runCpaButton = must<HTMLButtonElement>('#run-cpa-btn');
runCpaButton.addEventListener('click', () => {
  void withBusy(runCpaButton, 'Running CPA…', async () => {
    if (traceState.traces.length === 0) {
      await generateTraces();
    }

    cpaResults.innerHTML = `<p>Running CPA across ${Q.toLocaleString()} key guesses over ${traceState.traces.length} traces…</p>`;
    await nextFrame();

    const scores = correlationPowerAnalysis(traceState.traces, traceState.ciphertexts, 1);
    const ranked = Array.from(scores, (score, key) => ({ key, score: Math.abs(score) }))
      .sort((left, right) => right.score - left.score)
      .slice(0, 5);

    drawCorrelationPlot(cpaCanvas, scores, traceState.secret);

    const growth = cpaCorrelationGrowth(
      traceState.traces,
      traceState.ciphertexts,
      traceState.secret,
      1,
    );
    drawGrowthPlot(cpaGrowthCanvas, growth.counts, growth.trueScores, growth.noiseFloor);

    const recovered = ranked[0]?.key === traceState.secret;
    const margin = ranked.length > 1 ? (ranked[0]!.score - ranked[1]!.score) : 0;

    cpaResults.innerHTML = `
      <p><strong>Best correlation:</strong> k = ${ranked[0]?.key} (${formatNumber(ranked[0]?.score ?? 0, 3)})</p>
      <p><strong>Correct key:</strong> sk[0] = ${traceState.secret} ${recovered ? '✓ RECOVERED' : '• top guess is off — add traces or lower noise'}</p>
      <p class="small-text">Lead over 2nd-best hypothesis: ${formatNumber(margin, 3)}</p>
      <ul>
        ${ranked.map((entry) => `<li>k = ${entry.key} → ${formatNumber(entry.score, 3)}</li>`).join('')}
      </ul>
    `;
  });
});

function flattenCoefficients(entries: RejectionEntry[], limit = 4000): number[] {
  return entries.flatMap((entry) => Array.from(entry.z).slice(0, 32)).slice(0, limit);
}

function renderRejectionLogs(): void {
  if (normalEntries.length === 0) {
    normalLog.innerHTML = 'No normal signatures collected yet.';
  } else {
    const accepted = normalEntries.filter((entry) => entry.status === 'accepted').length;
    normalLog.innerHTML = `
      <p class="small-text">${accepted} of ${normalEntries.length} attempts accepted; the rest were resampled. Every accepted z stays within the γ₁−β bound.</p>
      <ul>${normalEntries.slice(0, 8).map((entry, index) => `<li>Attempt ${index + 1}: z_max = ${entry.maxCoeff} ${entry.status === 'accepted' ? '✓ Accept' : '✗ Reject'}</li>`).join('')}</ul>`;
  }

  if (faultedEntries.length === 0) {
    faultedLog.innerHTML = 'No faulted signatures collected yet.';
  } else {
    const leaked = faultedEntries.filter((entry) => entry.wouldReject).length;
    const pct = formatNumber((leaked / faultedEntries.length) * 100, 0);
    faultedLog.innerHTML = `
      <p class="small-text">${leaked} of ${faultedEntries.length} released signatures (${pct}%) exceed the γ₁−β bound a correct signer would have rejected.</p>
      <ul>${faultedEntries.slice(0, 8).map((entry, index) => `<li>Signature ${index + 1}: z_max = ${entry.maxCoeff} ${entry.wouldReject ? '⚠ over bound — leaked' : '• within bound — released'}</li>`).join('')}</ul>`;
  }

  const normalValues = flattenCoefficients(normalEntries.filter((entry) => entry.status === 'accepted'));
  const faultValues = flattenCoefficients(faultedEntries);

  if (normalValues.length > 0 || faultValues.length > 0) {
    drawHistogram(rejectionCanvas, normalValues, ML_DSA_PARAMS.gamma1 - ML_DSA_PARAMS.beta, faultValues);
  }
}

must<HTMLButtonElement>('#normal-sign-btn').addEventListener('click', async () => {
  rejectionSecret = new Int32Array(Array.from({ length: 256 }, () => randomIntInclusive(-ML_DSA_PARAMS.eta, ML_DSA_PARAMS.eta)));
  rejectionChallenge = new Int32Array(Array.from({ length: 256 }, () => (randomIntInclusive(0, 1) === 0 ? -1 : 1)));
  normalEntries = await signWithRejection(rejectionSecret, rejectionChallenge, ML_DSA_PARAMS, 300);
  renderRejectionLogs();
});

must<HTMLButtonElement>('#faulted-sign-btn').addEventListener('click', async () => {
  if (normalEntries.length === 0) {
    rejectionSecret = new Int32Array(Array.from({ length: 256 }, () => randomIntInclusive(-ML_DSA_PARAMS.eta, ML_DSA_PARAMS.eta)));
    rejectionChallenge = new Int32Array(Array.from({ length: 256 }, () => (randomIntInclusive(0, 1) === 0 ? -1 : 1)));
  }

  faultedEntries = await signWithFaultedRejection(rejectionSecret, rejectionChallenge, ML_DSA_PARAMS, 300);
  renderRejectionLogs();
});

const recoverButton = must<HTMLButtonElement>('#recover-btn');
recoverButton.addEventListener('click', () => {
  void withBusy(recoverButton, 'Recovering key…', runRecovery);
});

const RECOVERY_SIGNATURE_COUNT = 8000;

async function runRecovery(): Promise<void> {
  recoveryPanel.innerHTML = `<p>Collecting ${RECOVERY_SIGNATURE_COUNT.toLocaleString()} faulted signatures and averaging out the random nonce…</p>`;
  await nextFrame();

  faultedEntries = await signWithFaultedRejection(
    rejectionSecret,
    rejectionChallenge,
    ML_DSA_PARAMS,
    RECOVERY_SIGNATURE_COUNT,
    (pct) => {
      recoveryPanel.innerHTML = `<p>Collecting faulted signatures… ${formatNumber(pct, 0)}%</p>`;
    },
  );
  renderRejectionLogs();
  recoveryPanel.innerHTML = '<p>Solving for s₁ across 256 coefficients…</p>';
  await nextFrame();

  const recovery = recoverFromFaultySignatures(
    faultedEntries.map((entry) => entry.z),
    Array.from({ length: faultedEntries.length }, () => rejectionChallenge),
    ML_DSA_PARAMS,
  );

  let correct = 0;
  for (let index = 0; index < rejectionSecret.length; index += 1) {
    if (recovery.recovered[index] === rejectionSecret[index]) {
      correct += 1;
    }
  }

  const rate = (correct / rejectionSecret.length) * 100;
  recoveryPanel.innerHTML = `
    <p><strong>Recovery rate:</strong> ${formatNumber(rate, 1)}% — ${correct} of ${rejectionSecret.length} secret coefficients exactly recovered (random guessing ≈ 20%).</p>
    <p>Sample recovery:</p>
    <ul>
      ${Array.from({ length: 8 }, (_, index) => `<li>s₁[${index}] ≈ ${recovery.recovered[index]} (actual ${rejectionSecret[index]}) • confidence ${formatNumber(recovery.confidence[index] ?? 0, 2)}</li>`).join('')}
    </ul>
    <p><strong>Countermeasure:</strong> recompute and verify the output before returning the signature.</p>
  `;
}

const CLUSTER_REPETITIONS = 4000;
const CLUSTER_BINS = 40;

/**
 * Draw the two clusters of divide-cycle counts as an overlaid histogram.
 * The "secret bit = 0" (small dividend) and "secret bit = 1" (large dividend)
 * classes get their own colour; when they are cleanly separated the learner
 * sees two distinct humps, and the constant-time build collapses them into one.
 */
function drawClusterHistogram(experiment: ClusterExperiment | undefined): void {
  const ctx = clearPlot(timingCanvas);
  if (!experiment) {
    return;
  }
  const all = [...experiment.small, ...experiment.large];
  const min = Math.min(...all);
  const max = Math.max(...all);
  const span = Math.max(max - min, 1);
  const binWidth = span / CLUSTER_BINS;

  const bin = (values: number[]): number[] => {
    const out = new Array<number>(CLUSTER_BINS).fill(0);
    values.forEach((value) => {
      const idx = clamp(Math.floor((value - min) / binWidth), 0, CLUSTER_BINS - 1);
      out[idx] += 1;
    });
    return out;
  };

  const smallBins = bin(experiment.small);
  const largeBins = bin(experiment.large);
  const peak = Math.max(...smallBins, ...largeBins, 1);
  const usableH = timingCanvas.height - 30;
  const barW = (timingCanvas.width - 24) / CLUSTER_BINS;

  const drawBars = (bins: number[], color: string): void => {
    ctx.fillStyle = color;
    bins.forEach((count, i) => {
      if (count === 0) return;
      const x = 12 + i * barW;
      const h = (count / peak) * usableH;
      ctx.fillRect(x, timingCanvas.height - 12 - h, Math.max(barW - 1, 1), h);
    });
  };

  // bit 0 (small dividend) in cyan, bit 1 (large dividend) in red; drawn
  // semi-transparent so overlap (the constant-time case) is visible.
  drawBars(smallBins, 'rgba(0, 212, 255, 0.62)');
  drawBars(largeBins, 'rgba(255, 51, 102, 0.62)');
}

function renderTimingReport(): void {
  const vulnerable = timingState.vulnerable;
  const constant = timingState['constant-time'];

  const line = (label: string, x?: ClusterExperiment): string => {
    if (!x) return '';
    const gap = Math.abs(x.meanLarge - x.meanSmall);
    return `<p><strong>${label}:</strong> bit-0 class ≈ ${formatNumber(x.meanSmall, 1)} cycles,
      bit-1 class ≈ ${formatNumber(x.meanLarge, 1)} cycles, separation = ${formatNumber(gap, 1)} cycles —
      ${x.separated ? 'clusters are cleanly distinguishable ✓ the secret bit leaks' : 'clusters overlap — no usable leak'}.</p>`;
  };

  const blocks = [line('Vulnerable divide', vulnerable), line('Constant-time divide', constant)].filter(Boolean);

  const comparison = vulnerable && constant
    ? `<p><strong>Comparison:</strong> the vulnerable divide separates the two secret classes by
       ${formatNumber(Math.abs(vulnerable.meanLarge - vulnerable.meanSmall), 1)} cycles; the constant-time
       divide collapses them to ${formatNumber(Math.abs(constant.meanLarge - constant.meanSmall), 1)} cycles —
       one hump, no leak.</p>`
    : '<p>Run both models to see the vulnerable clusters collapse under constant-time code.</p>';

  timingResults.innerHTML = blocks.join('') + comparison;
}

const vulnerableButton = must<HTMLButtonElement>('#run-vulnerable-btn');
const constantButton = must<HTMLButtonElement>('#run-constant-btn');

/**
 * Run the cluster experiment. Prefer a Web Worker so the model runs off the main
 * thread; fall back to a synchronous call when Worker is unavailable (e.g. the
 * jsdom test realm). Either way the numbers come from runClusterExperiment.
 */
function runClusterInWorker(kind: TimingKey): Promise<ClusterExperiment> {
  if (typeof Worker === 'undefined') {
    return Promise.resolve(runClusterExperiment(kind, CLUSTER_REPETITIONS));
  }
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./timing.worker.ts', import.meta.url), { type: 'module' });
    worker.addEventListener('message', (event: MessageEvent<ClusterExperiment>) => {
      resolve(event.data);
      worker.terminate();
    });
    worker.addEventListener('error', (event) => {
      reject(event.error ?? new Error('timing worker failed'));
      worker.terminate();
    });
    const request: TimingWorkerRequest = { implementation: kind, repetitions: CLUSTER_REPETITIONS };
    worker.postMessage(request);
  });
}

async function runTiming(kind: TimingKey): Promise<void> {
  vulnerableButton.disabled = true;
  constantButton.disabled = true;
  timingResults.innerHTML = `<p>Running ${CLUSTER_REPETITIONS.toLocaleString()} ${kind} divides in a worker…</p>`;
  await nextFrame();
  try {
    timingState[kind] = await runClusterInWorker(kind);
    // Show the just-run experiment; if both exist, prefer the vulnerable one so
    // the separated clusters remain visible.
    drawClusterHistogram(timingState.vulnerable ?? timingState[kind]);
    renderTimingReport();
  } finally {
    vulnerableButton.disabled = false;
    constantButton.disabled = false;
  }
}

vulnerableButton.addEventListener('click', () => {
  void runTiming('vulnerable');
});

constantButton.addEventListener('click', () => {
  void runTiming('constant-time');
});

function drawKeccakGrid(
  normalLanes: bigint[],
  faultedLanes: bigint[],
  laneChanged: boolean[],
): void {
  const ctx = clearPlot(keccakCanvas);
  const cell = 44;
  // `highlightChanged` colors a lane red only when it TRULY differs from its
  // counterpart in the other run — a real diff, not a hardcoded column.
  const drawOne = (offsetX: number, lanes: bigint[], title: string, highlightChanged: boolean) => {
    ctx.fillStyle = '#d7ffe5';
    ctx.font = '14px sans-serif';
    ctx.fillText(title, offsetX, 20);

    for (let row = 0; row < 5; row += 1) {
      for (let col = 0; col < 5; col += 1) {
        const index = row * 5 + col;
        const lane = lanes[index] ?? 0n;
        const intensity = Number(lane & 255n) / 255;
        const changed = laneChanged[index] === true;
        const hue = highlightChanged && changed ? 'rgba(255, 51, 102,' : 'rgba(0, 212, 255,';
        ctx.fillStyle = `${hue}${0.25 + intensity * 0.6})`;
        ctx.fillRect(offsetX + col * cell, 32 + row * cell, cell - 4, cell - 4);
      }
    }
  };

  drawOne(30, normalLanes, 'Honest absorb (random κ)', false);
  drawOne(320, faultedLanes, 'Faulted absorb (κ = 0)', true);
}

must<HTMLButtonElement>('#run-keccak-btn').addEventListener('click', async () => {
  keccakResults.innerHTML = '<p>Aborting the nonce-expansion loop…</p>';
  const result = await simulateFaultyKeccakAttack();
  drawKeccakGrid(result.normalLanes, result.faultedLanes, result.laneChanged);
  const changedCount = result.laneChanged.filter(Boolean).length;
  // Does the attacker's PUBLIC-only guess of y match reality? Only in the faulted run.
  const normalGuessMatches = result.predictedNormalY.every(
    (value, index) => value === result.normalY[index],
  );
  keccakResults.innerHTML = `
    <p><strong>Honest derivation:</strong> ${result.normalInput}</p>
    <p><strong>Faulted derivation:</strong> ${result.faultedInput}</p>
    <p><strong>Lanes actually changed by the fault:</strong> ${changedCount} of 25 (highlighted red on the right).</p>
    <hr />
    <p><strong>The mask, honest run:</strong> the attacker's best public guess of y (κ=0) matches the
      real nonce? <strong>${normalGuessMatches ? 'yes' : 'no'}</strong> — the fresh random κ keeps y hidden,
      so z = y + c·s₁ stays blinded and s₁ is safe.</p>
    <p><strong>The mask, faulted run:</strong> attacker recomputes y from public data only (κ=0)
      and it matches the real faulted nonce? <strong>${result.maskingCollapsed ? 'yes' : 'no'}</strong>.
      With y now known, subtract it: s₁ = (z − y) / (17·c).</p>
    <p><strong>Recovered s₁[0..7]:</strong> [${Array.from(result.recovered).join(', ')}]
      &nbsp;vs actual [${Array.from(result.secret).join(', ')}] → ${result.success ? 'exact match ✓ key recovered' : 'no match'}.</p>
    <p class="small-text"><strong>Why it worked:</strong> nothing broke SHAKE or the lattice math — the fault
      only removed the randomness that made y unpredictable. Predictable nonce ⇒ collapsed blinding ⇒ linear solve.</p>
  `;
});

void generateTraces();
drawClusterHistogram(undefined);
renderRejectionLogs();
