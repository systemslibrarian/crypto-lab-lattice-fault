import './styles.css';
import {
  EXECUTABLE_ABORT_LIMIT,
  ML_DSA_44,
  expandMaskPoly,
  requiredEmbeddingDimension,
  runLoopAbortAttack,
} from './loopabort';
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
  hammingWeightCurve,
  leakageStages,
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
      ⚠ SIMULATED — no probe, glitcher or target device is involved; the physical half of every
      attack is stood up in software here, and real attacks require physical access, specialized
      equipment and significant expertise. Where an exhibit performs genuine cryptographic
      computation rather than a model of one, it says so on the exhibit. ML-KEM and ML-DSA are not
      mathematically broken; these are implementation attacks.
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
        <li><a href="#attack-4"><span class="toc-num">4</span> <span class="toc-label">Loop-abort fault</span> <span class="toc-what">cut the nonce-generation loop short so most of the nonce is zero</span></a></li>
      </ol>
    </nav>

    <details class="lattice-primer panel" id="lattice-primer" open>
      <summary>
        <span class="lp-kicker">START HERE · 60-SECOND ON-RAMP</span>
        <span class="lp-title">Zero to lattice: what is being attacked?</span>
        <span class="lp-hint">New to post-quantum crypto? Read this first. Already fluent? Collapse it.</span>
      </summary>
      <div class="lp-body">
        <div class="lp-prose">
          <p>
            A <strong>lattice</strong> is a grid of points you get by adding up a fixed set of vectors
            with whole-number multiples — like every corner you can reach on graph paper using a couple
            of "step" arrows. Lattice cryptography hides the secret key as a <em>tiny error</em> added to a
            point on such a grid. Recovering it means finding the nearest grid point to a slightly-off
            location, which is believed hard even for a quantum computer. That is the <strong>math</strong>
            promise, and it is <em>not</em> what these four exhibits break.
          </p>
          <p>
            In practice ML-KEM and ML-DSA don't store the key as raw grid vectors — they store
            <strong>polynomials</strong> (256 coefficients modulo a prime q — q = 3329 for ML-KEM,
            q = 8&nbsp;380&nbsp;417 for ML-DSA). Multiplying two polynomials the
            slow way is 256×256 work. The <strong>NTT</strong> (Number-Theoretic Transform) is a trick that
            first evaluates each polynomial at 256 special points; in that "NTT form" a product is just
            <strong>point-by-point multiplication</strong> — 256 cheap multiplies instead of 65 536.
            The secret key flows through those multiplies, one coefficient at a time — and <em>that</em> is
            the arithmetic Attack 1 watches leak through the chip's power draw.
          </p>
          <p class="lp-take">
            <strong>Hold onto this:</strong> the secret lives in a polynomial coefficient, the NTT touches it
            with a hardware multiply, and a multiply moves bits — which a probe can see. The math stays
            safe; the <em>chip doing the math</em> is what leaks.
          </p>
        </div>
        <figure class="lp-figure">
          <svg viewBox="0 0 300 210" role="img" aria-label="Diagram: multiplying two polynomials becomes point-by-point multiplication once both are in NTT form; the secret coefficient s-hat-0 times c-hat-0 is one such multiply.">
            <defs>
              <marker id="lp-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" fill="currentColor"/>
              </marker>
            </defs>
            <text x="8" y="20" class="lp-svg-h">coefficients (mod q=3329)</text>
            <text x="8" y="42" class="lp-svg-t">s = [ s₀ s₁ s₂ … s₂₅₅ ]</text>
            <text x="8" y="60" class="lp-svg-t">c = [ c₀ c₁ c₂ … c₂₅₅ ]</text>
            <line x1="150" y1="70" x2="150" y2="92" stroke="currentColor" stroke-width="1.5" marker-end="url(#lp-arrow)"/>
            <text x="160" y="86" class="lp-svg-s">NTT: evaluate at 256 points</text>
            <text x="8" y="112" class="lp-svg-h">NTT form (ŝ, ĉ)</text>
            <text x="8" y="134" class="lp-svg-t">ŝ = [ ŝ₀ ŝ₁ ŝ₂ … ]</text>
            <text x="8" y="152" class="lp-svg-t">ĉ = [ ĉ₀ ĉ₁ ĉ₂ … ]</text>
            <rect x="6" y="164" width="288" height="40" rx="8" class="lp-svg-box"/>
            <text x="150" y="181" class="lp-svg-p" text-anchor="middle">product = point-by-point:</text>
            <text x="150" y="197" class="lp-svg-hot" text-anchor="middle">ŝ₀·ĉ₀ , ŝ₁·ĉ₁ , … , ŝ₂₅₅·ĉ₂₅₅</text>
          </svg>
          <figcaption>The secret coefficient <code>ŝ₀</code> meets the ciphertext at one multiply <code>ŝ₀·ĉ₀</code>. Attack 1 recovers that <code>ŝ₀</code> from the power the multiply draws.</figcaption>
        </figure>
      </div>
    </details>

    <section class="warmup panel" role="note" aria-label="The simplest possible leak">
      <h2 class="warmup-title">Warm-up: the simplest possible leak (30 seconds)</h2>
      <p>
        Before any NTTs, here is the whole idea in one line. Imagine a chip that checks a secret PIN digit
        by digit and <em>stops at the first wrong digit</em>:
      </p>
      <pre class="warmup-code" tabindex="0" role="region" aria-label="Pseudocode: a PIN check that returns early on the first mismatch, leaking through time"><code>for i in 0..len:
    if guess[i] != secret[i]:
        return WRONG   <span class="warmup-note"># returns sooner when the guess is wrong earlier</span></code></pre>
      <p>
        Nobody read the secret — yet a <strong>stopwatch</strong> does: a guess wrong at digit 0 returns
        faster than one wrong at digit 3. The output ("WRONG") is identical; the <em>time</em> is not. That
        gap between "what the algorithm returns" and "what the hardware reveals" is the entire subject of
        this lab. The four attacks below are just richer versions of this — power instead of time, a glitch
        instead of a stopwatch — against real ML-KEM / ML-DSA code.
      </p>
    </section>

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
          <p class="small-text">Drag <strong>noise σ</strong> and let go: the traces redraw live so you watch the amber Hamming-weight signal drown as σ rises — then re-run CPA to see the true-key spike sink toward the floor.</p>
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
        <span class="swatch swatch-dash" style="--c:#ffaa00">noise-free Hamming-weight signal (power = this + noise)</span>
        <span class="swatch" style="--c:#ff3366">hovered sample &rarr; its butterfly card</span>
      </figcaption>
      <div id="trace-hover" class="hint-line">Hover, tap, or focus the trace and use &larr; &rarr; keys: each sample lights up the butterfly card whose Hamming weight produced it, and the amber dashed line is the noise-free signal the noisy traces wiggle around.</div>
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
      <p class="small-text honesty-note">
        <strong>Model disclosure:</strong> this exhibit uses the real ML-DSA-44 rejection bound
        (<code>γ₁ − β</code>, with <code>γ₁ = 2¹⁷</code> and <code>β = τ·η = 78</code> from FIPS 204
        Table 1) and the real <code>y</code> range <code>[−γ₁+1, γ₁]</code>, but it forms
        <code>c·s₁</code> <em>coefficient by coefficient</em> with a fixed scale factor rather than as a
        product in <code>Z_q[x]/(x²⁵⁶+1)</code>. That keeps the statistical point — bypass the rejection
        check and the secret term survives the average — visible without the ring machinery. Attack 4
        below does the real ring arithmetic.
      </p>
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
          <em>dividend carries the secret</em>. When the compiler cannot emit a hardware divide — as on the
          Raspberry Pi 2 (Cortex-A7) build the KyberSlash paper attacks, where gcc's default ABI does not
          guarantee a divide instruction — it calls a software routine instead: a shift-subtract loop whose
          <strong>iteration count grows with the magnitude of the dividend</strong>.
          Bigger secret-influenced value ⇒ more loop iterations ⇒ more cycles. Time the divide, learn the secret.
          (Cores that <em>do</em> have a divider leak too, just less: the Cortex-M4's hardware <code>udiv</code>
          itself runs 2–12 cycles depending on its operands.)
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
        count</em> from the real restoring-division routine instead. On a target that calls a software divide
        routine these two clusters are cleanly separated in actual cycles; the constant-time build collapses
        them into one.
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
        <span class="reveal-title">Attack 4 · Loop-abort fault on nonce expansion</span>
        <span class="reveal-hint">The subtlest one: end a loop early and the signature pins its own key inside a tiny lattice. Expand to continue.</span>
      </summary>
    <section class="exhibit panel" id="attack-4">
      <div class="exhibit-head">
        <div>
          <p class="kicker">SIMULATED FAULT • REAL LATTICE RECOVERY</p>
          <h2>ATTACK 4: LOOP-ABORT FAULT ON NONCE EXPANSION</h2>
          <p>Cut the loop that fills the nonce <code>y</code> short and most of <code>y</code> stays zero — which shrinks the lattice hiding the signing key from dimension 256 to a few dozen.</p>
        </div>
      </div>

      <div class="primer" role="note" aria-label="What's different this time">
        <h3>What's different this time</h3>
        <p class="small-text">
          Attacks 1–3 read a leak or skipped a check. This one <em>shortens a loop</em>. ML-DSA masks the
          secret in every signature as <code>z = y + c·s₁</code>, where the nonce <code>y</code> is 256
          coefficients that <strong>ExpandMask</strong> (FIPS 204 Algorithm 34, via the per-coefficient
          BitUnpack loop of Algorithm 19) writes <em>one at a time</em>. A fault on the loop counter — or a
          skipped back-jump — ends that loop after <code>m</code> iterations. Coefficients
          <code>y₀ … y₍ₘ₋₁₎</code> are real samples; <code>yₘ … y₂₅₅</code> are still the zeros the output
          buffer started with.
        </p>
        <p class="small-text">
          The attacker never learns <code>y</code> and never tries to. What they get is a signature whose
          mask lives in an <code>m</code>-dimensional corner of a 256-dimensional space. Multiplying the
          released <code>z</code> by <code>c⁻¹</code> in the ring gives
        </p>
        <p class="formula-line"><code>c⁻¹z − s₁ ≡ c⁻¹y ≡ Σ<sub>i&lt;m</sub> y<sub>i</sub>·(c⁻¹xⁱ) &nbsp;(mod q)</code></p>
        <p class="small-text">
          so <code>c⁻¹z</code> sits close to the lattice spanned by just <code>m</code> vectors, and the
          <em>offset is the secret</em>. Project that relation onto a few dozen coordinates and lattice
          reduction reads <code>s₁</code> straight out — from a <strong>single</strong> faulty signature.
        </p>
      </div>

      <div class="misconception" role="note" aria-label="What this attack is not">
        <h3>What this attack is <em>not</em></h3>
        <p class="small-text">
          Nothing here makes <code>y</code> computable from public data, and nothing here is about the
          per-signature randomness <code>rnd</code>. FIPS 204 Algorithm 7 derives the nonce seed as
          <code>ρ″ ← H(K ‖ rnd ‖ μ)</code>, and <code>K</code> is a 32-byte seed stored <em>inside the
          private key</em> — so <code>y</code> stays unpredictable to an attacker whatever <code>rnd</code>
          is. That is precisely why FIPS 204's <strong>deterministic variant</strong>, which sets
          <code>rnd = 0³²</code>, is an approved mode and remains secure: the secrecy comes from
          <code>K</code>, not from <code>rnd</code>. (FIPS 204 does warn that the deterministic variant makes
          fault attacks — like this one — harder to mitigate, which is a different concern from
          predictability.) The loop-abort fault does not make <code>y</code> predictable. It makes
          <code>y</code> mostly <em>zero</em>, which is a different and much sharper weapon.
        </p>
      </div>

      <p class="attacker-story">
        <strong>You are the attacker:</strong> a smartcard signing with ML-DSA is on your bench and you have
        a clock glitcher. You do not try to guess the nonce — you shorten the loop that builds it, take the
        one signature that comes back, and finish the job with lattice reduction on your laptop.
      </p>

      <div class="sim-warning" role="note">
        ⚠ SIMULATED FAULT — the glitch is injected in software here. The lattice recovery below, however, is
        real: it runs an actual LLL over the actual ML-DSA-44 ring in your browser.
      </div>

      <div class="grid-2">
        <div class="panel inset-panel">
          <h3>Where does the fault land?</h3>
          <label>ExpandMask loop aborts after m = <span id="abort-value">8</span> of 256 coefficients
            <input id="abort-slider" type="range" min="1" max="256" value="8" />
          </label>
          <p class="small-text">
            Drag it: the strip below shows the nonce collapsing to a short prefix, and the chart shows the
            lattice dimension an attacker then needs. Earlier abort ⇒ smaller lattice ⇒ easier recovery.
          </p>
          <div class="button-row">
            <button id="run-loopabort-btn">Inject fault, sign, and run the lattice attack</button>
          </div>
        </div>
        <div class="panel inset-panel">
          <h3>Effective dimension</h3>
          <div id="abort-readout" class="result-box" aria-live="polite">Move the slider.</div>
        </div>
      </div>

      <canvas id="nonce-canvas" width="600" height="150" role="img" aria-label="Nonce coefficient strips: the honest run fills all 256 coefficients, the faulted run stops at the abort point and leaves the rest zero"></canvas>
      <figcaption class="chart-legend">
        <span class="axes">Each strip is the 256 coefficients of y, index 0 on the left</span>
        <span class="swatch" style="--c:#00d4ff">coefficient the loop actually sampled (shade = magnitude)</span>
        <span class="swatch" style="--c:#4a5f59">never written — still zero after the abort</span>
        <span class="swatch" style="--c:#ff3366">abort point m</span>
      </figcaption>

      <canvas id="dimension-canvas" width="600" height="200" role="img" aria-label="Lattice dimension required for key recovery as a function of the abort point, with the LLL and BKZ feasibility bands from the paper"></canvas>
      <figcaption class="chart-legend">
        <span class="axes">X: abort point m (surviving nonce coefficients) &nbsp;·&nbsp; Y: embedding dimension ℓ+1 needed, from eq. (2) of the paper</span>
        <span class="swatch" style="--c:#35d6bb">required dimension (curve)</span>
        <span class="swatch" style="--c:#ff3366">current abort point</span>
        <span class="swatch" style="--c:#ffd166">shaded bands: reduction reach reported in the paper</span>
        <span class="swatch swatch-dash" style="--c:#7fd0ff">this page's in-browser LLL cap</span>
      </figcaption>

      <div class="context-bar">
        <strong>Why the dimension is the whole story:</strong> an unfaulted signature has all 256
        coefficients of <code>y</code> alive, and eq. (2) then asks for a projection <em>larger than the
        ring itself</em> — there is no subset to attack, which is exactly why normal ML-DSA signatures leak
        nothing. Every coefficient the fault steals moves that requirement down into range.
      </div>

      <div id="loopabort-results" class="result-box" aria-live="polite">No faulty signature collected yet.</div>

      <div class="honesty-box" role="note" aria-label="What is real and what is modelled in this exhibit">
        <h3>What is real here, and what is not</h3>
        <ul>
          <li><strong>Real computation.</strong> The ML-DSA-44 parameters (<code>q = 8&nbsp;380&nbsp;417</code>,
            <code>γ₁ = 2¹⁷</code>, <code>τ = 39</code>, <code>β = 78</code>, <code>η = 2</code>,
            <code>ζ = 1753</code>) are FIPS 204 Table 1. SHAKE256 is a genuine KECCAK-f[1600] sponge, and
            ExpandMask, BitUnpack, SampleInBall and the NTT are FIPS 204 Algorithms 34, 19, 29 and 41–42.
            The ring arithmetic in <code>Z_q[x]/(x²⁵⁶+1)</code> is exact, the rejection test
            <code>‖z‖∞ ≥ γ₁ − β</code> is the standard's own line-23 check, and the recovery runs a real LLL
            over a real Kannan embedding — the <code>s₁</code> printed above is what lattice reduction
            actually returned, not a replay of the planted secret.</li>
          <li><strong>Simulated or reduced.</strong> The fault is injected in software; no glitcher is
            involved. This exhibit signs with <em>one</em> polynomial, where ML-DSA-44 uses ℓ = 4 — the real
            attack repeats the same reduction per polynomial. The challenge <code>c</code> is drawn by
            SampleInBall from a random seed rather than from a real commitment hash, because the page does
            not build <code>A</code>, <code>w₁</code> or the hint; consequently the second validity check,
            <code>‖r₀‖∞ ≥ γ₂ − β</code>, is not evaluated here. The in-browser LLL is capped at
            <code>m = ${EXECUTABLE_ABORT_LIMIT}</code> for responsiveness; the paper reports LLL succeeding
            to <code>m ≈ 50–60</code> and BKZ to <code>m ≈ 100</code>. Past the cap this exhibit
            <em>models</em> the attack — it reports the dimension the reduction would need and says so —
            rather than executing it.</li>
          <li><strong>Scope.</strong> ePrint 2016/449 attacks BLISS, GLP, TESLA, PASSSign and GPV; ML-DSA
            did not exist when it was written. ML-DSA has the same Fiat–Shamir-with-aborts shape
            (<code>z = y + c·s₁</code> with <code>y</code> built coefficient by coefficient), so the
            mechanism carries over, but this exhibit is an adaptation of the paper's attack, not a result
            reported in it.</li>
        </ul>
      </div>

      <div class="context-bar">
        <strong>Countermeasures (paper, §7):</strong> check that the top <code>ε·n</code> coefficients of
        <code>y</code> are not all zero — at <code>ε = 1/16</code> the check costs almost nothing, leaves the
        distribution of <code>y</code> statistically indistinguishable, and pushes the attacker's lattice
        past dimension <code>(1−ε)n</code>. Or generate <code>y</code>'s coefficients in a random order, so
        an aborted loop no longer tells the attacker <em>which</em> <code>c⁻¹xⁱ</code> the relation is built
        from. (If the buffer holds a common unknown constant instead of zero — the paper's Remark 3 — the
        attacker just adds the all-ones vector to the generators, so "not zero-initialised" is not a
        defence.)
      </div>

      <p class="exhibit-ref">
        Real-world basis: Espitau, Fouque, Gérard &amp; Tibouchi, <em>Loop-Abort Faults on Lattice-Based
        Fiat–Shamir and Hash-and-Sign Signatures</em>, SAC 2016 — a fault ends the commitment-generation
        loop early, leaving the commitment polynomial with only a few non-zero coefficients, and one such
        signature recovers the whole secret key by lattice reduction.
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
            <tr><td>Loop-abort on the nonce y</td><td>Reject y whose top ε·n coefficients are all zero</td><td>&lt;1%</td><td>Available</td></tr>
            <tr><td>Loop-abort on the nonce y</td><td>Sample y's coefficients in random order</td><td>~0%</td><td>Available</td></tr>
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

/**
 * Draw the Attack-1 power trace: the first few noisy traces (green), the
 * noise-free Hamming-weight curve they wiggle around (amber), and — when a
 * sample is focused — a vertical cursor plus a dot on the HW curve. This is the
 * visible half of the "power tracks Hamming weight" link; the butterfly card
 * highlight is the other half, driven by the same cursorSample.
 */
function drawTracePlot(
  canvas: HTMLCanvasElement,
  traces: number[][],
  hwCurve: number[],
  cursorSample: number | null,
): void {
  const allSeries = hwCurve.length ? traces.concat([hwCurve]) : traces;
  const ctx = clearPlot(canvas);
  const { min, max } = valueRange(allSeries.length ? allSeries : [[0, 1]]);
  const pad = 18;
  const usableHeight = canvas.height - pad * 2;
  const usableWidth = canvas.width - pad * 2;
  const greens = ['#00ff66', '#24d97a', '#47c98a', '#8be3a8', '#d0ffde'];

  const xAt = (index: number, len: number): number =>
    pad + (index / Math.max(len - 1, 1)) * usableWidth;
  const yAt = (value: number): number =>
    pad + usableHeight - ((value - min) / Math.max(max - min, 1e-9)) * usableHeight;

  // Noisy traces first, thin.
  traces.forEach((series, seriesIndex) => {
    ctx.beginPath();
    ctx.lineWidth = 1.2;
    ctx.strokeStyle = greens[seriesIndex] ?? '#00ff66';
    series.forEach((value, index) => {
      const x = xAt(index, series.length);
      const y = yAt(value);
      index === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
  });

  // Noise-free Hamming-weight curve on top, bright + dashed so it reads as "the
  // real signal under the noise".
  if (hwCurve.length) {
    ctx.beginPath();
    ctx.lineWidth = 2.6;
    ctx.strokeStyle = '#ffaa00';
    ctx.setLineDash([6, 4]);
    hwCurve.forEach((value, index) => {
      const x = xAt(index, hwCurve.length);
      const y = yAt(value);
      index === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // Focused-sample cursor: a vertical line + a dot on the HW curve, the visible
  // end of the connector to the butterfly card below.
  if (cursorSample !== null && hwCurve.length) {
    const len = hwCurve.length;
    const idx = clamp(cursorSample, 0, len - 1);
    const x = xAt(idx, len);
    ctx.strokeStyle = 'rgba(255, 51, 102, 0.9)';
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    ctx.moveTo(x, pad - 8);
    ctx.lineTo(x, canvas.height - pad + 8);
    ctx.stroke();
    const dotY = yAt(hwCurve[idx] ?? 0);
    ctx.fillStyle = '#ff3366';
    ctx.beginPath();
    ctx.arc(x, dotY, 4.5, 0, Math.PI * 2);
    ctx.fill();
  }
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

  // The true-key spike, now called out directly so a newcomer sees WHERE to look
  // and WHY it wins: a full-height line, a dot at its peak, and a label naming
  // the recovered coefficient.
  const spikeX = pad + (secretKey / Math.max(values.length - 1, 1)) * (canvas.width - pad * 2);
  const spikeVal = values[secretKey] ?? 0;
  const spikeY = canvas.height - pad - (spikeVal / maxValue) * (canvas.height - pad * 2);
  const winner = values.every((v, k) => k === secretKey || v <= spikeVal);

  ctx.strokeStyle = '#ff3366';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(spikeX, 8);
  ctx.lineTo(spikeX, canvas.height - 8);
  ctx.stroke();

  ctx.fillStyle = '#ff3366';
  ctx.beginPath();
  ctx.arc(spikeX, spikeY, 5, 0, Math.PI * 2);
  ctx.fill();

  // Callout label near the peak, flipped to whichever side has room.
  const label = winner ? `sk[0]=${secretKey} — the winning spike` : `sk[0]=${secretKey} — true key (not yet leading)`;
  ctx.font = '700 12px Inter, "Segoe UI", sans-serif';
  // measureText may be absent/stubbed (e.g. the jsdom recording context); fall
  // back to an estimate so the callout still positions without throwing.
  const textW = ctx.measureText(label)?.width ?? label.length * 6.5;
  const leftSide = spikeX + 10 + textW > canvas.width - pad;
  const labelX = leftSide ? spikeX - 10 - textW : spikeX + 10;
  const labelY = clamp(spikeY - 8, 20, canvas.height - 12);
  ctx.fillStyle = 'rgba(4, 16, 8, 0.85)';
  ctx.fillRect(labelX - 4, labelY - 13, textW + 8, 18);
  ctx.fillStyle = '#ffd0da';
  ctx.fillText(label, labelX, labelY);
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
const nonceCanvas = must<HTMLCanvasElement>('#nonce-canvas');
const dimensionCanvas = must<HTMLCanvasElement>('#dimension-canvas');
const traceHover = must<HTMLDivElement>('#trace-hover');
const butterflyGrid = must<HTMLDivElement>('#butterfly-grid');
const cpaResults = must<HTMLDivElement>('#cpa-results');
const normalLog = must<HTMLDivElement>('#normal-log');
const faultedLog = must<HTMLDivElement>('#faulted-log');
const recoveryPanel = must<HTMLDivElement>('#recovery-panel');
const timingResults = must<HTMLDivElement>('#timing-results');
const abortReadout = must<HTMLDivElement>('#abort-readout');
const loopAbortResults = must<HTMLDivElement>('#loopabort-results');

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
  // The noise-free Hamming-weight signal the first trace wiggles around, so the
  // "power = HW + noise" claim is drawn, not just asserted.
  hwCurve: new Float64Array(0) as Float64Array,
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

// Live feedback: releasing the noise (or setup) slider regenerates the traces so
// the learner watches the amber Hamming-weight signal disappear into the noise as
// σ rises — the SNR trade-off felt by dragging, not by re-clicking "Generate".
// Fires on `change` (pointer release), not every `input` tick, to stay cheap.
[skSlider, ctSlider, noiseSlider, traceCountSlider].forEach((input) => {
  input.addEventListener('change', () => {
    void generateTraces();
  });
});

function renderButterflies(secret: number, cipher: number): void {
  // Render straight from the SAME leakage stages that generate the power trace,
  // so butterfly card `s` owns trace samples 3s, 3s+1, 3s+2 exactly. Each <p>
  // carries data-sample so a hovered trace point can light up its source line.
  const stages = leakageStages(secret, cipher);

  butterflyGrid.innerHTML = stages.map((stage, index) => {
    const [wHW, plusHW, minusHW] = stage.weights;
    const hot = Math.max(wHW, plusHW, minusHW) >= 8 ? 'hot' : '';
    const base = index * 3;

    return `
      <article class="butterfly-card ${hot}" data-stage="${index}">
        <h4>Stage ${index + 1} <span class="bf-samples">samples ${base}–${base + 2}</span></h4>
        <p>zeta = ${stage.zeta}</p>
        <p data-sample="${base}">w·b = ${stage.wB} (HW ${wHW})</p>
        <p data-sample="${base + 1}">a + wb = ${stage.plus} (HW ${plusHW})</p>
        <p data-sample="${base + 2}">a − wb = ${stage.minus} (HW ${minusHW})</p>
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

  // The butterfly cards and the noise-free curve must describe the SAME
  // (secret, cipher) pair the FIRST drawn trace uses, so the hover linkage lines
  // up sample-for-sample.
  const firstCipher = traceState.ciphertexts[0] ?? traceState.baseCipher;
  traceState.hwCurve = hammingWeightCurve(traceState.secret, firstCipher);

  redrawTrace(null);
  renderButterflies(traceState.secret, firstCipher);
  cpaResults.innerHTML = '<p>Traces generated. Ready to test all 3,329 hypotheses.</p>';
}

// Power-trace readout, reachable by mouse, touch, AND keyboard so the exhibit
// meets WCAG 2.1.1 and works on mobile. `traceCursor` is the focused sample.
let traceCursor = 0;

/** Redraw the trace canvas, optionally with a cursor marker at `cursorSample`. */
function redrawTrace(cursorSample: number | null): void {
  const visible = traceState.traces.slice(0, 5).map((trace) => Array.from(trace));
  drawTracePlot(traceCanvas, visible, Array.from(traceState.hwCurve), cursorSample);
}

/** Light up the butterfly card (and the exact intermediate line) a sample came
 * from, so the hovered power point is visibly tied to the Hamming weight that
 * produced it. Clears when `sampleIndex` is null. */
function highlightButterflyForSample(sampleIndex: number | null): void {
  butterflyGrid.querySelectorAll('.butterfly-card').forEach((card) => {
    card.classList.remove('linked');
    card.querySelectorAll('p[data-sample]').forEach((p) => p.classList.remove('linked-row'));
  });
  if (sampleIndex === null) {
    return;
  }
  const stage = Math.floor(sampleIndex / 3);
  const card = butterflyGrid.querySelector<HTMLElement>(`.butterfly-card[data-stage="${stage}"]`);
  if (card) {
    card.classList.add('linked');
    card.querySelector(`p[data-sample="${sampleIndex}"]`)?.classList.add('linked-row');
  }
}

function showTraceSample(sampleIndex: number): void {
  const trace = traceState.traces[0];
  if (!trace) {
    return;
  }
  traceCursor = clamp(sampleIndex, 0, trace.length - 1);
  const power = trace[traceCursor] ?? 0;
  const clean = traceState.hwCurve[traceCursor] ?? 0;
  const noise = power - clean;
  const stage = Math.floor(traceCursor / 3);
  const part = ['w·b', 'a + wb', 'a − wb'][traceCursor % 3] ?? '';
  traceHover.textContent =
    `Sample ${traceCursor} of ${trace.length - 1} — from butterfly stage ${stage + 1} (${part}): ` +
    `power ${formatNumber(power, 3)} = Hamming-weight signal ${formatNumber(clean, 3)} ` +
    `${noise >= 0 ? '+' : '−'} noise ${formatNumber(Math.abs(noise), 3)}. Highlighted below.`;
  redrawTrace(traceCursor);
  highlightButterflyForSample(traceCursor);
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

traceCanvas.addEventListener('mouseleave', () => {
  redrawTrace(null);
  highlightButterflyForSample(null);
});

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

// ---------------------------------------------------------------------------
// Attack 4 — loop-abort fault on ExpandMask
// ---------------------------------------------------------------------------

const abortSlider = must<HTMLInputElement>('#abort-slider');
const abortValue = must<HTMLSpanElement>('#abort-value');
const runLoopAbortButton = must<HTMLButtonElement>('#run-loopabort-btn');

/**
 * The nonce drawn in the strips. It starts as one real ExpandMask output so the
 * strip is populated before anything is run, and is replaced by the honest
 * nonce of the last actual attack run. Truncating it at m is exactly what the
 * faulted device produces — the abort only shortens the loop, it does not
 * change the coefficients that were already written.
 */
let displayNonce = expandMaskPoly(new Uint8Array(64).fill(0x5a), 0);

/** Draw the honest and faulted nonce as 256-cell strips with the abort marker. */
function drawNonceStrips(abortAfter: number): void {
  const ctx = clearPlot(nonceCanvas);
  const left = 14;
  const width = nonceCanvas.width - left * 2;
  const cell = width / ML_DSA_44.n;
  const gamma1 = ML_DSA_44.gamma1;

  const strip = (top: number, label: string, limit: number): void => {
    ctx.fillStyle = '#d7ffe5';
    ctx.font = '12px sans-serif';
    ctx.fillText(label, left, top - 6);
    for (let i = 0; i < ML_DSA_44.n; i += 1) {
      const live = i < limit;
      const magnitude = Math.min(1, Math.abs(displayNonce[i] ?? 0) / gamma1);
      ctx.fillStyle = live
        ? `rgba(0, 212, 255, ${0.22 + magnitude * 0.75})`
        : 'rgba(74, 95, 89, 0.9)';
      ctx.fillRect(left + i * cell, top, Math.max(cell - 0.4, 0.6), 34);
    }
    // The strip's OUTLINE is what tells you where the meter starts and ends —
    // and at m = 8 the dead tail is 97% of it, so the outline is doing that job
    // almost alone. At the previous 0.25 alpha it composited to 2.10:1 against
    // the plot fill, under the 3:1 WCAG 1.4.11 asks of a meaningful graphic's
    // extent (no oracle reaches inside a canvas; measured by hand from
    // screenshot pixels). 0.45 measures 4.25:1. 1.5px so the stroke is not
    // halved by antialiasing across an integer coordinate.
    ctx.strokeStyle = 'rgba(215, 255, 229, 0.45)';
    ctx.lineWidth = 1.5;
    ctx.strokeRect(left, top, width, 34);
  };

  strip(28, 'Honest run — all 256 coefficients sampled', ML_DSA_44.n);
  strip(100, `Faulted run — loop aborted after m = ${abortAfter}`, abortAfter);

  // The abort marker, on the faulted strip.
  const markerX = left + abortAfter * cell;
  ctx.strokeStyle = '#ff3366';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(markerX, 94);
  ctx.lineTo(markerX, 142);
  ctx.stroke();
  ctx.fillStyle = '#ff3366';
  ctx.font = '700 11px sans-serif';
  const labelText = `m = ${abortAfter}`;
  const labelWidth = ctx.measureText(labelText)?.width ?? 40;
  const labelX = Math.min(markerX + 5, nonceCanvas.width - labelWidth - 4);
  ctx.fillText(labelText, labelX, 140);
}

/**
 * Required embedding dimension against the abort point, with the reach of LLL
 * and BKZ reported in the paper drawn as bands. This is the "collapse in
 * effective dimension" the fault buys.
 */
function drawDimensionCurve(abortAfter: number): void {
  const ctx = clearPlot(dimensionCanvas);
  const padLeft = 42;
  const padRight = 14;
  const padTop = 16;
  const padBottom = 26;
  const plotWidth = dimensionCanvas.width - padLeft - padRight;
  const plotHeight = dimensionCanvas.height - padTop - padBottom;
  const maxM = ML_DSA_44.n;
  const maxDim = 300;

  const xAt = (m: number): number => padLeft + (m / maxM) * plotWidth;
  const yAt = (dim: number): number => padTop + plotHeight - (dim / maxDim) * plotHeight;

  // Feasibility bands, expressed in lattice dimension: the paper reports LLL
  // reaching m ≈ 50–60 and BKZ m ≈ 100, which is dimension ≈ 70 and ≈ 115.
  const bands: Array<[number, number, string]> = [
    [0, 70, 'rgba(53, 214, 187, 0.13)'],
    [70, 115, 'rgba(255, 209, 102, 0.12)'],
    [115, maxDim, 'rgba(255, 51, 102, 0.10)'],
  ];
  for (const [low, high, colour] of bands) {
    ctx.fillStyle = colour;
    ctx.fillRect(padLeft, yAt(high), plotWidth, yAt(low) - yAt(high));
  }

  // Band captions sit just inside the top of each band so none of them collide
  // with the n = 256 rule drawn below.
  ctx.font = '10px sans-serif';
  ctx.fillStyle = 'rgba(215, 255, 229, 0.75)';
  ctx.fillText('LLL reach (paper: m ≈ 50–60)', padLeft + 6, yAt(0) - 6);
  ctx.fillText('BKZ reach (paper: m ≈ 100)', padLeft + 6, yAt(70) - 6);
  ctx.fillText('beyond published reach', padLeft + 6, yAt(115) - 6);

  // n = 256: past here no projection is smaller than the ring, so the relation
  // carries no usable information at all.
  ctx.strokeStyle = 'rgba(215, 255, 229, 0.45)';
  ctx.lineWidth = 1;
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  ctx.moveTo(padLeft, yAt(maxM));
  ctx.lineTo(padLeft + plotWidth, yAt(maxM));
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle = 'rgba(215, 255, 229, 0.75)';
  ctx.fillText('n = 256 — above this the fault buys nothing', padLeft + 6, yAt(maxM) - 5);

  // the curve itself
  ctx.strokeStyle = '#35d6bb';
  ctx.lineWidth = 2.2;
  ctx.beginPath();
  for (let m = 1; m <= maxM; m += 1) {
    const dim = Math.min(maxDim, requiredEmbeddingDimension(m));
    const x = xAt(m);
    const y = yAt(dim);
    m === 1 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  }
  ctx.stroke();

  // this page's executable limit
  ctx.strokeStyle = 'rgba(127, 208, 255, 0.85)';
  ctx.lineWidth = 1.4;
  ctx.setLineDash([5, 4]);
  ctx.beginPath();
  ctx.moveTo(xAt(EXECUTABLE_ABORT_LIMIT), padTop);
  ctx.lineTo(xAt(EXECUTABLE_ABORT_LIMIT), padTop + plotHeight);
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle = 'rgba(127, 208, 255, 0.9)';
  ctx.fillText(`in-browser cap m = ${EXECUTABLE_ABORT_LIMIT}`, xAt(EXECUTABLE_ABORT_LIMIT) + 5, padTop + 12);

  // current abort point
  const currentDim = Math.min(maxDim, requiredEmbeddingDimension(abortAfter));
  ctx.strokeStyle = '#ff3366';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(xAt(abortAfter), padTop);
  ctx.lineTo(xAt(abortAfter), padTop + plotHeight);
  ctx.stroke();
  ctx.fillStyle = '#ff3366';
  ctx.beginPath();
  ctx.arc(xAt(abortAfter), yAt(currentDim), 4.5, 0, Math.PI * 2);
  ctx.fill();

  // axes ticks
  ctx.fillStyle = 'rgba(215, 255, 229, 0.7)';
  ctx.font = '10px sans-serif';
  for (const m of [0, 64, 128, 192, 256]) {
    ctx.fillText(String(m), xAt(m) - 8, dimensionCanvas.height - 8);
  }
  for (const dim of [0, 100, 200, 300]) {
    ctx.fillText(String(dim), 8, yAt(dim) + 3);
  }
}

/** Slider-driven readout: the dimension analysis, no lattice work. */
function renderAbortReadout(abortAfter: number): void {
  const dimension = requiredEmbeddingDimension(abortAfter);
  const rounded = Math.ceil(dimension);
  const reach =
    rounded > ML_DSA_44.n
      ? 'no projection is smaller than the ring — the signature leaks nothing'
      : rounded <= 70
        ? 'inside LLL reach'
        : rounded <= 115
          ? 'needs BKZ'
          : 'beyond the reduction reach reported in the paper';

  abortReadout.innerHTML = `
    <p><strong>Nonce coefficients still alive:</strong> ${abortAfter} of 256
      (${ML_DSA_44.n - abortAfter} left at zero).</p>
    <p><strong>Embedding dimension required:</strong> ℓ+1 ≈ ${rounded}
      &mdash; ${reach}.</p>
    <p class="small-text">From eq. (2) of Espitau et al., instantiated with ML-DSA-44's
      q = ${ML_DSA_44.q.toLocaleString()} and η = ${ML_DSA_44.eta}. The whole attack is this number:
      256 coefficients of secret, pinned down by a lattice of dimension ≈ m.</p>
    ${
      abortAfter > EXECUTABLE_ABORT_LIMIT
        ? `<p class="small-text"><strong>Note:</strong> past m = ${EXECUTABLE_ABORT_LIMIT} this page
             <em>models</em> the attack rather than running it — the reduction is real work, and a
             browser tab is not where you would do it.</p>`
        : ''
    }
  `;
}

function refreshAbortViews(): void {
  const abortAfter = Number(abortSlider.value);
  abortValue.textContent = String(abortAfter);
  drawNonceStrips(abortAfter);
  drawDimensionCurve(abortAfter);
  renderAbortReadout(abortAfter);
}

abortSlider.addEventListener('input', refreshAbortViews);

runLoopAbortButton.addEventListener('click', () => {
  void withBusy(runLoopAbortButton, 'Reducing lattice…', async () => {
    const abortAfter = Number(abortSlider.value);
    loopAbortResults.innerHTML =
      `<p>Aborting ExpandMask after ${abortAfter} coefficients, signing, then reducing…</p>`;
    await nextFrame();

    const result = runLoopAbortAttack(abortAfter);
    // Show the nonce this run actually expanded, not the placeholder.
    displayNonce = result.honestY;
    refreshAbortViews();

    const signerBlock = `
      <p><strong>The faulty signature.</strong> ExpandMask stopped after ${result.abortAfter}
        coefficients, so y has ${result.nonzeroY} non-zero coefficients and
        ${ML_DSA_44.n - result.nonzeroY} zeros. The device computed z = y + c·s₁ and released it with
        the challenge c (τ = ${ML_DSA_44.tau} coefficients of ±1).</p>
      <p><strong>Would a correct signer have released it?</strong> ‖z‖∞ = ${result.zInfinityNorm.toLocaleString()}
        against the FIPS 204 bound γ₁ − β = ${result.rejectionBound.toLocaleString()} —
        ${result.wouldReject
          ? 'no, this one is rejected, so the attacker glitches again'
          : 'yes, it passes the ‖z‖∞ check and goes out the door'}.
        (Rejection sampling means a fault may be wasted; ML-DSA-44 repeats the signing loop 4.25 times on
        average, which is roughly how many injections the paper expects per usable signature.)</p>`;

    if (result.skippedReason) {
      loopAbortResults.innerHTML = `
        ${signerBlock}
        <p><strong>Recovery not executed:</strong> ${result.skippedReason}</p>
        <p class="small-text">Everything above is real computation; only the lattice step was skipped.</p>`;
      return;
    }

    const solved = result.blocks.filter((block) => block.solved).length;
    const rate = (result.recoveredCount / ML_DSA_44.n) * 100;

    loopAbortResults.innerHTML = `
      ${signerBlock}
      <div class="algebra-walk" role="region" aria-label="How the recovery proceeded" tabindex="0">
        <p class="algebra-title">What the attacker did with it — real numbers from this run</p>
        <ol class="algebra-steps">
          <li>Inverted the challenge in the ring: c is invertible mod q?
            <strong>${result.challengeInvertible ? 'yes' : 'no'}</strong>
            (probability ≈ (1 − 1/q)²⁵⁶, so essentially always).</li>
          <li>Formed <code>v = c⁻¹z</code>, which satisfies
            <code>v − s₁ ≡ Σ<sub>i&lt;${result.abortAfter}</sub> y<sub>i</sub>·(c⁻¹xⁱ)</code> — a lattice
            spanned by only ${result.abortAfter} vectors instead of 256.</li>
          <li>Projected onto index blocks of size ${result.projection}
            (eq. (2) asked for ℓ+1 ≈ ${Math.ceil(result.requiredDimension)}), built the Kannan embedding,
            and ran LLL on each: ${solved} of ${result.blocks.length} blocks returned a short vector.</li>
          <li>Lattice time: ${formatNumber(result.latticeMs, 0)} ms, from
            <strong>one</strong> faulty signature.</li>
        </ol>
        <p class="small-text">Never once did the attacker guess, recompute or need the nonce y. The only
          thing they used about y is that most of it is zero.</p>
      </div>
      <p><strong>Recovered s₁:</strong> ${result.recoveredCount} of ${ML_DSA_44.n} coefficients exact
        (${formatNumber(rate, 1)}%) — ${result.success ? '<strong>full key recovery ✓</strong>' : 'partial'}.</p>
      <p class="small-text">First 12 coefficients — recovered
        [${Array.from(result.recovered).slice(0, 12).join(', ')}] vs actual
        [${Array.from(result.secret).slice(0, 12).join(', ')}].</p>`;
  });
});

void generateTraces();
drawClusterHistogram(undefined);
renderRejectionLogs();
refreshAbortViews();
