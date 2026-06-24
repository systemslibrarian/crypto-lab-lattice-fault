import './styles.css';
import { simulateFaultyKeccakAttack } from './keccak';
import {
  ML_DSA_PARAMS,
  recoverFromFaultySignatures,
  signWithFaultedRejection,
  signWithRejection,
} from './rejection';
import { Q, correlationPowerAnalysis, hammingWeight, nttButterfly, simulatePowerTrace } from './ntt';
import { randomIntInclusive } from './random';
import { timingExperiment } from './timing';

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App root not found');
}

app.innerHTML = `
  <main class="app-shell">
    <header class="topbar panel">
      <div>
        <p class="eyebrow">SIMULATED • implementation-security lab</p>
        <h1>crypto-lab-lattice-fault</h1>
        <p class="lede">
          ML-KEM and ML-DSA remain mathematically secure. These exhibits show how
          power leakage, timing variation, and physical faults can still recover secrets
          from real devices unless countermeasures migrate too.
        </p>
      </div>
      <button id="theme-toggle" class="theme-toggle" style="position: absolute; top: 0; right: 0" aria-label="Switch to light mode">🌙</button>
    </header>

    <section class="sim-warning" role="note">
      ⚠ SIMULATED — every exhibit demonstrates the principle only. Real attacks require
      physical access, specialized probes or glitchers, and significant expertise. ML-KEM
      and ML-DSA are not mathematically broken; these are implementation attacks.
    </section>

    <section class="exhibit panel" id="attack-1">
      <div class="exhibit-head">
        <div>
          <p class="kicker">SIMULATED • physical access required</p>
          <h2>ATTACK 1: NTT POWER ANALYSIS</h2>
          <p>Regular, branch-free NTT arithmetic still leaks through Hamming-weight power variations.</p>
        </div>
      </div>

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

      <div class="context-bar">
        <strong>Countermeasure:</strong> first-order masking and shuffling reduce leakage at a cost of roughly 2–4× runtime.
      </div>
    </section>

    <section class="exhibit panel" id="attack-2">
      <div class="exhibit-head">
        <div>
          <p class="kicker">SIMULATED • voltage glitch / EM fault</p>
          <h2>ATTACK 2: FAULT INJECTION ON REJECTION SAMPLING</h2>
          <p>If the rejection check is skipped, the returned signature coefficients become statistically leaky.</p>
        </div>
      </div>

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
    </section>

    <section class="exhibit panel" id="attack-3">
      <div class="exhibit-head">
        <div>
          <p class="kicker">SIMULATED • timing side-channel</p>
          <h2>ATTACK 3: KYBERSLASH — TIMING SIDE-CHANNEL</h2>
          <p>Data-dependent decoding work leaks a small but measurable timing difference; constant-time code flattens it.</p>
        </div>
      </div>

      <div class="sim-warning" role="note">
        ⚠ SIMULATED — real exploitation needs repeated timing capture from the target hardware. Browser timers are much noisier.
      </div>

      <div class="button-row">
        <button id="run-vulnerable-btn">Run Timing Experiment — Vulnerable</button>
        <button id="run-constant-btn">Run Timing Experiment — Constant Time</button>
      </div>
      <canvas id="timing-canvas" width="600" height="220" role="img" aria-label="Timing profile for vulnerable and constant-time ML-KEM decoding"></canvas>
      <figcaption class="chart-legend">
        <span class="axes">X: sampled coefficient &nbsp;·&nbsp; Y: decode time (µs)</span>
        <span class="swatch" style="--c:#ff3366">vulnerable (data-dependent, solid)</span>
        <span class="swatch swatch-dash" style="--c:#00d4ff">constant-time (dashed)</span>
      </figcaption>
      <div id="timing-results" class="result-box" aria-live="polite">No timing measurements collected yet.</div>
      <div class="context-bar">
        <strong>Browser note:</strong> Spectre mitigations reduce timer precision. This exhibit shows the principle, not nanosecond-fidelity lab measurements.
      </div>
    </section>

    <section class="exhibit panel" id="attack-4">
      <div class="exhibit-head">
        <div>
          <p class="kicker">SIMULATED • faulty KECCAK absorption</p>
          <h2>ATTACK 4: FAULT INJECTION ON KECCAK SEED GENERATION</h2>
          <p>A loop-abort fault can zero the nonce input, making the derived signing randomness attacker-predictable.</p>
        </div>
      </div>

      <div class="sim-warning" role="note">
        ⚠ SIMULATED — this is a physical-fault demo, not a practical browser attack tool.
      </div>

      <div class="button-row">
        <button id="run-keccak-btn">Run Attack Simulation</button>
      </div>
      <canvas id="keccak-canvas" width="600" height="260" role="img" aria-label="KECCAK sponge-state comparison between normal and faulted absorption"></canvas>
      <figcaption class="chart-legend">
        <span class="axes">5×5 sponge state — left: normal absorb &nbsp;·&nbsp; right: faulted absorb</span>
        <span class="swatch" style="--c:#00d4ff">lane byte intensity</span>
        <span class="swatch" style="--c:#ff3366">faulted (zeroed nonce) region</span>
      </figcaption>
      <div id="keccak-results" class="result-box" aria-live="polite">Awaiting KECCAK simulation.</div>
    </section>

    <section class="exhibit panel" id="attack-5">
      <div class="exhibit-head">
        <div>
          <p class="kicker">Implementation security</p>
          <h2>ATTACK 5: THE BIGGER PICTURE</h2>
          <p>Mathematical security and implementation security are separate requirements for deployed PQC.</p>
        </div>
      </div>

      <div class="comparison-table-wrap">
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
    </section>

  </main>
`;

type Theme = 'dark' | 'light';

type TimingKey = 'vulnerable' | 'constant-time';

type TimingResult = Awaited<ReturnType<typeof timingExperiment>>;

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
const timingState: Partial<Record<TimingKey, TimingResult>> = {};

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

function drawTimingOverlay(): void {
  const lines: number[][] = [];
  const colors: string[] = [];
  const highlights: number[] = [];
  const dashes: number[][] = [];

  if (timingState.vulnerable) {
    lines.push(Array.from(timingState.vulnerable.timings).filter((_, index) => index % 8 === 0));
    colors.push('#ff3366');
    highlights.push(0);
    dashes.push([]); // vulnerable: solid
  }

  if (timingState['constant-time']) {
    lines.push(Array.from(timingState['constant-time'].timings).filter((_, index) => index % 8 === 0));
    colors.push('#00d4ff');
    highlights.push(lines.length - 1);
    dashes.push([7, 5]); // constant-time: dashed, so the two are told apart without color
  }

  if (lines.length === 0) {
    drawLineSeries(timingCanvas, [[0, 0.2, 0.1, 0.15, 0.1]], ['#1a4a2a']);
  } else {
    drawLineSeries(timingCanvas, lines, colors, highlights, dashes);
  }
}

function renderTimingReport(): void {
  const vulnerable = timingState.vulnerable;
  const constant = timingState['constant-time'];

  const blocks = [
    vulnerable
      ? `<p><strong>Vulnerable:</strong> bit0 = ${formatNumber(vulnerable.mean0, 4)} µs, bit1 = ${formatNumber(vulnerable.mean1, 4)} µs, gap = ${formatNumber(vulnerable.difference, 4)} µs</p>`
      : '',
    constant
      ? `<p><strong>Constant-time:</strong> bit0 = ${formatNumber(constant.mean0, 4)} µs, bit1 = ${formatNumber(constant.mean1, 4)} µs, gap = ${formatNumber(constant.difference, 4)} µs</p>`
      : '',
  ].filter(Boolean);

  const comparison = vulnerable && constant
    ? `<p><strong>Comparison:</strong> |gap| drops from ${formatNumber(Math.abs(vulnerable.difference), 4)} µs to ${formatNumber(Math.abs(constant.difference), 4)} µs.</p>`
    : '<p>Run both experiments to compare the leakage gap.</p>';

  timingResults.innerHTML = blocks.join('') + comparison;
}

const vulnerableButton = must<HTMLButtonElement>('#run-vulnerable-btn');
const constantButton = must<HTMLButtonElement>('#run-constant-btn');

async function runTiming(kind: TimingKey): Promise<void> {
  // Disable both timing buttons: concurrent runs would contend for the CPU and
  // corrupt each other's measurements.
  vulnerableButton.disabled = true;
  constantButton.disabled = true;
  timingResults.innerHTML = `<p>Measuring ${kind} decoding timings…</p>`;
  await nextFrame();
  try {
    timingState[kind] = await timingExperiment(kind, 4, (pct) => {
      timingResults.innerHTML = `<p>Measuring ${kind} decoding timings… ${formatNumber(pct, 0)}%</p>`;
    });
    drawTimingOverlay();
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

function drawKeccakGrid(normalLanes: bigint[], faultedLanes: bigint[]): void {
  const ctx = clearPlot(keccakCanvas);
  const cell = 44;
  const drawOne = (offsetX: number, lanes: bigint[], title: string, faulted: boolean) => {
    ctx.fillStyle = '#d7ffe5';
    ctx.font = '14px sans-serif';
    ctx.fillText(title, offsetX, 20);

    for (let row = 0; row < 5; row += 1) {
      for (let col = 0; col < 5; col += 1) {
        const index = row * 5 + col;
        const lane = lanes[index] ?? 0n;
        const intensity = Number(lane & 255n) / 255;
        const hue = faulted && col < 2 ? 'rgba(255, 51, 102,' : 'rgba(0, 212, 255,';
        ctx.fillStyle = `${hue}${0.25 + intensity * 0.6})`;
        ctx.fillRect(offsetX + col * cell, 32 + row * cell, cell - 4, cell - 4);
      }
    }
  };

  drawOne(30, normalLanes, 'Normal absorb', false);
  drawOne(320, faultedLanes, 'Faulted absorb', true);
}

must<HTMLButtonElement>('#run-keccak-btn').addEventListener('click', async () => {
  keccakResults.innerHTML = '<p>Faulting KECCAK absorb loop…</p>';
  const result = await simulateFaultyKeccakAttack();
  drawKeccakGrid(result.normalLanes, result.faultedLanes);
  keccakResults.innerHTML = `
    <p><strong>Normal input:</strong> ${result.normalInput}</p>
    <p><strong>Faulted input:</strong> ${result.faultedInput}</p>
    <p><strong>ρ′ normal:</strong> ${result.normalRho.slice(0, 16)}…</p>
    <p><strong>ρ′ faulted:</strong> ${result.faultedRho.slice(0, 16)}…</p>
    <p><strong>Recovered s₁[0..7]:</strong> [${Array.from(result.recovered).join(', ')}]</p>
    <p><strong>Candidate search:</strong> tested ${result.candidateCount} candidates → ${result.success ? 'match found ✓' : 'no match'}</p>
  `;
});

void generateTraces();
drawTimingOverlay();
renderRejectionLogs();
