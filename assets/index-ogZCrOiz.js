(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const a of document.querySelectorAll('link[rel="modulepreload"]'))r(a);new MutationObserver(a=>{for(const i of a)if(i.type==="childList")for(const o of i.addedNodes)o.tagName==="LINK"&&o.rel==="modulepreload"&&r(o)}).observe(document,{childList:!0,subtree:!0});function n(a){const i={};return a.integrity&&(i.integrity=a.integrity),a.referrerPolicy&&(i.referrerPolicy=a.referrerPolicy),a.crossOrigin==="use-credentials"?i.credentials="include":a.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function r(a){if(a.ep)return;a.ep=!0;const i=n(a);fetch(a.href,i)}})();const At=new TextEncoder;function U(...t){const e=t.reduce((a,i)=>a+i.length,0),n=new Uint8Array(e);let r=0;for(const a of t)n.set(a,r),r+=a.length;return n}function J(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}async function Z(t,e=32){const n=new Uint8Array(e);let r=0,a=0;for(;r<e;){const i=new Uint8Array(4);new DataView(i.buffer).setUint32(0,a,!0);const o=U(t,i),s=o.buffer.slice(o.byteOffset,o.byteOffset+o.byteLength),c=new Uint8Array(await crypto.subtle.digest("SHA-256",s));n.set(c.subarray(0,Math.min(c.length,e-r)),r),r+=c.length,a+=1}return n}function tt(t,e){const n=new Int32Array(e);for(let r=0;r<e;r+=1){const a=t[r*2%t.length]??0,i=t[(r*2+1)%t.length]??0,o=a<<8|i;n[r]=o%2001-1e3}return n}function et(t){const e=[];for(let n=0;n<25;n+=1){let r=0n;for(let a=0;a<8;a+=1){const i=t[(n*8+a)%t.length]??0;r|=BigInt(i)<<BigInt(a*8)}e.push(r)}return e}async function kt(){const t=Int32Array.from([1,-2,0,1,-1,2,-1,0]),e=Int32Array.from([1,-1,1,1,-1,1,-1,1]),n=At.encode("Implementation security matters."),r=new Uint8Array(32);crypto.getRandomValues(r);const a=Uint8Array.from(Array.from(t,l=>l+2)),i=new Uint8Array(32),o=U(a,n,r),s=U(a,n,i),c=await Z(o,32),u=await Z(s,32),h=tt(c,t.length),d=tt(u,t.length),g=new Int32Array(t.length);for(let l=0;l<t.length;l+=1)g[l]=d[l]+e[l]*t[l]*17;const f=new Int32Array(t.length);for(let l=0;l<t.length;l+=1){const b=e[l]===0?1:e[l]??1;f[l]=Math.round((g[l]-d[l])/(17*b))}return{normalInput:`${a.length}B secret || ${n.length}B msg || 32B random`,faultedInput:`${a.length}B secret || ${n.length}B msg || 32B zeroes`,normalRho:J(c),faultedRho:J(u),normalY:h,faultedY:d,challenge:e,secret:t,z:g,recovered:f,candidateCount:256,success:Array.from(t).every((l,b)=>l===f[b]),normalLanes:et(c),faultedLanes:et(u)}}const st=4294967296;function j(){const t=new Uint32Array(1);return crypto.getRandomValues(t),t[0]??0}function nt(){return(j()+1)/(st+2)}function E(t,e){if(!Number.isInteger(t)||!Number.isInteger(e)||e<t)throw new Error("Invalid inclusive random integer range");const n=e-t+1,r=Math.floor(st/n)*n;let a=j();for(;a>=r;)a=j();return t+a%n}function Mt(t=1){const e=nt(),n=nt(),r=Math.sqrt(-2*Math.log(e)),a=2*Math.PI*n;return t*r*Math.cos(a)}const v=3329,R=256,xt=17;function w(t){const e=t%v;return e<0?e+v:e}function Tt(t,e){let n=1,r=w(t),a=e;for(;a>0;)(a&1)===1&&(n=w(n*r)),r=w(r*r),a>>=1;return n}function at(t){const e=Math.floor(67108864/v+.5),n=Math.floor((e*t+(1<<25))/(1<<26))*v;return w(t-n)}function ct(t,e,n){const r=n*e,a=t+r,i=t-r;return{a_out:at(a),b_out:at(i),intermediates:[r,a,i]}}function z(t){let e=Math.abs(Math.trunc(t))>>>0,n=0;for(;e>0;)n+=e&1,e>>>=1;return n}Array.from({length:R},(t,e)=>Tt(xt,e));function lt(t,e){const n=new Int32Array([w(t),w(e),w(t+e),w(t+2*e),w(2*t+e),w(3*t+e),w(t+3*e),w(2*t+3*e)]),r=[],a=[17,3312,2761,568,583,2746,2649,680];for(let i=4;i>=1;i>>=1)for(let o=0;o<n.length;o+=i*2)for(let s=0;s<i;s+=1){const c=o+s,u=a[(c+i+s)%a.length]??17,h=ct(n[c]??0,n[c+i]??0,u);n[c]=h.a_out,n[c+i]=h.b_out,r.push(...h.intermediates)}return r}async function Et(t,e,n=.5){const r=lt(t,e),a=new Float64Array(r.length);for(let i=0;i<r.length;i+=1){const o=z(r[i]??0)*.1;a[i]=o+Mt(n)}return a}function St(t,e){const n=t.length;if(n===0||e.length!==n)return 0;let r=0,a=0,i=0,o=0,s=0;for(let g=0;g<n;g+=1){const f=t[g]??0,l=e[g]??0;r+=f,a+=l,i+=f*l,o+=f*f,s+=l*l}const c=n*i-r*a,u=n*o-r*r,h=n*s-a*a,d=Math.sqrt(Math.max(u*h,0));return d===0?0:c/d}function Ct(t,e,n){if(t.length===0||t.length!==e.length)throw new Error("Trace count must match ciphertext count");const r=new Float64Array(v),a=[n-1,n,n+1].filter(i=>i>=0);for(let i=0;i<v;i+=1){let o=0;for(const s of a){const c=t.map(h=>h[s]??0),u=e.map(h=>{const d=lt(i,h);return z(d[s]??0)*.1});o+=St(u,c)}r[i]=o/a.length}return r}const M={gamma1:1<<17,beta:78,eta:2},dt=2560;function Lt(t,e,n){return Math.max(e,Math.min(n,t))}function ut(t,e,n){const r=new Int32Array(t.length);for(let a=0;a<t.length;a+=1){const i=e[a]??0,o=t[a]??0,s=n[a]??0;r[a]=s+i*o*dt}return r}async function ht(t){const e=new Int32Array(R);for(let n=0;n<R;n+=1)e[n]=E(-131071,t);return e}function mt(t,e){let n=0,r=null;for(let a=0;a<t.length;a+=1){const i=Math.abs(t[a]??0);i>n&&(n=i),i>=e.gamma1-e.beta&&r===null&&(r=a)}return{accepted:r===null,maxCoeff:n,violatingIndex:r}}async function It(t,e,n,r){const a=[];for(let i=0;i<r;i+=1){const o=await ht(n.gamma1),s=ut(t,e,o),c=mt(s,n);a.push({y:o,z:s,status:c.accepted?"accepted":"rejected",maxCoeff:c.maxCoeff})}return a}async function H(t,e,n,r){const a=[];let i=0;const o=Math.max(r*64,512);for(;a.length<r&&i<o;){i+=1;const s=await ht(n.gamma1),c=ut(t,e,s),u=mt(c,n);u.accepted||a.push({y:s,z:c,maxCoeff:u.maxCoeff,faulted:!0})}return a}function Rt(t,e,n){var o,s,c;if(t.length===0||t.length!==e.length)throw new Error("Faulty signatures and challenges must have the same non-zero length");const r=((o=t[0])==null?void 0:o.length)??R,a=new Int32Array(r),i=new Array(r).fill(0);for(let u=0;u<r;u+=1){let h=0,d=0;for(let b=0;b<t.length;b+=1){const I=((s=t[b])==null?void 0:s[u])??0,S=((c=e[b])==null?void 0:c[u])??0;S!==0&&(h+=I*S,d+=Math.abs(S))}const g=d===0?0:h/d/dt,f=Lt(Math.round(g),-2,n.eta);a[u]=f;const l=Math.abs(g-f);i[u]=Math.max(0,Math.min(1,1-l/(n.eta+.5)))}return{recovered:a,confidence:i}}const C=Math.floor(v/2),_=Math.floor(v/4);function V(t){const e=t%v;return e<0?e+v:e}function ft(t){return V(t+_)<C?0:1}function gt(t){return(V(t+_)-C>>31)+1&1}function $t(t){const e=t.reduce((r,a)=>r+a,0)/t.length,n=t.reduce((r,a)=>r+(a-e)**2,0)/t.length;return{meanUs:e,stdUs:Math.sqrt(n)}}async function Nt(t,e,n){const a=[];let i=0;for(let c=0;c<n;c+=1){const u=performance.now();for(let d=0;d<1024;d+=1){const g=V(t+_);if(e==="vulnerable"){let f=g*2/v|0;if(g>=C)for(let l=0;l<6;l+=1)f=(f+g+11+l)/(3+(l+1&3))|0;i^=ft(t)^f&0}else{let f=C*2/v|0;for(let l=0;l<6;l+=1)f=(f+C+11+l)/(3+(l+1&3))|0;i^=gt(t)^f&0}}const h=(performance.now()-u)*1e3/1024;a.push(h+i*1e-9),c>0&&c%8===0&&await Promise.resolve()}const{meanUs:o,stdUs:s}=$t(a);return{meanUs:o,stdUs:s,samples:a}}async function Ut(t,e,n){const r=new Float64Array(v);for(let d=0;d<v;d+=1){const g=await Nt(d,t,e);r[d]=g.meanUs,n&&d%64===0&&(n((d+1)/v*100),await Promise.resolve())}let a=0,i=0,o=0,s=0;for(let d=0;d<v;d+=1)(t==="vulnerable"?ft(d):gt(d))===0?(a+=r[d]??0,i+=1):(o+=r[d]??0,s+=1);const c=a/Math.max(i,1),u=o/Math.max(s,1),h=u-c;return{timings:r,mean0:c,mean1:u,difference:h,separationVisible:Math.abs(h)>.005}}const pt=document.querySelector("#app");if(!pt)throw new Error("App root not found");pt.innerHTML=`
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

    <section class="sim-warning" role="alert">
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

      <canvas id="trace-canvas" width="600" height="220" role="img" aria-label="Simulated power traces for ML-KEM NTT leakage"></canvas>
      <div id="trace-hover" class="hint-line">Hover the power trace for the current sample index.</div>
      <div id="butterfly-grid" class="butterfly-grid"></div>
      <canvas id="cpa-canvas" width="600" height="220" role="img" aria-label="CPA histogram for all ML-KEM key hypotheses"></canvas>

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

      <div class="sim-warning" role="alert">
        ⚠ SIMULATED — this requires invasive fault injection against a signing device. The math is not broken.
      </div>

      <div class="grid-2">
        <div class="panel inset-panel">
          <h3>Normal signing</h3>
          <p class="small-text">All accepted outputs remain below the bound γ₁ − β.</p>
          <button id="normal-sign-btn">Sign 20 messages normally</button>
          <div id="normal-log" class="log-panel" aria-live="polite"></div>
        </div>

        <div class="panel inset-panel">
          <h3>Faulted signing</h3>
          <p class="small-text">Bypassing the rejection check releases signatures that should have been discarded.</p>
          <button id="faulted-sign-btn">Simulate 20 Faulted Signatures</button>
          <div id="faulted-log" class="log-panel" aria-live="polite"></div>
        </div>
      </div>

      <canvas id="rejection-canvas" width="600" height="220" role="img" aria-label="Distribution comparison of normal and faulted ML-DSA signature coefficients"></canvas>
      <div class="button-row">
        <button id="recover-btn">Run Key Recovery from 1000 Faulty Signatures</button>
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

      <div class="sim-warning" role="alert">
        ⚠ SIMULATED — real exploitation needs repeated timing capture from the target hardware. Browser timers are much noisier.
      </div>

      <div class="button-row">
        <button id="run-vulnerable-btn">Run Timing Experiment — Vulnerable</button>
        <button id="run-constant-btn">Run Timing Experiment — Constant Time</button>
      </div>
      <canvas id="timing-canvas" width="600" height="220" role="img" aria-label="Timing profile for vulnerable and constant-time ML-KEM decoding"></canvas>
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

      <div class="sim-warning" role="alert">
        ⚠ SIMULATED — this is a physical-fault demo, not a practical browser attack tool.
      </div>

      <div class="button-row">
        <button id="run-keccak-btn">Run Attack Simulation</button>
      </div>
      <canvas id="keccak-canvas" width="600" height="260" role="img" aria-label="KECCAK sponge-state comparison between normal and faulted absorption"></canvas>
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

    <footer>
      <p>"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God." — 1 Corinthians 10:31</p>
    </footer>
  </main>
`;function m(t){const e=document.querySelector(t);if(!e)throw new Error(`Missing element: ${t}`);return e}function y(t,e=2){return Number.isFinite(t)?t.toFixed(e):"0.00"}function K(t,e,n){return Math.max(e,Math.min(n,t))}function $(t){const e=t.getContext("2d");if(!e)throw new Error("2D canvas unavailable");e.clearRect(0,0,t.width,t.height),e.fillStyle="#041008",e.fillRect(0,0,t.width,t.height),e.strokeStyle="rgba(0, 255, 102, 0.14)",e.lineWidth=1;for(let n=0;n<=t.width;n+=50)e.beginPath(),e.moveTo(n,0),e.lineTo(n,t.height),e.stroke();for(let n=0;n<=t.height;n+=40)e.beginPath(),e.moveTo(0,n),e.lineTo(t.width,n),e.stroke();return e}function jt(t){const e=t.flat(),n=Math.min(...e),r=Math.max(...e);return!Number.isFinite(n)||!Number.isFinite(r)||n===r?{min:-1,max:1}:{min:n,max:r}}function P(t,e,n,r=[]){const a=$(t),{min:i,max:o}=jt(e),s=18,c=t.height-s*2,u=t.width-s*2;e.forEach((h,d)=>{a.beginPath(),a.lineWidth=r.includes(d)?2.4:1.35,a.strokeStyle=n[d]??"#00ff66",h.forEach((g,f)=>{const l=s+f/Math.max(h.length-1,1)*u,b=s+c-(g-i)/Math.max(o-i,1e-9)*c;f===0?a.moveTo(l,b):a.lineTo(l,b)}),a.stroke()})}function Ht(t,e,n,r){const a=$(t),i=48,o=r?e.concat(r):e,s=Math.min(...o),c=Math.max(...o),h=Math.max(c-s,1)/i,d=new Array(i).fill(0),g=new Array(i).fill(0);e.forEach(l=>{const b=K(Math.floor((l-s)/h),0,i-1);d[b]+=1}),(r??[]).forEach(l=>{const b=K(Math.floor((l-s)/h),0,i-1);g[b]+=1});const f=Math.max(...d,...g,1);for(let l=0;l<i;l+=1){const b=12+l/i*(t.width-24),I=(t.width-24)/i-2,S=d[l]/f*(t.height-32),X=g[l]/f*(t.height-32);a.fillStyle="rgba(0, 212, 255, 0.55)",a.fillRect(b,t.height-12-S,I,S),r&&(a.fillStyle="rgba(255, 51, 102, 0.55)",a.fillRect(b,t.height-12-X,I,X))}}function Kt(t,e,n){const r=$(t),a=Array.from(e,c=>Math.abs(c)),i=Math.max(...a,1e-9),o=16;r.beginPath(),r.lineWidth=1.4,r.strokeStyle="rgba(255, 170, 0, 0.5)",a.forEach((c,u)=>{const h=o+u/Math.max(a.length-1,1)*(t.width-o*2),d=t.height-o-c/i*(t.height-o*2);u===0?r.moveTo(h,d):r.lineTo(h,d)}),r.stroke();const s=o+n/Math.max(a.length-1,1)*(t.width-o*2);r.strokeStyle="#ff3366",r.lineWidth=2,r.beginPath(),r.moveTo(s,8),r.lineTo(s,t.height-8),r.stroke()}function bt(t){B.textContent=t==="dark"?"🌙":"☀️",B.setAttribute("aria-label",t==="dark"?"Switch to light mode":"Switch to dark mode")}function Pt(){const e=(document.documentElement.getAttribute("data-theme")??"dark")==="dark"?"light":"dark";document.documentElement.setAttribute("data-theme",e),localStorage.setItem("theme",e),bt(e)}const B=m("#theme-toggle");bt(document.documentElement.getAttribute("data-theme")??"dark");B.addEventListener("click",Pt);const F=m("#trace-canvas"),Bt=m("#cpa-canvas"),Ft=m("#rejection-canvas"),rt=m("#timing-canvas"),Dt=m("#keccak-canvas"),Ot=m("#trace-hover"),zt=m("#butterfly-grid"),D=m("#cpa-results"),_t=m("#normal-log"),Vt=m("#faulted-log"),Wt=m("#recovery-panel"),O=m("#timing-results"),it=m("#keccak-results"),W=m("#sk-slider"),q=m("#ct-slider"),G=m("#noise-slider"),Y=m("#trace-count-slider"),qt=m("#sk-value"),Gt=m("#ct-value"),Yt=m("#noise-value"),Qt=m("#trace-count-value"),p={secret:1234,baseCipher:567,noise:.5,count:100,ciphertexts:[],traces:[]};let A=new Int32Array(Array.from({length:256},()=>E(-2,M.eta))),T=new Int32Array(Array.from({length:256},()=>E(0,1)===0?-1:1)),L=[],k=[];const x={};function vt(){qt.textContent=W.value,Gt.textContent=q.value,Yt.textContent=G.value,Qt.textContent=Y.value}[W,q,G,Y].forEach(t=>{t.addEventListener("input",vt)});vt();function Xt(t,e){let n=t,r=e;const a=[17,3312,2761,568,583,2746,2649,680];zt.innerHTML=a.map((i,o)=>{const s=ct(n,r,i),c=s.intermediates.map(h=>z(h));return n=s.a_out,r=s.b_out,`
      <article class="butterfly-card ${Math.max(...c)>=8?"hot":""}">
        <h4>Stage ${o+1}</h4>
        <p>zeta = ${i}</p>
        <p>w·b = ${s.intermediates[0]} (HW ${c[0]})</p>
        <p>a + wb = ${s.intermediates[1]} (HW ${c[1]})</p>
        <p>a − wb = ${s.intermediates[2]} (HW ${c[2]})</p>
      </article>
    `}).join("")}async function Q(){p.secret=Number(W.value),p.baseCipher=Number(q.value),p.noise=Number(G.value),p.count=Number(Y.value),p.ciphertexts=Array.from({length:p.count},(e,n)=>(p.baseCipher+n*37)%v),p.traces=[];for(const e of p.ciphertexts)p.traces.push(await Et(p.secret,e,p.noise));const t=p.traces.slice(0,5).map(e=>Array.from(e));P(F,t,["#00ff66","#24d97a","#47c98a","#8be3a8","#d0ffde"]),Xt(p.secret,p.ciphertexts[0]??p.baseCipher),D.innerHTML="<p>Traces generated. Ready to test all 3,329 hypotheses.</p>"}F.addEventListener("mousemove",t=>{var a;if(p.traces.length===0)return;const e=F.getBoundingClientRect(),n=K(Math.round((t.clientX-e.left)/Math.max(e.width,1)*(p.traces[0].length-1)),0,p.traces[0].length-1),r=((a=p.traces[0])==null?void 0:a[n])??0;Ot.textContent=`Sample ${n}: measured power ${y(r,3)} — inspect the butterfly cards below for the exact Hamming weights.`});m("#generate-traces-btn").addEventListener("click",()=>{Q()});m("#run-cpa-btn").addEventListener("click",async()=>{var n,r,a;p.traces.length===0&&await Q(),D.innerHTML="<p>Running CPA across 3,329 key guesses…</p>";const t=Ct(p.traces,p.ciphertexts,1),e=Array.from(t,(i,o)=>({key:o,score:Math.abs(i)})).sort((i,o)=>o.score-i.score).slice(0,5);Kt(Bt,t,p.secret),D.innerHTML=`
    <p><strong>Best correlation:</strong> k = ${(n=e[0])==null?void 0:n.key} (${y(((r=e[0])==null?void 0:r.score)??0,3)})</p>
    <p><strong>Correct key:</strong> sk[0] = ${p.secret} ${((a=e[0])==null?void 0:a.key)===p.secret?"✓ RECOVERED":"• close but noisy"}</p>
    <ul>
      ${e.map(i=>`<li>k = ${i.key} → ${y(i.score,3)}</li>`).join("")}
    </ul>
  `});function ot(t,e=4e3){return t.flatMap(n=>Array.from(n.z).slice(0,32)).slice(0,e)}function N(){_t.innerHTML=L.length===0?"No normal signatures collected yet.":`<ul>${L.slice(0,8).map((n,r)=>`<li>Attempt ${r+1}: z_max = ${n.maxCoeff} ${n.status==="accepted"?"✓ Accept":"✗ Reject"}</li>`).join("")}</ul>`,Vt.innerHTML=k.length===0?"No faulted signatures collected yet.":`<ul>${k.slice(0,8).map((n,r)=>`<li>Signature ${r+1}: z_max = ${n.maxCoeff} ⚠ SHOULD REJECT — bypassed</li>`).join("")}</ul>`;const t=ot(L.filter(n=>n.status==="accepted")),e=ot(k);(t.length>0||e.length>0)&&Ht(Ft,t,void 0,e)}m("#normal-sign-btn").addEventListener("click",async()=>{A=new Int32Array(Array.from({length:256},()=>E(-2,M.eta))),T=new Int32Array(Array.from({length:256},()=>E(0,1)===0?-1:1)),L=await It(A,T,M,20),N()});m("#faulted-sign-btn").addEventListener("click",async()=>{L.length===0&&(A=new Int32Array(Array.from({length:256},()=>E(-2,M.eta))),T=new Int32Array(Array.from({length:256},()=>E(0,1)===0?-1:1))),k=await H(A,T,M,20),N()});m("#recover-btn").addEventListener("click",async()=>{k.length<20?(k=await H(A,T,M,1e3),N()):k=await H(A,T,M,1e3);const t=Rt(k.map(r=>r.z),Array.from({length:k.length},()=>T),M);let e=0;for(let r=0;r<A.length;r+=1)t.recovered[r]===A[r]&&(e+=1);const n=e/A.length*100;Wt.innerHTML=`
    <p><strong>Recovery rate:</strong> ${y(n,1)}% coefficients correct</p>
    <p>Sample recovery:</p>
    <ul>
      ${Array.from({length:8},(r,a)=>`<li>s₁[${a}] ≈ ${t.recovered[a]} (actual ${A[a]}) • confidence ${y(t.confidence[a]??0,2)}</li>`).join("")}
    </ul>
    <p><strong>Countermeasure:</strong> recompute and verify the output before returning the signature.</p>
  `});function yt(){const t=[],e=[],n=[];x.vulnerable&&(t.push(Array.from(x.vulnerable.timings).filter((r,a)=>a%8===0)),e.push("#ff3366"),n.push(0)),x["constant-time"]&&(t.push(Array.from(x["constant-time"].timings).filter((r,a)=>a%8===0)),e.push("#00d4ff"),n.push(t.length-1)),t.length===0?P(rt,[[0,.2,.1,.15,.1]],["#1a4a2a"]):P(rt,t,e,n)}function Jt(){const t=x.vulnerable,e=x["constant-time"],n=[t?`<p><strong>Vulnerable:</strong> bit0 = ${y(t.mean0,4)} µs, bit1 = ${y(t.mean1,4)} µs, gap = ${y(t.difference,4)} µs</p>`:"",e?`<p><strong>Constant-time:</strong> bit0 = ${y(e.mean0,4)} µs, bit1 = ${y(e.mean1,4)} µs, gap = ${y(e.difference,4)} µs</p>`:""].filter(Boolean),r=t&&e?`<p><strong>Comparison:</strong> |gap| drops from ${y(Math.abs(t.difference),4)} µs to ${y(Math.abs(e.difference),4)} µs.</p>`:"<p>Run both experiments to compare the leakage gap.</p>";O.innerHTML=n.join("")+r}async function wt(t){O.innerHTML=`<p>Measuring ${t} decoding timings…</p>`,x[t]=await Ut(t,4,e=>{O.innerHTML=`<p>Measuring ${t} decoding timings… ${y(e,0)}%</p>`}),yt(),Jt()}m("#run-vulnerable-btn").addEventListener("click",()=>{wt("vulnerable")});m("#run-constant-btn").addEventListener("click",()=>{wt("constant-time")});function Zt(t,e){const n=$(Dt),r=44,a=(i,o,s,c)=>{n.fillStyle="#d7ffe5",n.font="14px sans-serif",n.fillText(s,i,20);for(let u=0;u<5;u+=1)for(let h=0;h<5;h+=1){const d=u*5+h,g=o[d]??0n,f=Number(g&255n)/255,l=c&&h<2?"rgba(255, 51, 102,":"rgba(0, 212, 255,";n.fillStyle=`${l}${.25+f*.6})`,n.fillRect(i+h*r,32+u*r,r-4,r-4)}};a(30,t,"Normal absorb",!1),a(320,e,"Faulted absorb",!0)}m("#run-keccak-btn").addEventListener("click",async()=>{it.innerHTML="<p>Faulting KECCAK absorb loop…</p>";const t=await kt();Zt(t.normalLanes,t.faultedLanes),it.innerHTML=`
    <p><strong>Normal input:</strong> ${t.normalInput}</p>
    <p><strong>Faulted input:</strong> ${t.faultedInput}</p>
    <p><strong>ρ′ normal:</strong> ${t.normalRho.slice(0,16)}…</p>
    <p><strong>ρ′ faulted:</strong> ${t.faultedRho.slice(0,16)}…</p>
    <p><strong>Recovered s₁[0..7]:</strong> [${Array.from(t.recovered).join(", ")}]</p>
    <p><strong>Candidate search:</strong> tested ${t.candidateCount} candidates → ${t.success?"match found ✓":"no match"}</p>
  `});Q();yt();N();
