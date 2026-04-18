import './styles.css';

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App root not found');
}

app.innerHTML = `
  <main class="shell">
    <header class="hero">
      <span class="badge">SIMULATED</span>
      <h1>crypto-lab-lattice-fault</h1>
      <p>
        Browser demo of implementation attacks on ML-KEM and ML-DSA.
      </p>
    </header>
  </main>
`;
