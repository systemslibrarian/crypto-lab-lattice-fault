import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The simulations call Web Crypto (crypto.getRandomValues, crypto.subtle)
    // and performance.now(); all are available on Node's globals, so the fast
    // default 'node' environment is enough — no jsdom needed.
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
});
