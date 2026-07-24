import { defineConfig } from '@playwright/test';

// Two e2e projects:
//   mock   — Tier 1: injected real-key EIP-1193 provider, headless, deterministic. Gates CI.
//   ambire — Tier 2: the REAL Ambire extension (launches its own persistent context under
//            Xvfb). Non-gating in CI; skips locally unless the build + a DISPLAY are present.
// Both serve the built page from the repo root over http (wallets reject file://).
export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  reporter: 'list',
  webServer: {
    command: 'pnpm run bundle && python3 -m http.server 8000',
    url: 'http://127.0.0.1:8000',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:8000',
  },
  projects: [
    // mock = all headless specs except the real-Ambire one.
    { name: 'mock', testIgnore: /ambire\.spec\.ts/, use: { headless: true } },
    { name: 'ambire', testMatch: /ambire\.spec\.ts/ },
  ],
});
