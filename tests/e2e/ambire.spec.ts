/**
 * Tier 2 e2e (non-gating): drive the real page against the REAL Ambire extension.
 * This is the regression guard for the wallet-integration bug that motivated all
 * this — Ambire dropping a back-to-back second signature. Requires a display
 * (Xvfb) and the downloaded extension build, so it skips cleanly otherwise; in CI
 * it runs with continue-on-error.
 *
 *   bash tests/e2e/setup-ambire.sh                     # once: fetch the build
 *   xvfb-run -a -s "-screen 0 1600x1000x24" pnpm test:e2e:ambire
 *
 * The baked fixture is anvil account 0 imported as an EOA (Basic account) — the
 * same key Tier 1 uses — so it derives the SAME address, cross-validating the two
 * tiers.
 */
import { test, expect } from '@playwright/test';
import { existsSync } from 'node:fs';
import { BUILD_DIR, approveRequestWindow, bootAmbire, hardenDisplayEnv, registerCleanup } from './ambire-harness.js';

const PAGE_URL = 'http://127.0.0.1:8000/';
// Same key as Tier 1 (anvil acct 0) => same derived address. Cross-tier pin.
const EXPECTED_ADDRESS = 'bc1pdm3k9qhvexuudmej2xmmjpyvvudmqclmkte4qk8jr43ylknaqs0qwcv59l';

test.skip(
  !process.env.DISPLAY || !existsSync(BUILD_DIR),
  'needs a DISPLAY (run under xvfb-run) and tests/e2e/ambire-build (run setup-ambire.sh)',
);

test('real Ambire EOA: derive with one signature, then verify determinism', async () => {
  test.setTimeout(180_000);
  registerCleanup();
  hardenDisplayEnv();

  const { ctx } = await bootAmbire();
  const dapp = await ctx.newPage();
  dapp.setDefaultTimeout(60_000);

  await dapp.goto(PAGE_URL, { waitUntil: 'load' });
  await dapp.getByRole('button', { name: /connect/i }).first().click();

  // dapp-connect popup, then ONE signature to derive.
  expect(await approveRequestWindow(ctx, ['dapp-connect-button'])).toBe('dapp-connect-button');
  expect(await approveRequestWindow(ctx, ['button-sign'])).toBe('button-sign');

  const btc = dapp.locator('#btcAddress');
  await expect(btc).not.toBeEmpty({ timeout: 30_000 });
  expect((await btc.textContent())!.trim()).toBe(EXPECTED_ADDRESS);

  // Determinism is a SEPARATE gesture (back-to-back signing breaks Ambire).
  await dapp.getByRole('button', { name: /sign again/i }).click();
  expect(await approveRequestWindow(ctx, ['button-sign'])).toBe('button-sign');
  await expect(dapp.locator('#determinism')).toContainText(/determinism verified/i, {
    timeout: 30_000,
  });
  await expect(dapp.locator('#determinism')).toContainText(EXPECTED_ADDRESS);

  await ctx.close();
});
