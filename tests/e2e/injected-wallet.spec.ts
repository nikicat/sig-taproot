/**
 * Tier 1 e2e (gates CI): drive the real page in headless Chromium against an
 * injected EIP-1193 provider that signs with a REAL key (viem). This produces a
 * genuine deterministic 65-byte ECDSA signature — byte-identical to what a real
 * EOA wallet would return for the same payload — so the page derives a real
 * bc1p… address. Deterministic, no extension, no Xvfb, no network.
 */
import { test, expect, type Page } from '@playwright/test';
import { privateKeyToAccount } from 'viem/accounts';
import { deriveTaproot } from '../../src/derive.js';

// anvil account 0 (public, well-known test key).
const TEST_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const account = privateKeyToAccount(TEST_KEY);

// Pinned regression value for TEST_KEY (locks the full page pipeline).
const PINNED_ADDRESS = 'bc1pdm3k9qhvexuudmej2xmmjpyvvudmqclmkte4qk8jr43ylknaqs0qwcv59l';

// The signer the injected provider forwards eth_signTypedData_v4 to. viem's
// signTypedData must NOT receive EIP712Domain in `types` (it derives the domain
// itself); stripping it yields the same signature a wallet produces from the full
// eth_signTypedData_v4 JSON. Captures the last signature for cross-checking.
let lastSig: string | null = null;
async function installProvider(page: Page) {
  await page.exposeFunction('__e2eSignTypedData', async (_from: string, json: string) => {
    const td = JSON.parse(json);
    const { EIP712Domain, ...types } = td.types;
    lastSig = await account.signTypedData({
      domain: td.domain,
      types,
      primaryType: td.primaryType,
      message: td.message,
    });
    return lastSig;
  });

  await page.addInitScript((address: string) => {
    const provider = {
      isMetaMask: true,
      on() {},
      removeListener() {},
      async request({ method, params }: { method: string; params?: any[] }) {
        switch (method) {
          case 'eth_requestAccounts':
          case 'eth_accounts':
            return [address];
          case 'eth_chainId':
            return '0x1';
          case 'eth_signTypedData_v4':
            return (window as any).__e2eSignTypedData(params![0], params![1]);
          default:
            throw Object.assign(new Error(`unhandled ${method}`), { code: 4200 });
        }
      },
    };
    (window as any).ethereum = provider;
  }, account.address);
}

test('injected EOA: derive, pin, and verify determinism', async ({ page }) => {
  await installProvider(page);
  await page.goto('/');

  await page.getByRole('button', { name: /connect/i }).click();

  const btc = page.locator('#btcAddress');
  await expect(btc).not.toBeEmpty({ timeout: 30_000 });
  const derived = (await btc.textContent())!.trim();

  // (a) regression pin, and (b) page derivation == independent node derivation of
  // the exact signature the page sent.
  expect(derived).toBe(PINNED_ADDRESS);
  expect(lastSig, 'provider was asked to sign').toBeTruthy();
  expect(deriveTaproot(lastSig!, account.address).btcAddress).toBe(derived);
  await expect(page.locator('#status')).toHaveClass(/status--ok/);

  // Determinism is a separate gesture — "Sign again to verify".
  await page.getByRole('button', { name: /sign again/i }).click();
  await expect(page.locator('#determinism')).toContainText(/determinism verified/i, {
    timeout: 30_000,
  });
  await expect(page.locator('#determinism')).toContainText(derived);
});
