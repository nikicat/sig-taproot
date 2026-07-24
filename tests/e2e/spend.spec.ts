/**
 * Tier 1 e2e (gates CI): the full spend flow in a real browser with mempool.space
 * STUBBED via page.route — no real network, no real funds. An injected real-key
 * provider derives the wallet; we stub UTXOs + fees + broadcast, drive
 * scan → Spend → preview → confirm, and assert the broadcast POST body is the
 * expected taproot tx (decoded and checked against a node-side build).
 */
import { test, expect, type Page } from '@playwright/test';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256 } from 'viem';
import * as btc from '@scure/btc-signer';
import { hexToBytes } from '@noble/hashes/utils.js';
import { deriveMnemonic, taprootAddressAt, CONTEXT } from '../../src/derive.js';
import { buildSpend } from '../../src/btc.js';

const TEST_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const account = privateKeyToAccount(TEST_KEY);

// The exact EIP-712 payload app.js builds (kept in sync with buildTypedData there).
function typedData(addr: string) {
  return {
    domain: { name: 'sig-taproot', version: '1' },
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
      ],
      Derivation: [
        { name: 'action', type: 'string' },
        { name: 'context', type: 'string' },
        { name: 'addressHash', type: 'bytes32' },
      ],
    },
    primaryType: 'Derivation' as const,
    message: { action: 'Derive Bitcoin Taproot Wallet', context: CONTEXT, addressHash: keccak256(addr as `0x${string}`) },
  };
}

// Reproduce the signature the injected provider will return, to precompute the
// same addresses/keys the page will derive.
async function walletFromKey() {
  const td = typedData(account.address);
  const { EIP712Domain, ...types } = td.types;
  const sig = await account.signTypedData({ domain: td.domain, types, primaryType: td.primaryType, message: td.message });
  const mnemonic = deriveMnemonic(sig, account.address);
  return {
    owner: taprootAddressAt(mnemonic, 0), // where the stubbed UTXO lives
    destination: taprootAddressAt(mnemonic, 1).btcAddress,
  };
}

async function installProvider(page: Page) {
  await page.exposeFunction('__e2eSignTypedData', async (_from: string, json: string) => {
    const td = JSON.parse(json);
    const { EIP712Domain, ...types } = td.types;
    return account.signTypedData({ domain: td.domain, types, primaryType: td.primaryType, message: td.message });
  });
  await page.addInitScript((address: string) => {
    (window as any).ethereum = {
      isMetaMask: true,
      on() {},
      removeListener() {},
      async request({ method, params }: { method: string; params?: any[] }) {
        if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [address];
        if (method === 'eth_chainId') return '0x1';
        if (method === 'eth_signTypedData_v4') return (window as any).__e2eSignTypedData(params![0], params![1]);
        throw Object.assign(new Error(`unhandled ${method}`), { code: 4200 });
      },
    };
  }, account.address);
}

const UTXO = { txid: 'ab'.repeat(32), vout: 0, value: 100_000 };
const FEES = { fastestFee: 10, halfHourFee: 6, hourFee: 3, economyFee: 2, minimumFee: 1 };
const FAKE_TXID = 'cd'.repeat(32);

test('spend flow: scan → build → broadcast the expected taproot tx (mempool stubbed)', async ({ page }) => {
  const { owner, destination } = await walletFromKey();
  let broadcastBody: string | null = null;

  // Safety net first (lowest priority): fail loudly if any mempool call is unstubbed.
  await page.route(/mempool\.space/, (route) => route.abort('failed'));
  await page.route(/\/api\/v1\/fees\/recommended/, (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(FEES) }),
  );
  await page.route(/\/api\/address\/[^/]+\/utxo/, (route) => {
    const body = route.request().url().includes(owner.btcAddress)
      ? JSON.stringify([{ ...UTXO, status: { confirmed: true, block_height: 900_000 } }])
      : '[]';
    return route.fulfill({ status: 200, contentType: 'application/json', body });
  });
  await page.route(/\/api\/tx$/, (route) => {
    broadcastBody = route.request().postData();
    return route.fulfill({ status: 200, contentType: 'text/plain', body: FAKE_TXID });
  });
  page.on('dialog', (d) => d.accept()); // the mainnet confirm()

  await installProvider(page);
  await page.goto('/');
  await page.getByRole('button', { name: /connect/i }).click();
  await expect(page.locator('#btcAddress')).not.toBeEmpty({ timeout: 30_000 });

  // Scan → the stubbed UTXO shows up with a Spend button.
  await page.getByRole('button', { name: /scan for utxos/i }).click();
  await expect(page.locator('#utxoStatus')).toContainText(/1 UTXO/i, { timeout: 15_000 });
  await page.locator('#utxoList').getByRole('button', { name: /spend/i }).first().click();

  // Fill destination + preview + confirm.
  await page.locator('#destAddress').fill(destination);
  await page.getByRole('button', { name: /^preview$/i }).click();
  await expect(page.locator('#spendPreview')).toContainText(/txid/i);
  await page.getByRole('button', { name: /confirm & broadcast/i }).click();
  await expect(page.locator('#spendResult')).toContainText(FAKE_TXID, { timeout: 15_000 });

  // The broadcast body is the expected 1-in/1-out taproot spend.
  expect(broadcastBody, 'broadcast POST fired').toBeTruthy();
  const expected = buildSpend({
    utxo: { txid: UTXO.txid, vout: UTXO.vout, value: BigInt(UTXO.value) },
    owner,
    destination,
    feeRate: FEES.halfHourFee,
  });
  const tx = btc.Transaction.fromRaw(hexToBytes(broadcastBody!));
  expect(tx.inputsLength).toBe(1);
  expect(tx.outputsLength).toBe(1);
  expect(tx.getOutputAddress(0, btc.NETWORK)).toBe(destination);
  expect(tx.getOutput(0).amount).toBe(expected.outputAmount);
});
