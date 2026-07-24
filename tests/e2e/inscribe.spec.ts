/**
 * Tier 1 e2e (gates CI): the full inscription commit/reveal flow in a real browser
 * with mempool.space STUBBED. Enter data → create commit address (persisted to
 * localStorage) → scan (stubbed UTXO) → reveal → broadcast, then decode the posted
 * reveal tx and assert its witness carries the exact data. No real network/funds.
 */
import { test, expect } from '@playwright/test';
import * as btc from '@scure/btc-signer';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { taprootAddressAt } from '../../src/derive.js';
import { commitAddress, OutInscription } from '../../src/inscription.js';
import { account, installProvider, walletMnemonic } from './inject-eoa.js';

const DATA = 'hello inscription — e2e test payload';
const FEES = { fastestFee: 10, halfHourFee: 6, hourFee: 3, economyFee: 2, minimumFee: 1 };
const FAKE_TXID = 'cd'.repeat(32);
const UTXO = { txid: 'ab'.repeat(32), vout: 0, value: 60_000 };

test('inscription: create → persist → scan → reveal the data on-chain (mempool stubbed)', async ({ page }) => {
  const mnemonic = await walletMnemonic();
  const owner = taprootAddressAt(mnemonic, 0);
  const commit = commitAddress(owner.xonlyHex, DATA);
  const destination = taprootAddressAt(mnemonic, 1).btcAddress;
  let broadcastBody: string | null = null;

  await page.route(/mempool\.space/, (route) => route.abort('failed')); // safety net
  await page.route(/\/api\/v1\/fees\/recommended/, (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(FEES) }),
  );
  await page.route(/\/api\/address\/[^/]+\/utxo/, (route) => {
    const body = route.request().url().includes(commit)
      ? JSON.stringify([{ ...UTXO, status: { confirmed: true, block_height: 900_000 } }])
      : '[]';
    return route.fulfill({ status: 200, contentType: 'application/json', body });
  });
  await page.route(/\/api\/tx$/, (route) => {
    broadcastBody = route.request().postData();
    return route.fulfill({ status: 200, contentType: 'text/plain', body: FAKE_TXID });
  });
  page.on('dialog', (d) => d.accept());

  await installProvider(page);
  await page.goto('/');
  await page.getByRole('button', { name: /connect/i }).click();
  await expect(page.locator('#btcAddress')).not.toBeEmpty({ timeout: 30_000 });

  // Create the inscription; commit address is shown and persisted.
  await page.locator('#inscribeData').fill(DATA);
  await page.getByRole('button', { name: /create inscription address/i }).click();
  await expect(page.locator('#inscriptionList')).toContainText(commit, { timeout: 15_000 });

  // Persistence: reload + reconnect, the inscription is still listed from localStorage.
  await page.reload();
  await page.getByRole('button', { name: /connect/i }).click();
  await expect(page.locator('#inscriptionList')).toContainText(commit, { timeout: 30_000 });

  // Scan the commit address → a UTXO with a Reveal button appears.
  await page.locator('#inscriptionList').getByRole('button', { name: /^scan$/i }).first().click();
  await page.locator('#inscriptionList').getByRole('button', { name: /^reveal$/i }).first().click();

  // Reveal → destination → preview → confirm.
  await page.locator('#revealDest').fill(destination);
  await page.getByRole('button', { name: /^preview$/i }).click();
  await expect(page.locator('#revealPreview')).toContainText(/fee/i);
  await page.getByRole('button', { name: /confirm & broadcast/i }).click();
  await expect(page.locator('#revealResult')).toContainText(FAKE_TXID, { timeout: 15_000 });

  // The broadcast reveal tx carries the data in its witness.
  expect(broadcastBody, 'broadcast fired').toBeTruthy();
  const tx = btc.Transaction.fromRaw(hexToBytes(broadcastBody!));
  expect(tx.inputsLength).toBe(1);
  expect(tx.outputsLength).toBe(1);
  expect(tx.getOutputAddress(0, btc.NETWORK)).toBe(destination);
  const witness = tx.getInput(0).finalScriptWitness!; // [sig, leaf script, control block]
  const recovered = OutInscription.encode(btc.Script.decode(witness[1]));
  expect(recovered && bytesToHex(recovered.data)).toBe(bytesToHex(utf8ToBytes(DATA)));
});
