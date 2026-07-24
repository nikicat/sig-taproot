// Unit tests for the mempool.space client — stubbed fetch, no network.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getUtxos, getFeeRates, broadcast, getTxStatus, txUrl } from '../src/mempool.js';

// Install a fake fetch that records the last request and returns a canned response.
function stubFetch({ ok = true, status = 200, json, text } = {}) {
  const calls = [];
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({ url, opts });
    return {
      ok,
      status,
      json: async () => json,
      text: async () => (text ?? (json !== undefined ? JSON.stringify(json) : '')),
    };
  };
  return calls;
}

test('getUtxos GETs the address utxo endpoint and returns parsed JSON', async () => {
  const utxos = [{ txid: 'ab'.repeat(32), vout: 0, value: 1234, status: { confirmed: true, block_height: 900000 } }];
  const calls = stubFetch({ json: utxos });
  const out = await getUtxos('bc1pexample');
  assert.deepEqual(out, utxos);
  assert.equal(calls[0].url, 'https://mempool.space/api/address/bc1pexample/utxo');
  assert.ok(!calls[0].opts.method || calls[0].opts.method === 'GET');
});

test('getFeeRates GETs the recommended fees endpoint', async () => {
  const fees = { fastestFee: 8, halfHourFee: 5, hourFee: 3, economyFee: 2, minimumFee: 1 };
  const calls = stubFetch({ json: fees });
  const out = await getFeeRates();
  assert.deepEqual(out, fees);
  assert.equal(calls[0].url, 'https://mempool.space/api/v1/fees/recommended');
});

test('broadcast POSTs the hex as text/plain and returns the txid', async () => {
  const txid = 'cd'.repeat(32);
  const calls = stubFetch({ text: txid });
  const out = await broadcast('0200000000...');
  assert.equal(out, txid);
  assert.equal(calls[0].url, 'https://mempool.space/api/tx');
  assert.equal(calls[0].opts.method, 'POST');
  assert.equal(calls[0].opts.headers['content-type'], 'text/plain');
  assert.equal(calls[0].opts.body, '0200000000...');
});

test('broadcast throws with the node reason on failure', async () => {
  stubFetch({ ok: false, status: 400, text: 'sendrawtransaction RPC error: dust' });
  await assert.rejects(() => broadcast('deadbeef'), /broadcast failed \(400\): .*dust/);
});

test('getTxStatus GETs the tx status endpoint', async () => {
  const calls = stubFetch({ json: { confirmed: false } });
  await getTxStatus('ff'.repeat(32));
  assert.equal(calls[0].url, `https://mempool.space/api/tx/${'ff'.repeat(32)}/status`);
});

test('getJson surfaces non-OK responses', async () => {
  stubFetch({ ok: false, status: 404, text: 'Not Found' });
  await assert.rejects(() => getUtxos('bad'), /404 Not Found/);
});

test('txUrl points at the mempool.space explorer', () => {
  assert.equal(txUrl('abc'), 'https://mempool.space/tx/abc');
});
