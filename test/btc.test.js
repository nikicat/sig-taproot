// Unit tests for the single-UTXO taproot spend builder — no wallet, no network.
// Uses a fixed Schnorr aux so the signed tx is reproducible.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as btc from '@scure/btc-signer';
import { hexToBytes } from '@noble/hashes/utils.js';
import { deriveMnemonic, taprootAddressAt } from '../src/derive.js';
import { buildSpend, DUST_SATS } from '../src/btc.js';

// Deterministic wallet (same fixed inputs as the derivation vector).
const mnemonic = deriveMnemonic('0x' + '11'.repeat(65), '0x' + '22'.repeat(20));
const owner = taprootAddressAt(mnemonic, 0);
const destination = taprootAddressAt(mnemonic, 1).btcAddress; // a valid mainnet P2TR
const AUX = new Uint8Array(32); // fixed aux → reproducible signature
const utxo = { txid: 'aa'.repeat(32), vout: 0, value: 100_000n };

test('builds a 1-in/1-out taproot spend with correct fee and output', () => {
  const r = buildSpend({ utxo, owner, destination, feeRate: 10, auxRand: AUX });
  assert.equal(r.vsize, 111); // 1 taproot key-path input + 1 P2TR output
  assert.equal(r.fee, 1110n); // ceil(vsize * 10)
  assert.equal(r.outputAmount, 98_890n); // value - fee
  assert.equal(r.fee, utxo.value - r.outputAmount);

  const tx = btc.Transaction.fromRaw(hexToBytes(r.txHex));
  assert.equal(tx.inputsLength, 1);
  assert.equal(tx.outputsLength, 1);
  assert.equal(tx.getOutputAddress(0, btc.NETWORK), destination);
  assert.equal(tx.getOutput(0).amount, 98_890n);
  assert.equal(tx.id, r.txid);
});

test('fee scales with rate; output = value - fee', () => {
  const r = buildSpend({ utxo, owner, destination, feeRate: 25, auxRand: AUX });
  assert.equal(r.fee, BigInt(Math.ceil(r.vsize * 25)));
  assert.equal(r.outputAmount, utxo.value - r.fee);
});

test('deterministic with a fixed aux (byte-identical tx)', () => {
  const a = buildSpend({ utxo, owner, destination, feeRate: 10, auxRand: AUX });
  const b = buildSpend({ utxo, owner, destination, feeRate: 10, auxRand: AUX });
  assert.equal(a.txHex, b.txHex);
  assert.equal(a.txid, b.txid);
});

test('rejects when output would be below dust', () => {
  // value 1000, rate 5 → fee 555 (< value) but output 445 < 546
  assert.throws(
    () => buildSpend({ utxo: { ...utxo, value: 1000n }, owner, destination, feeRate: 5, auxRand: AUX }),
    /below dust/,
  );
});

test('rejects when fee would meet or exceed the UTXO value', () => {
  assert.throws(
    () => buildSpend({ utxo: { ...utxo, value: 100n }, owner, destination, feeRate: 10, auxRand: AUX }),
    /fee .* UTXO value/,
  );
});

test('rejects an invalid destination address', () => {
  assert.throws(
    () => buildSpend({ utxo, owner, destination: 'not-a-real-address', feeRate: 10, auxRand: AUX }),
    /invalid mainnet address/,
  );
});

test('rejects a non-mainnet (testnet) destination', () => {
  assert.throws(
    () =>
      buildSpend({
        utxo,
        owner,
        destination: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
        feeRate: 10,
        auxRand: AUX,
      }),
    /invalid mainnet address/,
  );
});

test('rejects non-positive value and fee rate', () => {
  assert.throws(() => buildSpend({ utxo: { ...utxo, value: 0n }, owner, destination, feeRate: 10 }), /value must be positive/);
  assert.throws(() => buildSpend({ utxo, owner, destination, feeRate: 0 }), /fee rate must be a positive number/);
});

test('DUST_SATS is the documented floor', () => {
  assert.equal(DUST_SATS, 546n);
});
