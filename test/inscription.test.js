// Unit tests for the custom-envelope inscription builder — no wallet, no network.
// Fixed Schnorr aux → reproducible reveal tx.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as btc from '@scure/btc-signer';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { deriveMnemonic, taprootAddressAt } from '../src/derive.js';
import { commitAddress, buildReveal, estimateReveal, OutInscription } from '../src/inscription.js';

const mnemonic = deriveMnemonic('0x' + '11'.repeat(65), '0x' + '22'.repeat(20));
const owner = taprootAddressAt(mnemonic, 0);
const destination = taprootAddressAt(mnemonic, 1).btcAddress;
const AUX = new Uint8Array(32);
const utxo = { txid: 'ab'.repeat(32), vout: 0, value: 50_000n };

test('commit address is deterministic and pinned for fixed data + key', () => {
  assert.equal(
    commitAddress(owner.xonlyHex, 'hello world'),
    'bc1p4pgeq48htfuyerqg792fm96645kem7km56yt73w07uap34gg5a2q9ndxpv',
  );
  // different data => different commit address
  assert.notEqual(commitAddress(owner.xonlyHex, 'hello world'), commitAddress(owner.xonlyHex, 'other'));
});

test('reveal spends the commit UTXO 1-in/1-out with correct fee', () => {
  const r = buildReveal({ utxo, owner, data: 'hello world', destination, feeRate: 10, auxRand: AUX });
  assert.equal(r.vsize, 133);
  assert.equal(r.fee, 1330n);
  assert.equal(r.outputAmount, 48_670n);
  assert.equal(r.fee, utxo.value - r.outputAmount);

  const tx = btc.Transaction.fromRaw(hexToBytes(r.txHex));
  assert.equal(tx.inputsLength, 1);
  assert.equal(tx.outputsLength, 1);
  assert.equal(tx.getOutputAddress(0, btc.NETWORK), destination);
  assert.equal(tx.getOutput(0).amount, 48_670n);
});

test('reveal witness carries the data (round-trip out of the on-chain tx)', () => {
  const data = utf8ToBytes('the quick brown fox — '.repeat(60)); // ~1.3 KB, multi-chunk
  const r = buildReveal({ utxo: { ...utxo, value: 200_000n }, owner, data, destination, feeRate: 5, auxRand: AUX });
  const tx = btc.Transaction.fromRaw(hexToBytes(r.txHex));
  const witness = tx.getInput(0).finalScriptWitness; // [schnorr sig, leaf script, control block]
  assert.equal(witness.length, 3);
  const recovered = OutInscription.encode(btc.Script.decode(witness[1]));
  assert.ok(recovered, 'leaf parses back to an inscription');
  assert.equal(bytesToHex(recovered.data), bytesToHex(data));
});

test('deterministic with a fixed aux', () => {
  const a = buildReveal({ utxo, owner, data: 'x', destination, feeRate: 10, auxRand: AUX });
  const b = buildReveal({ utxo, owner, data: 'x', destination, feeRate: 10, auxRand: AUX });
  assert.equal(a.txHex, b.txHex);
});

test('rejects dust, fee>=value, and invalid destination', () => {
  assert.throws(
    () => buildReveal({ utxo: { ...utxo, value: 1200n }, owner, data: 'x', destination, feeRate: 10, auxRand: AUX }),
    /below dust|>= UTXO value/,
  );
  assert.throws(
    () => buildReveal({ utxo: { ...utxo, value: 100n }, owner, data: 'x', destination, feeRate: 10, auxRand: AUX }),
    /fee .* UTXO value/,
  );
  assert.throws(
    () => buildReveal({ utxo, owner, data: 'x', destination: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', feeRate: 10, auxRand: AUX }),
    /invalid mainnet address/,
  );
});

test('estimateReveal returns size + fee for a funding hint', () => {
  const e = estimateReveal({ owner, data: 'hello world', feeRate: 10 });
  assert.equal(e.vsize, 133);
  assert.equal(e.fee, 1330n);
});
