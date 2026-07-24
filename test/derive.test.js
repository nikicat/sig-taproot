// Automated derivation test-vector — no wallet required.
//
// Feeds a fixed 65-byte signature + fixed address through the pure pipeline and
// asserts the exact mnemonic and bc1p address. This locks the derivation against
// dependency drift and proves determinism: if any constant (context string,
// HKDF params, path, wordlist) or a bumped @scure/@noble version changes the
// output, these vectors go red.
//
// Run: `pnpm test`  (node --test)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveTaproot, PATH, CONTEXT } from '../src/derive.js';

const SIG = '0x' + '11'.repeat(65); // fixed 65-byte signature
const ADDR = '0x' + '22'.repeat(20); // fixed 20-byte EOA address

// Pinned on 2026-07-24 with @scure/* 2.2.0, @noble/hashes 2.2.0.
const EXPECTED = {
  mnemonic:
    'arrow birth burst unique space health regret cannon name erase never bubble ' +
    'oblige border violin manage dust pioneer ostrich dash carbon glance mango safe',
  xonlyHex: 'd541b36d9cd452eb35a5ee0dac5111f638b90655377af70eb9e1ae2461eaba1a',
  btcAddress: 'bc1plshpn20lv6899ca2x7wewnvdl50h46memkf9zrqc3fe7xk7nu52s2n9wjs',
};

test('fixed signature + address -> pinned taproot wallet', () => {
  const r = deriveTaproot(SIG, ADDR);
  assert.equal(r.mnemonic, EXPECTED.mnemonic);
  assert.equal(r.xonlyHex, EXPECTED.xonlyHex);
  assert.equal(r.btcAddress, EXPECTED.btcAddress);
  assert.equal(r.path, PATH);
  assert.equal(r.mnemonic.split(' ').length, 24);
  assert.ok(r.btcAddress.startsWith('bc1p'));
  assert.equal(r.privateKey.length, 32);
});

test('derivation is deterministic (same inputs -> same address)', () => {
  const a = deriveTaproot(SIG, ADDR);
  const b = deriveTaproot(SIG, ADDR);
  assert.equal(a.btcAddress, b.btcAddress);
  assert.equal(a.mnemonic, b.mnemonic);
});

test('address is part of the salt (different account -> different wallet)', () => {
  const a = deriveTaproot(SIG, ADDR);
  const b = deriveTaproot(SIG, '0x' + '33'.repeat(20));
  assert.notEqual(a.btcAddress, b.btcAddress);
  assert.notEqual(a.mnemonic, b.mnemonic);
});

test('signature entropy matters (different signature -> different wallet)', () => {
  const a = deriveTaproot(SIG, ADDR);
  const b = deriveTaproot('0x' + '44'.repeat(65), ADDR);
  assert.notEqual(a.btcAddress, b.btcAddress);
});

test('malformed inputs are rejected, not silently truncated', () => {
  assert.throws(() => deriveTaproot('0x' + '11'.repeat(64), ADDR), /65-byte signature/);
  assert.throws(() => deriveTaproot(SIG, '0x' + '22'.repeat(19)), /20-byte address/);
});

test('context string is the versioned domain separator', () => {
  assert.equal(CONTEXT, 'sig-taproot/wallet-seed:v1');
});
