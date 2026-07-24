// Pure derivation pipeline: EVM wallet signature -> Bitcoin taproot wallet.
//
// No DOM, no `window` — this module is imported both by the browser bundle
// (src/app.js) and directly by the test-vector under node (test/derive.test.js),
// so the derivation is machine-verifiable without a wallet.
//
// EVM signature (deterministic ECDSA) --HKDF--> 32 bytes entropy
//   --BIP-39--> 24-word mnemonic --seed--> BIP-32 root
//   --BIP-86 (m/86'/0'/0'/0/index)--> x-only pubkey --> P2TR bech32m (bc1p...)

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { entropyToMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import * as btc from '@scure/btc-signer';

// Domain-separation string. Baked into both the EIP-712 message the user signs
// (src/app.js) and the HKDF `info` here — changing it changes every derived
// address, so it is versioned and must never drift.
export const CONTEXT = 'sig-taproot/wallet-seed:v1';

// BIP-86 (single-sig P2TR), mainnet account 0, external chain. The receive
// address index varies (a per-UTXO wallet with an indexed address list).
export const pathAt = (index) => `m/86'/0'/0'/0/${index}`;

// Back-compat: the pinned test vector and the "first address" default use index 0.
export const PATH = pathAt(0);

/**
 * Turn a deterministic EVM wallet signature into the wallet's BIP-39 mnemonic.
 * This is the HKDF -> BIP-39 half; addresses come from `taprootAddressAt`.
 *
 * @param {string} signatureHex - `0x`-prefixed 65-byte signature (r||s||v) from
 *   `eth_signTypedData_v4`. Passed through HKDF whole (scheme-agnostic).
 * @param {string} address - `0x`-prefixed 20-byte EOA address, the HKDF salt.
 * @returns {string} 24-word English mnemonic.
 */
export function deriveMnemonic(signatureHex, address) {
  const sig = normalizeHex(signatureHex);
  const addr = normalizeHex(address);
  if (sig.length !== 65 * 2) {
    throw new Error(`expected a 65-byte signature, got ${sig.length / 2} bytes`);
  }
  if (addr.length !== 20 * 2) {
    throw new Error(`expected a 20-byte address, got ${addr.length / 2} bytes`);
  }

  const ikm = hexToBytes(sig); // full 65-byte signature
  const salt = hexToBytes(addr); // 20 address bytes
  const info = utf8ToBytes(CONTEXT);

  const entropy = hkdf(sha256, ikm, salt, info, 32); // 256-bit -> 24 words
  return entropyToMnemonic(entropy, wordlist);
}

/**
 * Derive the taproot receive address (and signing key) at a BIP-86 index.
 *
 * @param {string} mnemonic - from `deriveMnemonic`.
 * @param {number} index - non-negative integer address index.
 * @returns {{ path: string, xonlyHex: string, btcAddress: string, privateKey: Uint8Array }}
 *   `privateKey` is the child key, held in-page to sign a real taproot spend.
 */
export function taprootAddressAt(mnemonic, index) {
  if (!Number.isInteger(index) || index < 0) {
    throw new Error(`address index must be a non-negative integer, got ${index}`);
  }
  const path = pathAt(index);
  const seed = mnemonicToSeedSync(mnemonic);
  const child = HDKey.fromMasterSeed(seed).derive(path);
  if (!child.privateKey) throw new Error('BIP-32 derivation produced no private key');

  const xonly = btc.utils.pubSchnorr(child.privateKey); // 32-byte x-only pubkey
  const { address: btcAddress } = btc.p2tr(xonly, undefined, btc.NETWORK); // bc1p...

  return { path, xonlyHex: bytesToHex(xonly), btcAddress, privateKey: child.privateKey };
}

/**
 * Convenience: derive the first (index 0) taproot wallet in one call. Returns
 * the mnemonic alongside the index-0 address. Kept for the pinned test vector.
 *
 * @returns {{ mnemonic: string, path: string, xonlyHex: string,
 *   btcAddress: string, privateKey: Uint8Array }}
 */
export function deriveTaproot(signatureHex, address) {
  const mnemonic = deriveMnemonic(signatureHex, address);
  return { mnemonic, ...taprootAddressAt(mnemonic, 0) };
}

// Strip an optional `0x` prefix and lowercase; leaves the caller's byte content
// intact (address checksum casing is irrelevant to the derived bytes).
function normalizeHex(value) {
  const s = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  return s.toLowerCase();
}
