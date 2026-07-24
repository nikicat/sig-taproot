// Single-UTXO taproot key-path spend builder — pure, DOM-free (node-testable).
//
// A per-UTXO wallet: spending is an action on ONE utxo. Builds a 1-input /
// 1-output taproot key-path transaction that fully spends the UTXO (value - fee)
// to a destination — no change, no coin selection. Mainnet only.

import * as btc from '@scure/btc-signer';
import { hexToBytes } from '@noble/hashes/utils.js';

// Conservative dust floor (sats). Real relay dust is lower for P2TR/P2WPKH, but a
// single threshold across destination types is simpler and safe for a demo.
export const DUST_SATS = 546n;

/** Validate a mainnet BTC address; throws on invalid or wrong-network input. */
export function assertMainnetAddress(address) {
  try {
    btc.Address(btc.NETWORK).decode(address);
  } catch {
    throw new Error(`invalid mainnet address: ${address}`);
  }
}

/**
 * Build a fully-signed taproot key-path spend of a single UTXO.
 *
 * @param {object} args
 * @param {{ txid: string, vout: number, value: bigint|number|string }} args.utxo
 * @param {{ xonlyHex: string, privateKey: Uint8Array }} args.owner - from taprootAddressAt
 * @param {string} args.destination - mainnet BTC address
 * @param {number} args.feeRate - sat/vB
 * @param {Uint8Array} [args.auxRand] - fixed Schnorr aux for reproducible tests;
 *   omit in production (BIP-340 random aux).
 * @returns {{ txHex: string, txid: string, fee: bigint, vsize: number,
 *   value: bigint, outputAmount: bigint, feeRate: number }}
 */
export function buildSpend({ utxo, owner, destination, feeRate, auxRand } = {}) {
  const value = BigInt(utxo.value);
  if (value <= 0n) throw new Error('UTXO value must be positive');
  const rate = Number(feeRate);
  if (!Number.isFinite(rate) || rate <= 0) throw new Error('fee rate must be a positive number');
  assertMainnetAddress(destination);

  const xonly = hexToBytes(owner.xonlyHex);
  const spend = btc.p2tr(xonly, undefined, btc.NETWORK);

  const build = (outAmount) => {
    const tx = new btc.Transaction();
    tx.addInput({
      txid: utxo.txid,
      index: utxo.vout,
      witnessUtxo: { script: spend.script, amount: value },
      tapInternalKey: xonly,
    });
    tx.addOutputAddress(destination, outAmount, btc.NETWORK);
    tx.sign(owner.privateKey, undefined, auxRand);
    tx.finalize();
    return tx;
  };

  // The output amount is a fixed-width field, so vsize is independent of it:
  // probe with the full value to measure vsize, then rebuild with value - fee.
  const vsize = build(value).vsize;
  const fee = BigInt(Math.ceil(vsize * rate));
  const outputAmount = value - fee;
  if (fee >= value) throw new Error(`fee ${fee} >= UTXO value ${value}`);
  if (outputAmount < DUST_SATS) {
    throw new Error(`output ${outputAmount} sat is below dust ${DUST_SATS} after fee ${fee}`);
  }

  const tx = build(outputAmount);
  return {
    txHex: tx.hex,
    txid: tx.id,
    fee: tx.fee, // actual fee from the finalized tx (== value - outputAmount)
    vsize: tx.vsize,
    value,
    outputAmount,
    feeRate: rate,
  };
}
