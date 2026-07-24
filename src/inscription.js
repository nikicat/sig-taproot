// Inscribe arbitrary data via a custom taproot envelope (commit/reveal) — pure,
// DOM-free (node-testable). The Ordinals commit/reveal pattern with our OWN
// envelope (not the ord protocol).
//
// Leaf script (the reveal tapscript):
//   <xonly-pubkey> OP_CHECKSIG  OP_FALSE OP_IF [MARKER] <data chunks ≤520B> OP_ENDIF
// The `<pubkey> OP_CHECKSIG` makes the leaf spendable via the script path; the
// `OP_FALSE OP_IF … OP_ENDIF` envelope is inert dead code that carries the data.
// The commit address uses a NUMS (unspendable) internal key, so the ONLY way to
// spend it is the script path — the reveal always puts the data on-chain.
//
// Modeled on micro-ordinals' OutOrdinalReveal (minus the ord tag/CBOR system).
// All the hard crypto (taproot tweak, control block, sighash, Schnorr) is done by
// @scure/btc-signer via its customScripts mechanism; we only own this envelope codec.

import * as btc from '@scure/btc-signer';
import { hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { DUST_SATS, assertMainnetAddress } from './btc.js';

const MAX_PUSH = 520; // consensus max bytes per script push

// Optional envelope marker (protocol id). Set to `new Uint8Array(0)` for a bare
// OP_FALSE OP_IF <data> OP_ENDIF envelope with no marker.
export const MARKER = utf8ToBytes('sig');

const eqBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const toBytes = (data) => (typeof data === 'string' ? utf8ToBytes(data) : data);

function chunk(data) {
  const out = [];
  for (let i = 0; i < data.length; i += MAX_PUSH) out.push(data.subarray(i, i + MAX_PUSH));
  return out;
}

// btc-signer CustomScript for the envelope leaf. `type` must start with 'tr_'.
// (btc-signer's convention: `encode` = scriptItems → parsed, `decode` = parsed → scriptItems.)
export const OutInscription = Object.freeze({
  encode(from) {
    try {
      const pubkey = from[0];
      if (!(pubkey instanceof Uint8Array) || pubkey.length !== 32) return;
      if (from[1] !== 'CHECKSIG' || from[from.length - 1] !== 'ENDIF') return;
      const ifIdx = from.indexOf('IF');
      if (ifIdx < 0) return;
      let i = ifIdx + 1;
      if (MARKER.length && from[i] instanceof Uint8Array && eqBytes(from[i], MARKER)) i++;
      const pushes = [];
      for (; i < from.length - 1; i++) {
        if (!(from[i] instanceof Uint8Array)) return;
        pushes.push(from[i]);
      }
      return { type: 'tr_inscription', pubkey, data: concatBytes(...pushes) };
    } catch {
      return;
    }
  },
  decode(to) {
    if (to.type !== 'tr_inscription') return;
    const out = [to.pubkey, 'CHECKSIG', 0, 'IF']; // 0 = OP_FALSE
    if (MARKER.length) out.push(MARKER);
    for (const c of chunk(to.data)) out.push(c);
    out.push('ENDIF');
    return out;
  },
  finalizeTaproot(script, parsed, signatures) {
    const [{ pubKey }, sig] = signatures[0];
    if (!eqBytes(pubKey, parsed.pubkey)) return;
    return [sig, script]; // btc-signer appends the taproot control block
  },
});

/**
 * The commit taproot payment for `data` under the owner's key. NUMS internal key
 * ⇒ spendable only by revealing the script (data always goes on-chain).
 * @param {string} xonlyHex - owner x-only pubkey (from taprootAddressAt)
 * @param {Uint8Array|string} data - the data to inscribe
 */
export function commitPayment(xonlyHex, data) {
  const pubkey = hexToBytes(xonlyHex);
  const leaf = {
    type: 'tr',
    script: btc.Script.encode(OutInscription.decode({ type: 'tr_inscription', pubkey, data: toBytes(data) })),
  };
  return btc.p2tr(undefined, leaf, btc.NETWORK, false, [OutInscription]);
}

/** The address the user funds to commit to the inscription. */
export function commitAddress(xonlyHex, data) {
  return commitPayment(xonlyHex, data).address;
}

/**
 * Build a fully-signed reveal transaction: spend the commit UTXO via the script
 * path (revealing the data) to `destination`. 1 input → 1 output, no change.
 * @param {object} args
 * @param {{ txid:string, vout:number, value:bigint|number|string }} args.utxo
 * @param {{ xonlyHex:string, privateKey:Uint8Array }} args.owner
 * @param {Uint8Array|string} args.data - same data used for the commit address
 * @param {string} args.destination - mainnet address
 * @param {number} args.feeRate - sat/vB
 * @param {Uint8Array} [args.auxRand] - fixed Schnorr aux for reproducible tests
 * @returns {{ txHex:string, txid:string, fee:bigint, vsize:number, value:bigint, outputAmount:bigint }}
 */
export function buildReveal({ utxo, owner, data, destination, feeRate, auxRand } = {}) {
  const value = BigInt(utxo.value);
  if (value <= 0n) throw new Error('UTXO value must be positive');
  const rate = Number(feeRate);
  if (!Number.isFinite(rate) || rate <= 0) throw new Error('fee rate must be a positive number');
  assertMainnetAddress(destination);

  const payment = commitPayment(owner.xonlyHex, data);
  const build = (outAmount) => {
    const tx = new btc.Transaction({ customScripts: [OutInscription] });
    tx.addInput({
      ...payment,
      txid: utxo.txid,
      index: utxo.vout,
      witnessUtxo: { script: payment.script, amount: value },
    });
    tx.addOutputAddress(destination, outAmount, btc.NETWORK);
    tx.sign(owner.privateKey, undefined, auxRand);
    tx.finalize();
    return tx;
  };

  // The reveal witness carries the data, so vsize is large but independent of the
  // output amount — probe with the full value, then rebuild with value - fee.
  const vsize = build(value).vsize;
  const fee = BigInt(Math.ceil(vsize * rate));
  const outputAmount = value - fee;
  if (fee >= value) throw new Error(`fee ${fee} >= UTXO value ${value}`);
  if (outputAmount < DUST_SATS) {
    throw new Error(`output ${outputAmount} sat is below dust ${DUST_SATS} after fee ${fee}`);
  }

  const tx = build(outputAmount);
  return { txHex: tx.hex, txid: tx.id, fee: tx.fee, vsize: tx.vsize, value, outputAmount };
}

/**
 * Estimate the reveal size/fee so the user knows how much to send to the commit
 * address. Uses a dummy well-funded UTXO and a self-destination.
 * @returns {{ vsize:number, fee:bigint }}
 */
export function estimateReveal({ owner, data, feeRate }) {
  const r = buildReveal({
    utxo: { txid: '00'.repeat(32), vout: 0, value: 100_000_000n },
    owner,
    data,
    destination: commitAddress(owner.xonlyHex, data),
    feeRate,
    auxRand: new Uint8Array(32),
  });
  return { vsize: r.vsize, fee: BigInt(Math.ceil(r.vsize * Number(feeRate))) };
}
