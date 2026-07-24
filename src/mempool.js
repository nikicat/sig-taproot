// Thin mempool.space REST client for the browser — no backend, no dependencies.
//
// CORS-verified (2026-07-24): GET endpoints return `access-control-allow-origin: *`,
// and POST /tx takes the raw hex as a text/plain body, which is a CORS "simple
// request" (no preflight). Mainnet only.

const BASE = 'https://mempool.space/api';

async function getJson(path) {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`mempool.space ${path} → ${res.status} ${body}`.trim());
  }
  return res.json();
}

/** Unspent outputs for an address: [{ txid, vout, value, status:{confirmed,block_height} }]. */
export function getUtxos(address) {
  return getJson(`/address/${address}/utxo`);
}

/** Recommended fee rates in sat/vB: { fastestFee, halfHourFee, hourFee, economyFee, minimumFee }. */
export function getFeeRates() {
  return getJson('/v1/fees/recommended');
}

/** Broadcast a raw signed tx (hex). Returns the txid, or throws with the node's reason. */
export async function broadcast(txHex) {
  const res = await fetch(`${BASE}/tx`, {
    method: 'POST',
    headers: { 'content-type': 'text/plain' }, // simple request → no CORS preflight
    body: txHex,
  });
  const text = (await res.text()).trim();
  if (!res.ok) throw new Error(`broadcast failed (${res.status}): ${text}`);
  return text; // txid
}

/** Confirmation status: { confirmed, block_height, block_hash, block_time }. */
export function getTxStatus(txid) {
  return getJson(`/tx/${txid}/status`);
}

export const txUrl = (txid) => `https://mempool.space/tx/${txid}`;
export const addressUrl = (address) => `https://mempool.space/address/${address}`;
export const MEMPOOL_API = BASE;
