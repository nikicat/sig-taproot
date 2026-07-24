// Wallet + DOM wiring for the sig-taproot demo.
//
// Flow: connect an EOA -> sign the EIP-712 payload ONCE -> derive the taproot
// wallet in-page -> display it. A non-EOA (EIP-1271) signature is rejected by its
// shape. The "Sign again to verify" button re-signs and re-derives as a SEPARATE
// user gesture to prove determinism live (signing twice back-to-back makes some
// wallets, e.g. Ambire, drop the second request).
//
// All key material stays in this page. See README for the security model.

import { keccak256, hashTypedData, getAddress } from 'viem';
import { deriveTaproot, taprootAddressAt, CONTEXT } from './derive.js';
import { buildSpend } from './btc.js';
import { getUtxos, getFeeRates, broadcast, txUrl } from './mempool.js';

// EIP-712 payload the user signs. The `context` string is the phishing defense:
// any dapp can replay this exact payload, so the user must recognize the text.
// `addressHash = keccak256(address)` commits the signature to the signing account.
function buildTypedData(account) {
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
    primaryType: 'Derivation',
    message: {
      action: 'Derive Bitcoin Taproot Wallet',
      context: CONTEXT,
      addressHash: keccak256(account),
    },
  };
}

// --- DOM helpers -----------------------------------------------------------

const $ = (id) => document.getElementById(id);

function setStatus(msg, kind = 'info') {
  const el = $('status');
  el.textContent = msg;
  el.className = `status status--${kind}`;
}

function requireProvider() {
  const eth = globalThis.ethereum;
  if (!eth) {
    throw new Error('No EVM wallet found. Install MetaMask (or another EOA wallet) and reload.');
  }
  return eth;
}

// Sign the payload once with eth_signTypedData_v4 (returns 0x + 130 hex = 65 bytes).
// `phase` labels the call so the error handler can say which prompt was rejected.
async function signOnce(eth, account, typedData, phase) {
  try {
    return await eth.request({
      method: 'eth_signTypedData_v4',
      params: [account, JSON.stringify(typedData)],
    });
  } catch (err) {
    if (err && typeof err === 'object') err.signPhase = phase;
    throw err;
  }
}

// Best-effort identification of the injected wallet, for the console log — a
// non-MetaMask provider can behave differently (some return 4001 for typed data
// they don't fully support, or route to the wrong wallet when several inject).
function describeProvider(eth) {
  const flags = [
    [eth.isMetaMask, 'MetaMask'],
    [eth.isRabby, 'Rabby'],
    [eth.isCoinbaseWallet, 'Coinbase'],
    [eth.isBraveWallet, 'Brave'],
    [eth.isTrust, 'Trust'],
    [eth.isPhantom, 'Phantom'],
    [eth.isAmbire, 'Ambire'],
  ]
    .filter(([f]) => f)
    .map(([, n]) => n);
  const multi = Array.isArray(eth.providers)
    ? ` — ${eth.providers.length} providers injected (ambiguous)`
    : '';
  return (flags.join('/') || 'unknown provider') + multi;
}

const EOA_HINT =
  'This demo needs a plain EOA that signs with deterministic ECDSA (e.g. MetaMask, or an ' +
  'Ambire "Basic"/EOA account). Smart-contract accounts (Ambire smart accounts, Safe, ' +
  'ERC-4337/1271) sign via contracts, not a canonical 65-byte ECDSA signature, so they ' +
  'are not supported.';

// A standard EOA signature is exactly 0x + 130 hex (r||s||v, 65 bytes). Anything
// else (e.g. an EIP-1271 contract signature) can't seed the BIP-32 tree meaningfully.
function assertEoaSignature(sig) {
  if (typeof sig !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(sig)) {
    const n = typeof sig === 'string' && sig.startsWith('0x') ? (sig.length - 2) / 2 : '?';
    throw new Error(
      `Wallet returned a ${n}-byte signature, not a standard 65-byte EOA signature. ${EOA_HINT}`,
    );
  }
}

// Centralized error → status. 4001 (EIP-1193 user-rejected) gets flow-specific
// guidance; everything else surfaces the raw message. Full error always logged.
function reportError(err) {
  console.error('[sig-taproot] error:', err);
  if (err && err.code === 4001) {
    setStatus('Signature request was rejected in your wallet. Click to retry.', 'error');
    return;
  }
  setStatus(err?.message || String(err), 'error');
}

// --- Core flow -------------------------------------------------------------

let state = null; // { account, btcAddress, verified }

async function connectAndDerive() {
  try {
    $('connect').disabled = true;
    const eth = requireProvider();
    console.info('[sig-taproot] provider:', describeProvider(eth));

    setStatus('Requesting account…');
    const accounts = await eth.request({ method: 'eth_requestAccounts' });
    if (!accounts || !accounts.length) throw new Error('No account authorized.');
    const account = getAddress(accounts[0]); // checksummed for display

    const typedData = buildTypedData(account);
    // Belt-and-suspenders: this is the digest the wallet signs (viem, independent
    // of the wallet's own EIP-712 encoding). Logged for cross-checking only.
    console.info('[sig-taproot] EIP-712 digest:', hashTypedData(typedData));

    // One signature to derive. Determinism is confirmed by a SEPARATE user gesture
    // ("Sign again") rather than a second automatic prompt — signing twice back-to-back
    // makes some wallets (e.g. Ambire, which reuses one request window) drop the second
    // request. `assertEoaSignature` still rejects non-EOA (EIP-1271) signatures here.
    setStatus('Approve the signature in your wallet…');
    const sig = await signOnce(eth, account, typedData, 'derive');
    console.info('[sig-taproot] signature bytes:', (sig.length - 2) / 2);
    assertEoaSignature(sig);

    const wallet = deriveTaproot(sig, account);
    state = { account, btcAddress: wallet.btcAddress, verified: false, mnemonic: wallet.mnemonic };
    render(account, wallet);
    setStatus(
      'Derived ✓  Click “Sign again to verify” to confirm your wallet reproduces the same ' +
        'address (the determinism check).',
      'ok',
    );
  } catch (err) {
    reportError(err);
  } finally {
    $('connect').disabled = false;
  }
}

function render(account, wallet) {
  $('evmAccount').textContent = account;
  $('btcAddress').textContent = wallet.btcAddress;
  $('derivPath').textContent = wallet.path;
  $('xonly').textContent = wallet.xonlyHex;
  $('mnemonic').textContent = wallet.mnemonic;
  // Reset the mnemonic to hidden each derivation.
  $('mnemonic').classList.add('hidden');
  $('revealMnemonic').textContent = 'Reveal mnemonic';
  $('determinism').textContent = '';
  $('determinism').className = '';
  $('result').classList.remove('hidden');
  $('signAgain').classList.remove('hidden');
  $('connect').textContent = 'Reconnect / re-derive';
  $('wallet').classList.remove('hidden');
  renderAddresses();
}

// Re-sign once and re-derive; assert the address matches — the live proof.
async function signAgain() {
  if (!state) return;
  try {
    $('signAgain').disabled = true;
    const eth = requireProvider();
    const account = getAddress((await eth.request({ method: 'eth_requestAccounts' }))[0]);
    if (account !== state.account) {
      setStatus(`Active account changed to ${account}. Reconnect to derive its wallet.`, 'error');
      return;
    }
    setStatus('Approve the signature to re-derive…');
    const sig = await signOnce(eth, account, buildTypedData(account), 'reverify');
    assertEoaSignature(sig);
    const again = deriveTaproot(sig, account);
    const ok = again.btcAddress === state.btcAddress;
    state.verified = ok;
    const el = $('determinism');
    el.textContent = ok
      ? `✓ Determinism verified — reproduced the same address: ${again.btcAddress}`
      : `✗ MISMATCH — got ${again.btcAddress}, expected ${state.btcAddress}. ` +
        `This signer is non-deterministic; do NOT use this wallet.`;
    el.className = ok ? 'ok' : 'error';
    setStatus(
      ok ? 'Determinism confirmed ✓' : 'Determinism check FAILED — non-deterministic signer.',
      ok ? 'ok' : 'error',
    );
  } catch (err) {
    reportError(err);
  } finally {
    $('signAgain').disabled = false;
  }
}

function toggleMnemonic() {
  const m = $('mnemonic');
  const hidden = m.classList.toggle('hidden');
  $('revealMnemonic').textContent = hidden ? 'Reveal mnemonic' : 'Hide mnemonic';
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const prev = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => (btn.textContent = prev), 1200);
  } catch {
    setStatus('Clipboard unavailable — copy manually.', 'error');
  }
}

// --- Wallet: indexed addresses, UTXOs, per-UTXO spend (mainnet) ------------

let addresses = []; // [{ index, address, xonlyHex, privateKey }]
let utxos = []; // [{ txid, vout, value: bigint, status, ownerIndex, ownerAddress }]
let feeRates = null; // { fastestFee, halfHourFee, hourFee, ... }
let selectedUtxo = null; // the UTXO chosen to spend
let builtSpend = null; // { txHex, txid, fee, outputAmount, vsize } from buildSpend

const fmtSats = (n) => `${Number(n).toLocaleString('en-US')} sat`;
const fmtBtc = (n) => `${(Number(n) / 1e8).toFixed(8)} BTC`;
const short = (s, n = 8) => `${s.slice(0, n)}…${s.slice(-n)}`;

// Derive and list the first N receive addresses (indices 0..N-1).
function renderAddresses() {
  const count = Math.max(1, Math.min(50, Number($('addrCount').value) || 5));
  addresses = [];
  for (let i = 0; i < count; i++) {
    const a = taprootAddressAt(state.mnemonic, i);
    addresses.push({ index: i, address: a.btcAddress, xonlyHex: a.xonlyHex, privateKey: a.privateKey });
  }
  const list = $('addressList');
  list.innerHTML = '';
  for (const a of addresses) {
    const row = document.createElement('div');
    row.className = 'wl-row';
    row.innerHTML = `<span class="wl-idx">#${a.index}</span><code class="wl-addr">${a.address}</code>`;
    const copy = document.createElement('button');
    copy.className = 'ghost';
    copy.textContent = 'Copy';
    copy.addEventListener('click', () => copyText(a.address, copy));
    row.appendChild(copy);
    list.appendChild(row);
  }
}

// Query mempool.space for UTXOs across the listed addresses; also refresh fees.
async function scanUtxos() {
  try {
    $('scanUtxos').disabled = true;
    $('utxoStatus').textContent = 'Scanning addresses…';
    $('utxoStatus').className = 'status status--info';
    feeRates = await getFeeRates().catch(() => feeRates);
    const found = [];
    for (const a of addresses) {
      for (const u of await getUtxos(a.address)) {
        found.push({
          txid: u.txid,
          vout: u.vout,
          value: BigInt(u.value),
          status: u.status,
          ownerIndex: a.index,
          ownerAddress: a.address,
        });
      }
    }
    utxos = found;
    renderUtxos();
    const total = utxos.reduce((s, u) => s + u.value, 0n);
    $('utxoStatus').textContent = utxos.length
      ? `${utxos.length} UTXO(s) — total ${fmtBtc(total)} (${fmtSats(total)})`
      : 'No UTXOs. Send funds to an address above, wait for the tx, then Scan again.';
    $('utxoStatus').className = utxos.length ? 'status status--ok' : 'status status--info';
  } catch (err) {
    reportError(err);
    $('utxoStatus').textContent = err?.message || String(err);
    $('utxoStatus').className = 'status status--error';
  } finally {
    $('scanUtxos').disabled = false;
  }
}

function renderUtxos() {
  const list = $('utxoList');
  list.innerHTML = '';
  utxos.forEach((u, i) => {
    const row = document.createElement('div');
    row.className = 'wl-row';
    const conf = u.status?.confirmed ? 'confirmed' : 'pending';
    row.innerHTML =
      `<span class="wl-idx">#${u.ownerIndex}</span>` +
      `<code class="wl-addr">${short(u.txid)}:${u.vout}</code>` +
      `<span>${fmtBtc(u.value)}</span><span class="wl-conf">${conf}</span>`;
    const spend = document.createElement('button');
    spend.textContent = 'Spend';
    spend.setAttribute('data-utxo', String(i));
    spend.addEventListener('click', () => openSpend(i));
    row.appendChild(spend);
    list.appendChild(row);
  });
}

// Fill the fee-rate <select> with the three mempool presets (no arbitrary rate).
function feeRateOptions() {
  const sel = $('feeRate');
  sel.innerHTML = '';
  const presets = feeRates
    ? [
        ['fastestFee', 'Fast (~10 min)'],
        ['halfHourFee', 'Normal (~30 min)'],
        ['hourFee', 'Slow (~1 hr)'],
      ].filter(([k]) => feeRates[k] != null)
    : [];
  for (const [k, label] of presets) {
    const o = document.createElement('option');
    o.value = String(feeRates[k]);
    o.textContent = `${label} — ${feeRates[k]} sat/vB`;
    if (k === 'halfHourFee') o.selected = true;
    sel.appendChild(o);
  }
  if (!presets.length) {
    const o = document.createElement('option');
    o.value = '';
    o.textContent = 'fee rates unavailable — Scan first';
    sel.appendChild(o);
  }
}

function openSpend(i) {
  selectedUtxo = utxos[i];
  builtSpend = null;
  feeRateOptions();
  $('spendUtxo').textContent =
    `#${selectedUtxo.ownerIndex}  ${short(selectedUtxo.txid)}:${selectedUtxo.vout}  ${fmtBtc(selectedUtxo.value)}`;
  $('destAddress').value = '';
  $('spendPreview').textContent = '';
  $('spendPreview').className = '';
  $('confirmSpend').classList.add('hidden');
  $('spendResult').textContent = '';
  $('spendResult').className = '';
  $('spendPanel').classList.remove('hidden');
  $('spendPanel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Build + sign (but don't broadcast) so the user reviews exact amounts first.
function previewSpend() {
  try {
    if (!selectedUtxo) return;
    const destination = $('destAddress').value.trim();
    const feeRate = Number($('feeRate').value);
    const owner = addresses.find((a) => a.index === selectedUtxo.ownerIndex);
    builtSpend = buildSpend({
      utxo: { txid: selectedUtxo.txid, vout: selectedUtxo.vout, value: selectedUtxo.value },
      owner,
      destination,
      feeRate,
    });
    $('spendPreview').innerHTML =
      `Send <b>${fmtBtc(builtSpend.outputAmount)}</b> → <code>${destination}</code><br>` +
      `from ${fmtBtc(selectedUtxo.value)}, fee <b>${fmtSats(builtSpend.fee)}</b> ` +
      `@ ${feeRate} sat/vB (${builtSpend.vsize} vB)<br>` +
      `txid (once broadcast): <code>${builtSpend.txid}</code>`;
    $('spendPreview').className = 'ok';
    $('confirmSpend').classList.remove('hidden');
  } catch (err) {
    builtSpend = null;
    $('confirmSpend').classList.add('hidden');
    $('spendPreview').textContent = err?.message || String(err);
    $('spendPreview').className = 'error';
  }
}

async function confirmSpend() {
  if (!builtSpend || !selectedUtxo) return;
  const destination = $('destAddress').value.trim();
  const ok = window.confirm(
    'BROADCAST a REAL mainnet transaction?\n\n' +
      `Send ${fmtBtc(builtSpend.outputAmount)} to:\n${destination}\n\n` +
      `Fee: ${fmtSats(builtSpend.fee)}. This is irreversible.`,
  );
  if (!ok) return;
  try {
    $('confirmSpend').disabled = true;
    $('spendResult').textContent = 'Broadcasting…';
    $('spendResult').className = 'status status--info';
    const txid = await broadcast(builtSpend.txHex);
    $('spendResult').innerHTML =
      `✓ Broadcast. txid: <a href="${txUrl(txid)}" target="_blank" rel="noopener">${txid}</a>`;
    $('spendResult').className = 'ok';
    $('confirmSpend').classList.add('hidden');
  } catch (err) {
    $('spendResult').textContent = err?.message || String(err);
    $('spendResult').className = 'error';
  } finally {
    $('confirmSpend').disabled = false;
  }
}

function resetWallet() {
  state = null;
  addresses = [];
  utxos = [];
  selectedUtxo = null;
  builtSpend = null;
  $('result').classList.add('hidden');
  $('signAgain').classList.add('hidden');
  $('wallet').classList.add('hidden');
  $('spendPanel').classList.add('hidden');
}

// --- Wire up ---------------------------------------------------------------

$('connect').addEventListener('click', connectAndDerive);
$('signAgain').addEventListener('click', signAgain);
$('revealMnemonic').addEventListener('click', toggleMnemonic);
$('copyAddress').addEventListener('click', (e) => copyText($('btcAddress').textContent, e.target));
$('copyMnemonic').addEventListener('click', (e) => copyText($('mnemonic').textContent, e.target));
$('refreshAddresses').addEventListener('click', renderAddresses);
$('scanUtxos').addEventListener('click', scanUtxos);
$('previewSpend').addEventListener('click', previewSpend);
$('confirmSpend').addEventListener('click', confirmSpend);

// Re-derivation is required if the user switches accounts in the wallet.
globalThis.ethereum?.on?.('accountsChanged', () => {
  resetWallet();
  setStatus('Account changed — reconnect to derive.', 'info');
});
