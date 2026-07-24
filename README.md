# sig-taproot

Derive a Bitcoin **taproot** wallet (`bc1p…`) deterministically from an **EVM wallet
signature**, entirely client-side. Connect MetaMask (or any EOA web3 wallet) → sign a fixed
EIP-712 message → the page turns that signature into a BIP-39 mnemonic and a BIP-86 taproot
address. The same wallet always reproduces the same Bitcoin address; nobody else can.

> **Scope:** this is the offline core (connect → derive → display → live determinism proof).
> Signing and broadcasting a real Bitcoin transaction is a deferred stretch goal — see
> [`PLAN.md`](./PLAN.md).

## How it works

ECDSA with RFC 6979 deterministic nonces (used by all major Ethereum wallets) makes a
signature a pure function of `(private key, message)` — reproducible by the owner,
unpredictable to everyone else. Bitcoin and Ethereum share the secp256k1 curve, so signature
entropy can seed a BIP-32 tree that yields standards-compliant taproot keys.

```
EIP-712 signature (65 bytes)
  ──HKDF-SHA256(salt = address, info = "sig-taproot/wallet-seed:v1")──▶ 32 bytes entropy
  ──BIP-39──▶ 24-word mnemonic ──▶ seed ──▶ BIP-32 root
  ──BIP-86 (m/86'/0'/0'/0/0)──▶ x-only pubkey ──▶ P2TR (bech32m) ──▶ bc1p…
```

Hardening over the naive `personal_sign` → `keccak256` approach:

- **EIP-712 typed data**, not `personal_sign`: readable in the wallet prompt; the unique
  `context` string is the phishing defense, and `addressHash = keccak256(address)` commits the
  signature to the signing account.
- **65-byte signature check + a separate re-sign to verify determinism.** A non-EOA
  (EIP-1271) signature is rejected on the spot; the "Sign again to verify" gesture re-derives
  and flags any non-deterministic signer before you rely on the wallet. (The two signatures
  are separate user actions, not two automatic prompts — some wallets, e.g. Ambire, reuse one
  request window and drop a second back-to-back request.)
- **BIP-39 mnemonic**, not a raw seed: the escape hatch — importable into Sparrow/Xverse,
  survives this app and survives the wallet changing its signing behavior.

## Run

```sh
pnpm install
pnpm bundle        # esbuild src/app.js -> dist/app.bundle.js (vendored, no runtime CDN)
pnpm serve         # python http.server on :8000  (wallets need http(s), not file://)
# open http://localhost:8000
```

Then: **Connect wallet & derive** → approve **one** signature → the `bc1p…` address,
derivation path, x-only pubkey, and (behind a reveal toggle) the 24-word mnemonic appear.
**Sign again to verify** re-signs and re-derives, proving the address is reproduced live.

### Requires a plain EOA (not a smart-account wallet)

The signature must be deterministic ECDSA (RFC 6979), which only an **externally-owned
account** produces. A **smart-contract account** (account abstraction) signs via EIP-1271 —
not a canonical 65-byte ECDSA sig — so it can't seed the wallet:

- **Safe, ZeroDev, Biconomy, Coinbase Smart Wallet, ERC-4337 accounts, and Ambire *smart
  accounts*** → won't work: the returned signature isn't 65 bytes, so the app rejects it with
  a clear "not an EOA signature" message rather than deriving an unrecoverable wallet.
- **Ambire is fine on a "Basic" (EOA) account** — verified end-to-end (see
  `../browser-web3-signer/tests/e2e-browser/demo-ambire`): it returns a 65-byte signature and
  reproduces the same address on the verify step.
- **Fix:** use MetaMask (or any EOA), or switch Ambire to a **Basic (EOA) account**.

Detection is by the *signature*, not the wallet brand: an on-chain `eth_getCode` probe was
tried and dropped — through some wallets (Ambire) it misreports a Basic/EOA account as a
contract. The 65-byte shape check is the reliable signal.

## Test

Three tiers, fastest first:

```sh
pnpm test              # unit: pinned derivation vector + determinism/salt/validation (node --test)
pnpm test:e2e          # e2e (headless): real page + an injected real-key EIP-1193 provider
bash tests/e2e/setup-ambire.sh          # once: download the pinned Ambire build (needs gh + unzip)
xvfb-run -a -s "-screen 0 1600x1000x24" \
  pnpm test:e2e:ambire # e2e: real page + the REAL Ambire extension (needs a display)
```

- **Unit** — `src/derive.js` is a pure, DOM-free pipeline imported by both the browser bundle
  and the test, so the derivation is machine-verifiable without a wallet. The pinned vector
  locks it against dependency drift.
- **`test:e2e` (Tier 1, gates CI)** — Playwright drives the built page in headless Chromium
  against an injected provider that signs with a real key (viem), producing a genuine 65-byte
  signature. Deterministic; pins the derived `bc1p…` and cross-checks it against a node
  derivation of the same signature.
- **`test:e2e:ambire` (Tier 2, non-gating in CI)** — the real Ambire extension via a small
  harness (`tests/e2e/ambire-harness.ts`, copied/trimmed from `../browser-web3-signer`). Boots
  a baked EOA fixture, approves the connect + sign popups, and asserts the one-sign-then-verify
  flow reproduces the same address. Skips unless a display and the extension build are present.
  See `.github/workflows/ci.yml` for how CI runs all three.

## Verify end-to-end

- **Determinism:** connect → note `bc1p…`; hit *Sign again* (unchanged); reload → same address.
- **Account binding:** a different EVM account yields a different address.
- **Sparrow cross-check:** import the 24-word mnemonic (script type Taproot/P2TR, derivation
  `m/86'/0'/0'`); receive address index 0 must equal the page's `bc1p…`.
- **Wallet-independence:** re-derive in a second browser/profile with the same MetaMask seed →
  same address.

## Security model

- **Hot wallet — demo / petty-cash tier only.** The derived key lives in page JavaScript;
  an XSS bug on this page equals theft.
- **Phishing.** Signing this exact EIP-712 payload on a malicious site hands over the wallet.
  The unique, human-readable message text is the only mitigation — read it before signing.
- **Recoverability is not automatic.** Determinism lets you *re-derive* on demand, but that
  breaks silently if your EOA ever signs the payload differently (a different/upgraded/hardware
  wallet) or if this app and its exact derivation constants disappear. **Back up the
  mnemonic** — it collapses those dependencies into one portable BIP-39 secret any BIP-86
  wallet can import. (Cautionary tale: Ordswap-style platform wallets with no mnemonic export
  died with the platform.)
- **Hardware wallets behind MetaMask** (Ledger/Trezor) sign EIP-712 deterministically, but the
  "Sign again to verify" step confirms it anyway.

## Layout

```
index.html            UI shell; loads dist/app.bundle.js as a module
src/derive.js         pure derivation pipeline (no DOM) — shared by app + test
src/app.js            wallet connect, sign-to-derive, verify, render
dist/app.bundle.js    esbuild output (vendored)
test/derive.test.js   pinned test-vector (node --test)
PLAN.md               research/design notes + the deferred signet-spend stage
```

## Stack

`@scure/btc-signer` · `@scure/bip39` · `@scure/bip32` · `@noble/hashes` (HKDF/SHA-256) ·
`viem` (EIP-712 / keccak256) — bundled once with `esbuild`, no runtime CDN.
