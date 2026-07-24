# sig-taproot — Bitcoin taproot wallet derived from an EVM wallet signature

**Goal:** a single-file local demo page: connect MetaMask (any EOA web3 wallet) →
deterministic signature → BIP-39 mnemonic → BIP-86 taproot address (`bc1p…`), all
client-side. Verify determinism across reloads/browsers, cross-check the mnemonic in
Sparrow, then (stretch) sign and broadcast a real signet spend with Schnorr from the page.

Status: **planning — nothing built yet.** This file is the resume point.

## Why this works (context from research session 2026-07-24)

- ECDSA with RFC 6979 deterministic nonces (all major Ethereum wallets): same key +
  same message → byte-identical signature. The signature is a PRF of the private key —
  reproducible by the owner, unpredictable to everyone else.
- Bitcoin and Ethereum both use secp256k1, so a BIP-32 root seeded from signature
  entropy yields standards-compliant taproot keys directly.
- Taproot key-path spends need BIP-340 Schnorr — MetaMask cannot produce those. The
  EVM wallet only *bootstraps* the key; the page holds the derived key and signs BTC
  transactions itself.

### Prior art (verified live 2026-07-24)

| Who | What | Notes |
|---|---|---|
| [Privacy Pools walletSeed.ts](https://github.com/0xbow-io/privacy-pools-website/blob/main/src/utils/walletSeed.ts) | sig → 24-word mnemonic (EVM side) | The hardened design: EIP-712 + addressHash commit, sign-twice determinism check ([Welcome.tsx](https://github.com/0xbow-io/privacy-pools-website/blob/main/src/containers/Welcome.tsx)), HKDF(ikm=r, salt=addr, info=appId) |
| [generative.xyz metamask-for-bitcoin](https://github.com/generative-xyz/metamask-for-bitcoin/blob/main/metamask.for.bitcoin.ts) | sig → taproot wallet, in production since 2023 | The simple version: `personal_sign` fixed msg → `keccak256(sig)` → `bip32.fromSeed` → `m/86'/0'/0'/0/0` → p2tr. No mnemonic (unrecoverable outside their app), no determinism check, no HKDF |
| [btcsnap](https://github.com/KeystoneHQ/btcsnap) | MetaMask Snap, `snap_getBip32Entropy` | The "proper" MetaMask-only alternative — derives from the actual seed, no signature dance |
| Ordswap (dead, both ordswap.io and recovery domain) | same pattern | Cautionary tale: platform-derived wallet without mnemonic export dies with the platform |

## Derivation spec (decided)

Improvements over generative.xyz, borrowed from Privacy Pools:

1. **EIP-712 typed data** (not `personal_sign`): domain `{name: 'sig-taproot', version: '1'}`,
   message `{action: 'Derive Bitcoin Taproot Wallet', context: 'sig-taproot/wallet-seed:v1',
   addressHash: keccak256(address)}`. Readable in the wallet prompt; unique context string
   is the phishing defense (any dapp can replay the same payload — the user must recognize it).
2. **Sign twice, compare bytes.** Abort with a clear error if they differ (MPC/smart-account
   wallets randomize; ERC-4337/1271 signers have no canonical signature). EOA-only.
3. **Entropy:** `HKDF-SHA256(ikm = full 65-byte signature, salt = addressBytes,
   info = 'sig-taproot/wallet-seed:v1', len = 32)`. Full sig through HKDF (scheme-agnostic)
   rather than slicing out `r` like Privacy Pools does.
4. **BIP-39, not raw `bip32.fromSeed`:** 32 bytes → 24-word English mnemonic → seed →
   BIP-32 root → **BIP-86** path `m/86'/0'/0'/0/0` → x-only pubkey → P2TR (bech32m).
   The mnemonic is the escape hatch: importable into Sparrow/Xverse, survives the app
   and survives the wallet changing signing behavior.
5. **BTC signing in-page** with `@scure/btc-signer` (BIP-340 Schnorr, taproot PSBT support).

## Implementation stages

1. **Scaffold.** New git repo here. `index.html` + one bundled `app.js`. Deps:
   `@noble/hashes` (hkdf, sha2), `@scure/bip39`, `@scure/bip32`, `@scure/btc-signer`,
   `@scure/base`; keccak256 + EIP-712 hashing via `viem` or hand-rolled with noble
   (viem is heavy for one hash — decide at build time). Bundle once with esbuild
   (`deno run -A npm:esbuild` fits the no-node preference); vendor the output, no CDN
   at runtime. Serve with `python -m http.server` or `deno file_server` — wallet
   extensions need http(s), not file://.
2. **Wallet connect + sign-twice.** `eth_requestAccounts`, `eth_signTypedData_v4` × 2,
   byte-compare, clear UX for the mismatch case.
3. **Derive + display.** Mnemonic (behind a reveal toggle), derivation path, x-only
   pubkey, `bc1p…` address. Show a "sign again" button that re-derives and asserts the
   same address — the determinism proof, live.
4. **Cross-check in Sparrow.** Import the mnemonic (script type P2TR, deriv `m/86'/0'/0'`),
   confirm address 0 matches the page. Also re-derive in a second browser/profile with
   the same MetaMask seed to prove wallet-independence of the derivation.
5. **Stretch — real spend.** Signet (or testnet4) faucet → coins to the derived address →
   build + Schnorr-sign a key-path spend PSBT in-page → broadcast via mempool.space
   signet API. Proves the full loop without mainnet risk.

## Verification checklist

- [ ] Same wallet + same page → identical address across reloads, browsers, days
- [ ] Different EVM account → different address; addressHash commit matches signer
- [ ] Mnemonic imported into Sparrow yields the same `bc1p…` at index 0
- [ ] Non-deterministic signer (e.g. a Privy embedded wallet, if handy) is rejected by the sign-twice check, not silently accepted
- [ ] Signet round-trip: receive + key-path spend confirmed

## Security notes (for the README later)

- Hot wallet: derived key lives in page JS — XSS = theft. Demo/petty-cash tier only.
- Phishing: signing this exact EIP-712 payload on a malicious site = handing over the
  wallet. Unique, readable message text is the only mitigation.
- Recoverability: mnemonic export is mandatory UX, not optional — see Ordswap.
- Hardware wallets behind MetaMask: Ledger/Trezor sign EIP-712 deterministically (fine),
  but verify with the sign-twice check anyway.
- Future: same pattern via WebAuthn PRF extension (passkey-derived, no extension wallet
  needed); Ed25519/BLS signers would make the determinism check unnecessary.

## Open decisions

- viem vs hand-rolled EIP-712 struct hashing (bundle size vs correctness risk — lean viem
  unless bundle is obnoxious; its `hashTypedData` is well-tested)
- signet vs testnet4 for the stretch stage (lean signet: reliable faucets, mempool.space support)
- dir currently not a git repo — `git init` at scaffold time
