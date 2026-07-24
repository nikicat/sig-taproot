// Shared e2e helper: inject an EIP-1193 provider that signs with a REAL viem key,
// so the page derives a genuine wallet (headless, deterministic).
import { type Page } from '@playwright/test';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256 } from 'viem';
import { deriveMnemonic, CONTEXT } from '../../src/derive.js';

// anvil account 0 (public, well-known test key).
export const TEST_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
export const account = privateKeyToAccount(TEST_KEY);

// The exact EIP-712 payload app.js builds (kept in sync with buildTypedData there).
function typedData(addr: string) {
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
    primaryType: 'Derivation' as const,
    message: { action: 'Derive Bitcoin Taproot Wallet', context: CONTEXT, addressHash: keccak256(addr as `0x${string}`) },
  };
}

async function signPayload() {
  const td = typedData(account.address);
  const { EIP712Domain, ...types } = td.types;
  return account.signTypedData({ domain: td.domain, types, primaryType: td.primaryType, message: td.message });
}

/** The mnemonic the page will derive for this injected key (to precompute addresses). */
export async function walletMnemonic() {
  return deriveMnemonic(await signPayload(), account.address);
}

export async function installProvider(page: Page) {
  await page.exposeFunction('__e2eSignTypedData', async (_from: string, json: string) => {
    const td = JSON.parse(json);
    const { EIP712Domain, ...types } = td.types;
    return account.signTypedData({ domain: td.domain, types, primaryType: td.primaryType, message: td.message });
  });
  await page.addInitScript((address: string) => {
    (window as any).ethereum = {
      isMetaMask: true,
      on() {},
      removeListener() {},
      async request({ method, params }: { method: string; params?: any[] }) {
        if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [address];
        if (method === 'eth_chainId') return '0x1';
        if (method === 'eth_signTypedData_v4') return (window as any).__e2eSignTypedData(params![0], params![1]);
        throw Object.assign(new Error(`unhandled ${method}`), { code: 4200 });
      },
    };
  }, account.address);
}
