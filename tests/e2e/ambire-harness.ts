/**
 * Minimal Ambire-driving harness for Playwright e2e — dapp-agnostic.
 *
 * Copied and trimmed from ../browser-web3-signer/tests/e2e-browser/demo-ambire
 * (lib.mts + config.mts): the reusable wallet-driving core only. Dropped from the
 * original: the anvil lifecycle, the browser-web3-signer CLI glue, demo-recording
 * cursor overlays, and the anvil Local-Network-Access chromium flags — sig-taproot
 * only signs a message, so none of that is needed.
 *
 * Requires a display (run headed under Xvfb in CI). Boots Ambire fully onboarded
 * from a baked chrome.storage.local fixture, then exposes helpers to approve the
 * extension's request-window popups by their data-testid.
 */
import { chromium, type BrowserContext, type Page } from '@playwright/test';
import { type ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const AMBIRE_VERSION = 'v6.15.3'; // keep in sync with setup-ambire.sh
export const BUILD_DIR = join(import.meta.dirname, 'ambire-build');
export const FIXTURE = join(import.meta.dirname, 'fixtures', 'ambire-storage.json.gz');

/** Keystore password for the baked demo wallet (test-only; protects a public anvil key). */
export const KEYSTORE_PASS = 'AmbireDemo2026!';

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const children: ChildProcess[] = [];
export function registerCleanup(extra?: () => void): void {
  process.on('exit', () => {
    extra?.();
    children.forEach((c) => c.kill());
  });
}

// Keep every window inside Xvfb and off any real desktop: on Wayland, Chromium
// auto-connects to the compositor via WAYLAND_DISPLAY (ignoring DISPLAY), and it
// reaches the desktop D-Bus for notifications. Scrub both; pin ozone to X11 below.
// Call once before bootAmbire(). Throws if there is no DISPLAY to attach to.
export function hardenDisplayEnv(): void {
  delete process.env.WAYLAND_DISPLAY;
  if (!process.env.DISPLAY) {
    throw new Error('no DISPLAY — run the ambire project under xvfb-run');
  }
  delete process.env.DBUS_SESSION_BUS_ADDRESS;
  process.env.XDG_RUNTIME_DIR = mkdtempSync(join(tmpdir(), 'ambire-runtime-'));
}

const CHROMIUM_ARGS = [
  `--disable-extensions-except=${BUILD_DIR}`,
  `--load-extension=${BUILD_DIR}`,
  '--no-sandbox',
  '--ozone-platform=x11',
  '--disable-gpu',
  '--disable-dev-shm-usage',
  '--window-size=1440,900',
];

function loadFixture(): Record<string, unknown> {
  return JSON.parse(gunzipSync(readFileSync(FIXTURE)).toString('utf8'));
}

const findSw = async (c: BrowserContext) => {
  for (let i = 0; i < 100; i++) {
    const sw = c.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://'));
    if (sw) return sw;
    await sleep(200);
  }
  throw new Error('no service worker');
};

/**
 * Boot Ambire fully onboarded: inject the fixture in a throwaway launch, close,
 * relaunch (the background races injection on first boot; chrome.runtime.reload()
 * breaks unpacked extensions), then unlock. Returns the context + a blank tab.
 */
export async function bootAmbire(): Promise<{ ctx: BrowserContext; extId: string; tab: Page }> {
  const storage = loadFixture();
  const profile = mkdtempSync(join(tmpdir(), 'ambire-e2e-'));
  const launch = () =>
    chromium.launchPersistentContext(profile, {
      channel: 'chromium',
      headless: false,
      viewport: null,
      args: CHROMIUM_ARGS,
    });

  let ctx = await launch();
  const sw = await findSw(ctx);
  const extId = sw.url().split('/')[2];
  await sleep(2000);
  await sw.evaluate(
    (params) => chrome.storage.local.set(params),
    { ...storage, isE2EStorageSet: true, isSetupComplete: 'true' },
  );
  await sleep(1000);
  await ctx.close();

  ctx = await launch();
  await findSw(ctx);

  const tab = await ctx.newPage();
  tab.setDefaultTimeout(60_000);
  let unlocked = false;
  for (let i = 0; i < 5 && !unlocked; i++) {
    await tab.goto(`chrome-extension://${extId}/tab.html#/`, { waitUntil: 'load' }).catch(() => {});
    unlocked = await tab
      .getByTestId('passphrase-field')
      .waitFor({ state: 'visible', timeout: 8000 })
      .then(() => true)
      .catch(() => false);
    if (!unlocked) await tab.waitForTimeout(2000);
  }
  if (!unlocked) throw new Error('unlock screen never appeared');
  await tab.getByTestId('passphrase-field').fill(KEYSTORE_PASS);
  await tab.getByTestId('button-unlock').click();
  await sleep(2500);

  return { ctx, extId, tab };
}

/** Ambire reuses one request window; 'page' events are unreliable under Xvfb. */
export const findRequestWindow = (ctx: BrowserContext): Page | undefined =>
  ctx.pages().find((p) => !p.isClosed() && p.url().includes('request-window'));

/** Poll for the request window and click the first matching approve button by testid. */
export async function approveRequestWindow(
  ctx: BrowserContext,
  ids: string[],
  { rounds = 12, pauseMs = 300 }: { rounds?: number; pauseMs?: number } = {},
): Promise<string | null> {
  for (let round = 0; round < rounds; round++) {
    await sleep(2000);
    const popup = findRequestWindow(ctx);
    if (!popup) continue;
    await popup.waitForLoadState('load').catch(() => {});
    await sleep(pauseMs);
    for (const tid of ids) {
      const b = popup.getByTestId(tid).first();
      if (await b.isVisible().catch(() => false)) {
        await b.click().catch(() => {});
        return tid;
      }
    }
  }
  return null;
}
