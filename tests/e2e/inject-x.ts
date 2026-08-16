import { spawn, type ChildProcess } from 'node:child_process';
import { accessSync, constants as fsConstants } from 'node:fs';
import { resolve } from 'node:path';

import { chromium } from 'playwright';

import { injectWithPalladin as injectPlaywright } from '../../packages/playwright-mcp/src/server.js';
import { extensionCurrentUrl, runExtensionInject } from '../../src/browser-host/client.js';

const X_FORM = {
  version: 1 as const,
  steps: [
    {
      fields: [{
        entryFieldId: 'credential.username',
        // X renders a non-form responsive duplicate; the actual login
        // controls live in the form. Scoping the contract to that form keeps
        // discovery deterministic instead of weakening the ambiguity guard.
        selector: 'input[name="username_or_email"] >> nth=0',
        control: 'username' as const,
      }],
      // X renders the real transition control outside the responsive form;
      // pressing Enter can be swallowed by the onboarding shell. The visible
      // X renders the primary submit only after the identifier is entered;
      // the hidden responsive copy is filtered by the trusted provider.
      submit: { action: 'click' as const, selector: 'button[type="submit"]' },
      // X keeps an inert opacity-zero password copy on the identifier screen;
      // wait for an actionable control before filling the second step.
      waitFor: { selector: 'input[name="password"]:not([style*="opacity: 0"])', timeoutMs: 45_000 },
    },
    {
      fields: [{
        entryFieldId: 'credential.password',
        selector: 'input[name="password"][type="password"]',
        control: 'password' as const,
      }],
      submit: { action: 'press-enter' as const, selector: 'input[name="password"][type="password"]' },
    },
  ],
};

const X_LOGIN_URL = 'https://x.com/i/flow/login';
const LOGIN_TIMEOUT_MS = 45_000;

interface Arguments {
  provider: 'extension' | 'playwright';
  vaultId: string;
  entryId: string;
}

const input = parseArguments(process.argv.slice(2));
const runtime = resolveRequiredPath(process.env.PALLADIN_E2E_RUNTIME, 'PALLADIN_E2E_RUNTIME');
if (!process.env.PALLADIN_AGENT_PROFILE?.trim()) {
  throw new Error('PALLADIN_AGENT_PROFILE is required');
}

const spawnRuntime = (args: readonly string[]): ChildProcess => spawn(runtime, args, {
  shell: false,
  stdio: ['pipe', 'pipe', 'inherit'],
  windowsHide: true,
  env: process.env,
});

switch (input.provider) {
  case 'playwright':
    await testPlaywright(input);
    break;
  case 'extension':
    await testExtension(input);
    break;
}

async function testPlaywright(args: Arguments): Promise<void> {
  const browser = await chromium.launch({
    channel: process.env.PALLADIN_PLAYWRIGHT_CHANNEL ?? 'chrome',
    headless: process.env.PALLADIN_PLAYWRIGHT_HEADLESS === '1',
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  let completed = false;
  try {
    await page.goto(X_LOGIN_URL, { waitUntil: 'domcontentloaded' });
    await page.bringToFront();
    const refuseCookies = page.getByRole('button', { name: /Refuse non-essential cookies/i });
    if (await refuseCookies.count() > 0) await refuseCookies.first().click();
    // Discovery must finish before the CLI is invoked. X renders its login
    // surface asynchronously and briefly exposes only the onboarding shell.
    await page.locator('form input[name="username_or_email"]').first().waitFor({
      state: 'visible',
      timeout: 45_000,
    });
    const result = await injectPlaywright(page, request(args), spawnRuntime);
    if (result.isError === true) await printValueFreeFormShape(page);
    assertInjected(result, 'playwright');
    await page.waitForURL((url) => isXAuthenticatedUrl(url), { timeout: LOGIN_TIMEOUT_MS });
    completed = true;
    process.stdout.write('E2E Inject succeeded through Playwright.\n');
} finally {
  if (completed) {
    process.stdout.write(
      'Authenticated Playwright browser left open for further agent actions. Close it or press Ctrl+C to finish.\n',
    );
    await waitForOperatorClose(context);
  } else if (process.env.PALLADIN_E2E_KEEP_OPEN_ON_FAILURE === '1') {
    process.stderr.write('Playwright browser left open for value-free failure inspection.\n');
    await waitForOperatorClose(context);
  }
  await context.close().catch(() => undefined);
  await browser.close().catch(() => undefined);
}
}

async function printValueFreeFormShape(page: import('playwright').Page): Promise<void> {
  const shape = await page.locator('input,button,[role="button"]').evaluateAll((elements) => (
    elements.slice(0, 40).map((element) => ({
      tag: element.tagName.toLowerCase(),
      type: element.getAttribute('type'),
      name: element.getAttribute('name'),
      autocomplete: element.getAttribute('autocomplete'),
      role: element.getAttribute('role'),
      ariaLabel: element.getAttribute('aria-label'),
      text: (element.textContent ?? '').trim().slice(0, 80),
      visible: element.getBoundingClientRect().width > 0 && element.getBoundingClientRect().height > 0,
    }))
  ));
  const url = new URL(page.url());
  process.stderr.write(`Value-free X form shape: ${JSON.stringify({ path: url.pathname, shape })}\n`);
}

async function testExtension(args: Arguments): Promise<void> {
  const exitCode = await runExtensionInject([
    '--id', process.env.PALLADIN_AGENT_PROFILE ?? '',
    'inject', args.vaultId, args.entryId,
    '--provider', 'extension',
    '--reason', 'E2E login verification through the existing Palladin extension',
    '--wait', '5m',
  ], async (runtimeArgs) => spawnRuntime(runtimeArgs), X_FORM);
  if (exitCode !== 0) throw new Error('Extension Inject did not complete');
  await waitForAuthenticatedExtension();
  process.stdout.write('E2E Inject succeeded through the existing extension.\n');
}

function request(args: Arguments): Arguments & { reason: string; wait: string; form: typeof X_FORM } {
  return {
    ...args,
    reason: `E2E login verification through ${args.provider}`,
    wait: '5m',
    form: X_FORM,
  };
}

function assertInjected(
  result: { isError?: boolean; content: Array<{ type: string; text?: string }> },
  provider: string,
): void {
  if (result.isError === true
    || result.content.some((item) => item.text?.includes(`"provider":"${provider}"`) !== true)) {
    const diagnostic = result.content
      .filter((item) => item.type === 'text' && typeof item.text === 'string')
      .map((item) => item.text)
      .join('; ');
    throw new Error(`Inject failed through ${provider}: ${diagnostic || 'no diagnostic'}`);
  }
}

async function waitForAuthenticatedExtension(): Promise<void> {
  const deadline = Date.now() + LOGIN_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const currentUrl = await extensionCurrentUrl();
    if (currentUrl !== null && isXAuthenticatedUrl(new URL(currentUrl))) return;
    await new Promise((resolveWait) => setTimeout(resolveWait, 500));
  }
  throw new Error('The existing extension did not reach an authenticated X page');
}

function isXAuthenticatedUrl(url: URL): boolean {
  return (url.hostname === 'x.com' || url.hostname.endsWith('.x.com'))
    && !url.pathname.startsWith('/i/flow/login');
}

function parseArguments(values: string[]): Arguments {
  const provider = option(values, '--provider');
  const vaultId = option(values, '--vault');
  const entryId = option(values, '--entry');
  if (!['extension', 'playwright'].includes(provider)) {
    throw new Error('invalid --provider');
  }
  if (vaultId.length === 0 || entryId.length === 0) throw new Error('vault and entry are required');
  return { provider: provider as Arguments['provider'], vaultId, entryId };
}

function option(values: string[], name: string): string {
  const index = values.indexOf(name);
  const value = index === -1 ? undefined : values[index + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${name} is required`);
  return value;
}

function resolveRequiredPath(value: string | undefined, name: string): string {
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  const path = resolve(value);
  accessSync(path, fsConstants.R_OK);
  return path;
}

async function waitForOperatorClose(contextToObserve: typeof context): Promise<void> {
  if (contextToObserve.pages().length === 0) return;
  await new Promise<void>((resolveWait) => {
    const finish = (): void => {
      process.off('SIGINT', finish);
      process.off('SIGTERM', finish);
      resolveWait();
    };
    contextToObserve.once('close', finish);
    process.once('SIGINT', finish);
    process.once('SIGTERM', finish);
  });
}
