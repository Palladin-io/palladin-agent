import { spawn, type ChildProcess } from 'node:child_process';
import { accessSync, constants as fsConstants } from 'node:fs';
import { resolve } from 'node:path';

import { chromium, type Frame, type Locator, type Page } from 'playwright';

import type { InjectFormDefinition } from '../../src/inject-contract.js';
import { injectWithPalladin } from '../../packages/playwright-mcp/src/server.js';

const LOGIN_URL = 'https://allegro.pl/login/form';
const WAIT_MS = Number.parseInt(process.env.PALLADIN_E2E_WAIT_MS ?? `${5 * 60_000}`, 10);

const vaultId = option(process.argv.slice(2), '--vault');
const entryId = option(process.argv.slice(2), '--entry');
const runtime = resolveRequiredPath(process.env.PALLADIN_E2E_RUNTIME, 'PALLADIN_E2E_RUNTIME');
if (!process.env.PALLADIN_AGENT_PROFILE?.trim()) throw new Error('PALLADIN_AGENT_PROFILE is required');

const spawnRuntime = (args: readonly string[]): ChildProcess => spawn(runtime, args, {
  shell: false,
  stdio: ['pipe', 'pipe', 'inherit'],
  windowsHide: true,
  env: process.env,
});

const browser = await chromium.launch({ channel: 'chrome', headless: false });
const context = await browser.newContext({ locale: 'pl-PL' });
const page = await context.newPage();
let completed = false;
try {
  await page.goto(LOGIN_URL, { waitUntil: 'domcontentloaded' });
  await dismissCookieBanner(page);
  process.stderr.write('Waiting for the public Allegro login form; complete any visible CAPTCHA manually.\n');
  const form = await recognizePublicForm(page, WAIT_MS);
  const result = await injectWithPalladin(page, {
    vaultId,
    entryId,
    reason: 'E2E login verification through Playwright on Allegro',
    wait: '5m',
    form,
  }, spawnRuntime);
  if (result.isError === true) {
    throw new Error(result.content.map((item) => item.type === 'text' ? item.text : '').join('; '));
  }
  await page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: 60_000 });
  completed = true;
  process.stdout.write('E2E Inject succeeded through Playwright on Allegro.\n');
} finally {
  if (completed) {
    process.stdout.write(
      'Authenticated Playwright browser left open for further agent actions. Close it or press Ctrl+C to finish.\n',
    );
    await waitForOperatorClose(context);
  } else if (process.env.PALLADIN_E2E_KEEP_OPEN_ON_FAILURE !== '0') {
    process.stderr.write('Playwright browser left open for value-free failure inspection.\n');
    await waitForOperatorClose(context);
  }
  await context.close().catch(() => undefined);
  await browser.close().catch(() => undefined);
}

async function recognizePublicForm(page: Page, timeoutMs: number): Promise<InjectFormDefinition> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await dismissCookieBanner(page);
    await attemptHumanVerificationCheckbox(page);
    const username = await uniqueUsable(page.locator([
      'input[autocomplete~="username"]',
      'input[type="email"]',
      'input[name="login"]',
      'input[name*="email" i]',
    ].join(',')));
    if (username !== null) {
      const usernameSelector = await stableSelector(username);
      const password = await uniqueUsable(page.locator('input[type="password"]'));
      const passwordSelector = password === null
        ? 'input[type="password"]'
        : await stableSelector(password);
      if (password !== null) {
        return {
          version: 1,
          steps: [{
            fields: [
              { entryFieldId: 'credential.username', selector: usernameSelector, control: 'username' },
              { entryFieldId: 'credential.password', selector: passwordSelector, control: 'password' },
            ],
            submit: { action: 'press-enter', selector: passwordSelector },
          }],
        };
      }
      return {
        version: 1,
        steps: [
          {
            fields: [{ entryFieldId: 'credential.username', selector: usernameSelector, control: 'username' }],
            submit: { action: 'press-enter', selector: usernameSelector },
            waitFor: { selector: passwordSelector, timeoutMs: 45_000 },
          },
          {
            fields: [{ entryFieldId: 'credential.password', selector: passwordSelector, control: 'password' }],
            submit: { action: 'press-enter', selector: passwordSelector },
          },
        ],
      };
    }
    await page.waitForTimeout(250);
  }
  const publicInputCount = await page.locator('input:visible').count();
  const publicButtonCount = await page.locator('button:visible').count();
  throw new Error(
    `Allegro did not expose a login form before the timeout (path=${new URL(page.url()).pathname}, inputs=${publicInputCount}, buttons=${publicButtonCount})`,
  );
}

async function attemptHumanVerificationCheckbox(page: Page): Promise<void> {
  const scopes: Array<Page | Frame> = [page, ...page.frames()];
  const selectors = [
    '[role="checkbox"][aria-label*="human" i]',
    '[role="checkbox"][aria-label*="robot" i]',
    '.h-captcha [role="checkbox"]',
    '#recaptcha-anchor',
  ].join(',');
  for (const scope of scopes) {
    try {
      for (const candidate of await scope.locator(selectors).all()) {
        if (await candidate.isVisible() && await candidate.isEnabled()) {
          await candidate.click({ timeout: 2_000 }).catch(() => undefined);
          process.stderr.write('Attempted the visible human-verification checkbox; waiting for the public login form.\n');
          return;
        }
      }
    } catch {
      // CAPTCHA providers replace frames while navigating; inspect the next live scope.
    }
  }
}

async function dismissCookieBanner(page: Page): Promise<void> {
  const selector = [
    '#onetrust-accept-btn-handler',
    '[id*="cookie" i][id*="accept" i]',
    '[data-role="accept-cookies"]',
    '[data-testid*="accept-cookies" i]',
    'button:has-text("Zezwól na wszystkie")',
    'button:has-text("Zgadzam się")',
    '[data-role="accept-cookies"]',
    'button:has-text("Akceptuję")',
    'button:has-text("Akceptuj wszystkie")',
    'button:has-text("Akceptuj")',
    'button:has-text("Potwierdź wybór")',
    'button:has-text("Accept all")',
    'button:has-text("Allow all")',
  ].join(',');
  const scopes: Array<Page | Frame> = [page, ...page.frames()];
  for (const scope of scopes) {
    try {
      for (const candidate of await scope.locator(selector).all()) {
        if (await candidate.isVisible() && await candidate.isEnabled()) {
          await candidate.click({ timeout: 2_000 }).catch(() => undefined);
          return;
        }
      }
    } catch {
      // Consent providers may replace an iframe while the banner closes.
    }
  }
}

async function uniqueUsable(locator: Locator): Promise<Locator | null> {
  const usable: Locator[] = [];
  for (const candidate of await locator.all()) {
    if (await candidate.isVisible() && await candidate.isEnabled()) usable.push(candidate);
  }
  return usable.length === 1 ? usable[0]! : null;
}

async function stableSelector(locator: Locator): Promise<string> {
  return await locator.evaluate((element) => {
    if (!(element instanceof HTMLInputElement)) throw new Error('login control is not an input');
    if (element.id.length > 0) return `#${CSS.escape(element.id)}`;
    if (element.name.length > 0) return `input[name="${CSS.escape(element.name)}"]`;
    if (element.autocomplete.length > 0) {
      const token = element.autocomplete.split(/\s+/u)[0] ?? '';
      if (token.length > 0) return `input[autocomplete~="${CSS.escape(token)}"]`;
    }
    return `input[type="${CSS.escape(element.type)}"]`;
  });
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
