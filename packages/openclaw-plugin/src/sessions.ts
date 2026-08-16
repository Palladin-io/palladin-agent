import { randomBytes } from 'node:crypto';

import { injectExistingPlaywrightPage } from '@palladin/playwright-mcp/embedded';
import {
  chromium,
  type Browser,
  type BrowserContext,
  type Page,
} from 'playwright';

export interface BrowserOptions {
  channel?: string;
  headless?: boolean;
}

export function resolveBrowserLaunchOptions(
  options: BrowserOptions,
): NonNullable<Parameters<typeof chromium.launch>[0]> {
  return {
    ...(options.channel === undefined ? {} : { channel: options.channel }),
    headless: options.headless ?? false,
  };
}

const SAFE_PROVIDER_FAILURE_STAGES = new Set([
  'runtime-start',
  'runtime-handshake',
  'origin-verification',
  'form-fill',
  'runtime-result',
]);

export function parseSafeProviderFailure(
  text: string,
): { stage: string; code: string } | null {
  const match = /^The trusted Playwright Inject provider failed at ([a-z][a-z0-9-]{0,63}) \(([a-z][a-z0-9-]{0,63})\)\.$/.exec(text);
  if (match === null) return null;
  const [, stage, code] = match;
  if (stage === undefined || code === undefined || !SAFE_PROVIDER_FAILURE_STAGES.has(stage)) return null;
  return { stage, code };
}

interface BrowserParams {
  action: 'open' | 'navigate' | 'snapshot' | 'click' | 'press' | 'wait' | 'close';
  sessionId?: string;
  url?: string;
  selector?: string;
  key?: 'Enter' | 'Escape' | 'Tab';
  timeoutMs?: number;
}

interface InjectParams {
  sessionId: string;
  vaultId: string;
  entryId: string;
  reason?: string;
  wait?: string;
  noWait?: boolean;
  pollInterval?: string;
  form: {
    version: 1;
    steps: Array<{
      fields: Array<{
        entryFieldId: string;
        selector: string;
        control: 'username' | 'password' | 'text' | 'email' | 'tel' | 'otp';
      }>;
      submit: { action: 'click' | 'press-enter'; selector: string };
      waitFor?: { selector: string; timeoutMs?: number };
    }>;
  };
}

interface PalladinRuntimeOptions {
  profile?: string;
  packageRoot?: string;
  launcher?: string;
}

interface ManagedSession {
  context: BrowserContext;
  page: Page;
  injecting: boolean;
}

interface PublicControl {
  selector: string;
  tag: string;
  type?: string;
  name?: string;
  placeholder?: string;
  autocomplete?: string;
  ariaLabel?: string;
  text?: string;
  enabled: boolean;
}

export class PalladinBrowserSessions {
  private connectedBrowser: Browser | undefined;
  private readonly sessions = new Map<string, ManagedSession>();

  async browser(params: BrowserParams, options: BrowserOptions): Promise<Record<string, unknown>> {
    if (params.action === 'open') {
      const url = requiredHttpsUrl(params.url);
      const browser = await this.ensureBrowser(options);
      const context = await browser.newContext();
      const sessionId = randomBytes(32).toString('hex');
      const session: ManagedSession = { context, page: await context.newPage(), injecting: false };
      this.sessions.set(sessionId, session);
      await this.gotoStable(session, url);
      return await this.snapshot(sessionId, session.page);
    }

    const session = this.requireSession(params.sessionId);
    if (session.injecting) throw new Error('Palladin Inject is active for this browser session.');
    switch (params.action) {
      case 'navigate':
        await this.gotoStable(session, requiredHttpsUrl(params.url));
        return await this.snapshot(params.sessionId ?? '', session.page);
      case 'snapshot':
        return await this.snapshot(params.sessionId ?? '', session.page);
      case 'click': {
        const selector = requiredSelector(params.selector);
        const control = session.page.locator(selector);
        if (await control.count() !== 1 || !await control.isVisible() || !await control.isEnabled()) {
          throw new Error('Public browser control is missing or ambiguous.');
        }
        await control.click({ timeout: params.timeoutMs });
        return await this.snapshot(params.sessionId ?? '', session.page);
      }
      case 'press':
        await session.page.keyboard.press(params.key ?? 'Enter');
        return await this.snapshot(params.sessionId ?? '', session.page);
      case 'wait':
        await session.page.locator(requiredSelector(params.selector)).waitFor({
          state: 'visible',
          timeout: params.timeoutMs ?? 20_000,
        });
        return await this.snapshot(params.sessionId ?? '', session.page);
      case 'close':
        this.sessions.delete(params.sessionId ?? '');
        await session.context.close();
        return { status: 'closed' };
      default:
        throw new Error('Unsupported Palladin browser action.');
    }
  }

  /** Keep the opaque session identity stable when a redirect closes/replaces its Page. */
  private async gotoStable(session: ManagedSession, url: string): Promise<void> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        if (session.page.isClosed()) session.page = await session.context.newPage();
        await session.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 });
        if (!session.page.isClosed()) return;
      } catch (error) {
        lastError = error;
        if (!session.context.pages().length) {
          try { session.page = await session.context.newPage(); } catch { /* context is unrecoverable */ }
        }
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Browser navigation did not produce a stable page.');
  }

  async inject(params: InjectParams, runtime: PalladinRuntimeOptions): Promise<Record<string, unknown>> {
    const session = this.requireSession(params.sessionId);
    if (session.injecting) throw new Error('Palladin Inject is already active for this browser session.');
    session.injecting = true;
    try {
      const result = await injectExistingPlaywrightPage(session.page, {
        ...(runtime.profile === undefined ? {} : { profile: runtime.profile }),
        vaultId: params.vaultId,
        entryId: params.entryId,
        ...(params.reason === undefined ? {} : { reason: params.reason }),
        ...(params.wait === undefined ? {} : { wait: params.wait }),
        ...(params.noWait === undefined ? {} : { noWait: params.noWait }),
        ...(params.pollInterval === undefined ? {} : { pollInterval: params.pollInterval }),
        form: params.form,
      }, {
        packageRoot: runtime.packageRoot,
        launcher: runtime.launcher,
      });
      if (result.isError === true) {
        // The provider deliberately returns only a redacted stage/code diagnostic.
        // Preserve it for OpenClaw logs; replacing it with a generic message made
        // runtime, handshake, grant and form failures indistinguishable.
        const diagnostic = result.content
          .filter((item): item is { type: 'text'; text: string } => item.type === 'text')
          .map((item) => item.text)
          .find((text) => text.startsWith('The trusted Playwright Inject provider failed at '));
        const failure = diagnostic === undefined ? null : parseSafeProviderFailure(diagnostic);
        if (failure === null) throw new Error('The trusted Playwright provider failed.');
        return {
          status: 'failed',
          provider: 'playwright',
          sessionId: params.sessionId,
          stage: failure.stage,
          code: failure.code,
        };
      }
      return {
        status: 'injected',
        provider: 'playwright',
        sessionId: params.sessionId,
        currentUrl: session.page.url(),
      };
    } finally {
      session.injecting = false;
    }
  }

  private async ensureBrowser(options: BrowserOptions): Promise<Browser> {
    if (this.connectedBrowser !== undefined) return this.connectedBrowser;
    const browser = await chromium.launch(resolveBrowserLaunchOptions(options));
    this.connectedBrowser = browser;
    return browser;
  }

  private requireSession(sessionId: string | undefined): ManagedSession {
    if (sessionId === undefined) throw new Error('Palladin browser sessionId is required.');
    const session = this.sessions.get(sessionId);
    if (session === undefined || session.page.isClosed()) throw new Error('Palladin browser session is unavailable.');
    return session;
  }

  private async snapshot(sessionId: string, page: Page): Promise<Record<string, unknown>> {
    const controls = await snapshotPublicControls(page);
    return {
      status: 'ready',
      sessionId,
      currentUrl: page.url(),
      title: await page.title(),
      controls,
    };
  }
}

/** Returns value-free controls which can actually receive an agent action. */
export async function snapshotPublicControls(page: Page): Promise<PublicControl[]> {
  return await page.locator('input, textarea, select, button, a[href], [role="button"]').evaluateAll((elements) => (
    elements.flatMap((element): PublicControl[] => {
      const html = element as HTMLElement;
      const style = getComputedStyle(html);
      const rect = html.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(centerX, centerY);
      const formControl = html instanceof HTMLButtonElement || html instanceof HTMLInputElement
        || html instanceof HTMLSelectElement || html instanceof HTMLTextAreaElement;
      const readOnly = html instanceof HTMLInputElement || html instanceof HTMLTextAreaElement
        ? html.readOnly : false;
      const hiddenInput = html instanceof HTMLInputElement && html.type === 'hidden';
      if (style.display === 'none' || style.visibility === 'hidden'
        || Number.parseFloat(style.opacity || '1') <= 0.01 || style.pointerEvents === 'none'
        || rect.width <= 0 || rect.height <= 0
        || centerX < 0 || centerY < 0
        || centerX > document.documentElement.clientWidth
        || centerY > document.documentElement.clientHeight
        || html.hidden || html.getAttribute('aria-hidden') === 'true'
        || hiddenInput || readOnly || (formControl && html.disabled)
        || hit === null || !(hit === html || html.contains(hit) || hit.contains(html))) return [];
      const escapedId = html.id ? `#${CSS.escape(html.id)}` : undefined;
      const testId = html.getAttribute('data-testid') ?? undefined;
      const name = html.getAttribute('name') ?? undefined;
      const ariaLabel = html.getAttribute('aria-label') ?? undefined;
      const type = html.getAttribute('type') ?? undefined;
      const role = html.getAttribute('role') ?? undefined;
      const escapedTestId = testId === undefined ? undefined
        : `[data-testid="${CSS.escape(testId)}"]`;
      const escapedName = name === undefined ? undefined
        : `${html.tagName.toLowerCase()}[name="${CSS.escape(name)}"]`;
      const escapedAriaLabel = ariaLabel === undefined ? undefined
        : `${html.tagName.toLowerCase()}[aria-label="${CSS.escape(ariaLabel)}"]`;
      const escapedType = type === undefined ? undefined
        : `${html.tagName.toLowerCase()}[type="${CSS.escape(type)}"]`;
      const escapedRole = role === undefined ? undefined
        : `${html.tagName.toLowerCase()}[role="${CSS.escape(role)}"]`;
      const baseSelector = escapedId ?? escapedTestId ?? escapedName ?? escapedAriaLabel ?? escapedType ?? escapedRole;
      if (baseSelector === undefined) return [];
      const matches = [...document.querySelectorAll(baseSelector)];
      const ordinal = matches.indexOf(html);
      if (ordinal < 0) return [];
      const selector = matches.length === 1
        ? baseSelector
        : `:nth-match(${baseSelector}, ${ordinal + 1})`;
      const control: PublicControl = {
        selector,
        tag: html.tagName.toLowerCase(),
        enabled: true,
      };
      const placeholder = html.getAttribute('placeholder');
      const autocomplete = html.getAttribute('autocomplete');
      const text = html instanceof HTMLButtonElement || html instanceof HTMLAnchorElement || role === 'button'
        ? html.innerText.trim().slice(0, 200) : '';
      if (type) control.type = type;
      if (name) control.name = name;
      if (placeholder) control.placeholder = placeholder;
      if (autocomplete) control.autocomplete = autocomplete;
      if (ariaLabel) control.ariaLabel = ariaLabel;
      if (text) control.text = text;
      return [control];
    })
  ));
}

function requiredHttpsUrl(value: string | undefined): string {
  if (value === undefined) throw new Error('HTTPS URL is required.');
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '') {
    throw new Error('Only an HTTPS browser target without userinfo is allowed.');
  }
  return parsed.toString();
}

function requiredSelector(value: string | undefined): string {
  if (value === undefined || value.length < 1 || value.length > 1024 || value !== value.trim()
    || value.includes('\0')) throw new Error('A bounded selector is required.');
  return value;
}
