import { parseHTML } from 'linkedom';
import { ParsedSecret } from '../crypto/secret.js';
import { checkOrigin } from './origin-check.js';
import { detectLoginFields, DetectedFields, SelectorOverrides } from './field-detection.js';

// Structural subset of the Playwright Page we use — keeps this module testable with a fake page and
// avoids a hard compile-time dependency on playwright-core's types at every call site.
export interface InjectablePage {
  url(): string;
  content(): Promise<string>;
  fill(selector: string, value: string): Promise<void>;
  click(selector: string): Promise<void>;
  waitForTimeout(ms: number): Promise<void>;
}

export interface InjectOptions {
  /** The entry's bound domain (Entry.UrlDomain). Required for the origin gate. */
  entryDomain: string | null;
  overrides?: SelectorOverrides;
  /** Submit after filling (default true). */
  submit?: boolean;
  /** Max time to wait for the password field to appear on a multi-step form. */
  passwordStepTimeoutMs?: number;
}

export type InjectResult =
  | { ok: true; steps: string[] }
  | { ok: false; reason: string; steps: string[] };

const DEFAULT_PASSWORD_STEP_TIMEOUT = 8000;
const POLL_INTERVAL = 400;

/**
 * Fill (and optionally submit) the login form on `page` with `secret` (CVT-151).
 *
 * Order of operations is security-critical:
 *  1. Verify the page origin matches the entry's bound domain BEFORE touching any field. This is the
 *     anti-phishing gate — a mismatched origin aborts with no typing.
 *  2. Detect fields with pure heuristics (or caller-supplied selectors). We never run agent-provided
 *     JavaScript and never pass the secret through page.evaluate — values are typed via fill().
 *  3. Handle multi-step forms: if only a username field is present, fill + submit it, then poll for
 *     the password field to appear and fill that.
 */
export async function injectCredential(
  page: InjectablePage,
  secret: ParsedSecret,
  options: InjectOptions,
): Promise<InjectResult> {
  const steps: string[] = [];
  const submit = options.submit ?? true;

  const origin = checkOrigin(page.url(), options.entryDomain);
  if (!origin.ok) {
    return { ok: false, reason: origin.reason, steps };
  }
  steps.push(`origin verified: ${origin.registrableDomain}`);

  let fields = await detect(page, options.overrides);

  if (fields.step === 'none') {
    return { ok: false, reason: 'no login form detected on the current page', steps };
  }

  // Combined form: fill both, submit once.
  if (fields.step === 'combined') {
    await fillUsername(page, fields, secret, steps);
    await fillPassword(page, fields, secret, steps);
    if (submit) {
      await clickSubmit(page, fields, steps);
    }
    return { ok: true, steps };
  }

  // Password-only view (username already entered elsewhere, or a re-auth page).
  if (fields.step === 'password-step') {
    await fillPassword(page, fields, secret, steps);
    if (submit) {
      await clickSubmit(page, fields, steps);
    }
    return { ok: true, steps };
  }

  // Username-step view: fill username, submit, wait for the password view, then fill it.
  await fillUsername(page, fields, secret, steps);
  if (!submit) {
    return { ok: true, steps };
  }
  await clickSubmit(page, fields, steps);

  const appeared = await waitForPasswordStep(page, options.passwordStepTimeoutMs ?? DEFAULT_PASSWORD_STEP_TIMEOUT);
  if (!appeared) {
    return { ok: false, reason: 'submitted the identifier but the password field never appeared', steps };
  }
  steps.push('password step appeared');

  // Re-verify origin after the navigation/transition — the password view could be a different page.
  const postNav = checkOrigin(page.url(), options.entryDomain);
  if (!postNav.ok) {
    return { ok: false, reason: `after the username step the origin changed: ${postNav.reason}`, steps };
  }

  fields = await detect(page, options.overrides);
  if (!fields.passwordSelector) {
    return { ok: false, reason: 'password field not detected on the second step', steps };
  }
  await fillPassword(page, fields, secret, steps);
  await clickSubmit(page, fields, steps);
  return { ok: true, steps };
}

async function detect(page: InjectablePage, overrides?: SelectorOverrides): Promise<DetectedFields> {
  const html = await page.content();
  const { document } = parseHTML(html);
  return detectLoginFields(document as unknown as Parameters<typeof detectLoginFields>[0], overrides);
}

async function waitForPasswordStep(page: InjectablePage, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await page.waitForTimeout(POLL_INTERVAL);
    const fields = await detect(page);
    if (fields.passwordSelector) {
      return true;
    }
  }
  return false;
}

async function fillUsername(page: InjectablePage, fields: DetectedFields, secret: ParsedSecret, steps: string[]): Promise<void> {
  if (!fields.usernameSelector || secret.username === null) {
    return;
  }
  await page.fill(fields.usernameSelector, secret.username);
  steps.push('filled username');
}

async function fillPassword(page: InjectablePage, fields: DetectedFields, secret: ParsedSecret, steps: string[]): Promise<void> {
  if (!fields.passwordSelector) {
    return;
  }
  await page.fill(fields.passwordSelector, secret.password);
  steps.push('filled password');
}

async function clickSubmit(page: InjectablePage, fields: DetectedFields, steps: string[]): Promise<void> {
  if (!fields.submitSelector) {
    steps.push('no submit button found — left form filled');
    return;
  }
  await page.click(fields.submitSelector);
  steps.push('submitted');
}
