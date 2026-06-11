import { parseHTML } from 'linkedom';
import { ParsedSecret } from '../crypto/secret.js';
import { checkOrigin } from './origin-check.js';
import { detectLoginFields, DetectedFields, SelectorOverrides } from './field-detection.js';
import { classifyInjectOutcome, InjectOutcome } from './outcome.js';

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
  | {
      ok: true;
      steps: string[];
      /**
       * Best-effort observation of the post-submit auth outcome (CVT-151 follow-up). `succeeded` /
       * `rejected` are HINTS, not guarantees; `unknown` is the honest default (and is used whenever
       * we did not submit). The agent makes the final call from its own browser/task result. A
       * `rejected` outcome means the form was driven correctly but the credential was likely refused
       * — NOT a heuristic miss, so it is not reported as one.
       */
      outcome: InjectOutcome;
    }
  | {
      ok: false;
      reason: string;
      steps: string[];
      /**
       * The page HTML at failure time and its URL, so the caller can persist a redacted, value-free
       * diagnostic (CVT-151 follow-up). Omitted only when failure happened before any page read
       * (e.g. origin mismatch — we still pass it so misses are captured). Never contains secrets.
       */
      diagnostic?: { html: string; url: string };
    };

const DEFAULT_PASSWORD_STEP_TIMEOUT = 8000;
const POLL_INTERVAL = 400;
// How long to let the page settle after the final submit before observing the outcome.
const OUTCOME_SETTLE_MS = 1500;

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

  // Build a failure result with a structural (value-free) diagnostic snapshot of the current page,
  // so the caller can persist it for offline heuristic improvement. Reading content() must never
  // break the failure path, so it is best-effort.
  const fail = async (reason: string): Promise<InjectResult> => {
    let diagnostic: { html: string; url: string } | undefined;
    try {
      diagnostic = { html: await page.content(), url: page.url() };
    } catch {
      diagnostic = undefined;
    }
    return { ok: false, reason, steps, diagnostic };
  };

  const origin = checkOrigin(page.url(), options.entryDomain);
  if (!origin.ok) {
    return fail(origin.reason);
  }
  steps.push(`origin verified: ${origin.registrableDomain}`);

  let fields = await detect(page, options.overrides);

  if (fields.step === 'none') {
    return fail('no login form detected on the current page');
  }

  // After a final submit, observe (best-effort) whether the credential was accepted. Honest default
  // is `unknown`; only navigation-away or an ARIA error cue move it off that. Never blocks success.
  const observe = async (preUrl: string): Promise<InjectResult> => {
    try {
      await page.waitForTimeout(OUTCOME_SETTLE_MS);
      const outcome = classifyInjectOutcome({ preUrl, postUrl: page.url(), postHtml: await page.content() });
      if (outcome === 'rejected') {
        steps.push('post-submit: credential appears rejected');
      } else if (outcome === 'succeeded') {
        steps.push('post-submit: navigated away (login likely succeeded)');
      }
      return { ok: true, steps, outcome };
    } catch {
      return { ok: true, steps, outcome: 'unknown' };
    }
  };

  // Combined form: fill both, submit once.
  if (fields.step === 'combined') {
    await fillUsername(page, fields, secret, steps);
    await fillPassword(page, fields, secret, steps);
    if (!submit) {
      return { ok: true, steps, outcome: 'unknown' };
    }
    const preUrl = page.url();
    await clickSubmit(page, fields, steps);
    return observe(preUrl);
  }

  // Password-only view (username already entered elsewhere, or a re-auth page).
  if (fields.step === 'password-step') {
    await fillPassword(page, fields, secret, steps);
    if (!submit) {
      return { ok: true, steps, outcome: 'unknown' };
    }
    const preUrl = page.url();
    await clickSubmit(page, fields, steps);
    return observe(preUrl);
  }

  // Username-step view: fill username, submit, wait for the password view, then fill it.
  await fillUsername(page, fields, secret, steps);
  if (!submit) {
    return { ok: true, steps, outcome: 'unknown' };
  }
  await clickSubmit(page, fields, steps);

  const appeared = await waitForPasswordStep(page, options.passwordStepTimeoutMs ?? DEFAULT_PASSWORD_STEP_TIMEOUT);
  if (!appeared) {
    return fail('submitted the identifier but the password field never appeared');
  }
  steps.push('password step appeared');

  // Re-verify origin after the navigation/transition — the password view could be a different page.
  const postNav = checkOrigin(page.url(), options.entryDomain);
  if (!postNav.ok) {
    return fail(`after the username step the origin changed: ${postNav.reason}`);
  }

  fields = await detect(page, options.overrides);
  if (!fields.passwordSelector) {
    return fail('password field not detected on the second step');
  }
  await fillPassword(page, fields, secret, steps);
  const preUrl = page.url();
  await clickSubmit(page, fields, steps);
  return observe(preUrl);
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
