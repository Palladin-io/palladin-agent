import { Command } from 'commander';
import { ProfilePaths } from '../config/paths.js';
import { SelectorOverrides } from '../inject/field-detection.js';
import { injectCredential, InjectablePage } from '../inject/inject-runner.js';
import { checkOrigin } from '../inject/origin-check.js';
import { buildFailureReport, writeFailureReport } from '../inject/failure-report.js';
import { uploadInjectFailure } from '../http/agent-api.js';
import { resolveAgentContext } from '../http/agent-context.js';
import { resolveSecret } from './credentials.js';
import { addWaitOptions, parseWaitCli, RawWaitOpts } from '../credential/wait-options.js';
import { exitCodeForAccess } from '../credential/exit-codes.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

function fail(message: string): never {
  console.error(`Error: ${message}`);
  process.exit(1);
}

/**
 * claw-vault inject <vaultId> <entryId> --cdp <ws-endpoint> [selectors]
 *
 * Connects to the agent's already-running browser over the Chrome DevTools Protocol, verifies the
 * active page's origin against the entry's backend-bound domain (anti-phishing), then fills and
 * submits the login form. The secret is typed into the page via Playwright `fill()` — it never
 * enters the agent's LLM context and we never run agent-provided JavaScript.
 *
 * The agent is expected to launch its browser with a CDP endpoint, e.g.
 *   chromium --remote-debugging-port=9222
 * and pass --cdp http://localhost:9222 (or the ws:// endpoint).
 */
export function injectCommand(getProfile: GetProfile): Command {
  const cmd = new Command('inject')
    .description("Fill a login form in the agent's browser (over CDP) — the secret never enters the agent context")
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .requiredOption('--cdp <endpoint>', 'CDP endpoint of the running browser (e.g. http://localhost:9222)')
    .option('--reason <reason>', 'justification shown to the approving user (required on first request)')
    .option('--username-selector <css>', 'override: CSS selector for the username field')
    .option('--password-selector <css>', 'override: CSS selector for the password field')
    .option('--submit-selector <css>', 'override: CSS selector for the submit button')
    .option('--no-submit', 'fill the form but do not submit')
    .option('--page-url <url>', 'pick the open page whose URL starts with this prefix (default: first page)')
    .option('--fill-only', 'secure-fill primitive: type the secret into the given --password/--username-selector ONLY (no auto-detection, no submit unless --submit-selector). The agent drives navigation/clicks itself.')
    .option('--verbose', 'log a value-free trace of detection + actions to stderr (debugging)');
  addWaitOptions(cmd);
  return cmd.action(async (vaultId: string, entryId: string, opts: {
      cdp: string;
      reason?: string;
      usernameSelector?: string;
      passwordSelector?: string;
      submitSelector?: string;
      submit?: boolean;
      pageUrl?: string;
      fillOnly?: boolean;
      verbose?: boolean;
    } & RawWaitOpts) => {
      const { name, paths } = getProfile();
      const { config, keypair, signing } = await resolveAgentContext(name, paths);

      const resolved = await resolveSecret(config, keypair, vaultId, entryId, 'inject', opts.reason, parseWaitCli(opts), signing);
      if (!resolved.ok) {
        console.error(`Error: ${resolved.message}`);
        process.exit(exitCodeForAccess(resolved.access));
      }
      const { secret, urlDomain, label } = resolved;

      if (!urlDomain) {
        fail(`entry "${label}" has no bound URL — inject is only allowed for entries with a known site (anti-phishing).`);
      }

      // playwright-core is an optional/heavy dependency; import lazily so `get`/`exec`/`search` work
      // without a browser stack installed.
      let chromium: typeof import('playwright-core').chromium;
      try {
        ({ chromium } = await import('playwright-core'));
      } catch {
        fail('inject requires playwright-core. Install it: npm i -g playwright-core');
      }

      // inject drives the browser over the Chrome DevTools Protocol, so the agent's browser must be
      // Chromium-family (Chrome, Edge, Brave, Chromium, Arc, Opera) launched with
      // --remote-debugging-port. Firefox (Juggler) and WebKit/Safari do not expose CDP and are not
      // supported by this path.
      const browser = await chromium.connectOverCDP(opts.cdp).catch((err) => {
        fail(
          `could not connect over CDP at ${opts.cdp}: ${err.message}. ` +
          'inject requires a Chromium-based browser (Chrome/Edge/Brave/Chromium) started with ' +
          '--remote-debugging-port. Firefox and Safari are not supported.',
        );
      });

      try {
        const page = pickPage(browser, opts.pageUrl);
        if (!page) {
          fail('no open page found in the connected browser — open the login page first.');
        }

        // Visible-first adapter: resolve every selector to the first VISIBLE match. SPA login pages
        // (X / Facebook) render an inert, aria-hidden copy of the form behind the modal, so a raw
        // selector matches 2+ elements and Playwright's strict mode throws. Scoping to the visible
        // one fixes that for both --fill-only and auto detection.
        const injectable = toInjectable(page);

        // --fill-only (CVT-158): the agent has already navigated to the right step (e.g. via the
        // Playwright MCP) and tells us the visible field selector. We ONLY type the secret — no
        // auto-detection, no submit unless an explicit --submit-selector is given. The origin gate
        // still applies; the secret is typed via fill() and never enters the agent context.
        if (opts.fillOnly) {
          if (!opts.passwordSelector && !opts.usernameSelector) {
            fail('--fill-only requires --password-selector and/or --username-selector (the visible field to type into).');
          }
          const origin = checkOrigin(injectable.url(), urlDomain);
          if (!origin.ok) {
            fail(origin.reason);
          }
          const did: string[] = [];
          if (opts.usernameSelector && secret.username !== null) {
            await injectable.fill(opts.usernameSelector, secret.username);
            did.push('username');
          }
          if (opts.passwordSelector) {
            await injectable.fill(opts.passwordSelector, secret.password);
            did.push('password');
          }
          if (opts.submitSelector && opts.submit !== false) {
            await injectable.click(opts.submitSelector);
            did.push('submitted');
          }
          console.log(`Filled ${label} (fill-only): ${did.join(' → ') || 'nothing'}`);
          return;
        }

        const overrides: SelectorOverrides = {
          usernameSelector: opts.usernameSelector,
          passwordSelector: opts.passwordSelector,
          submitSelector: opts.submitSelector,
        };

        const result = await injectCredential(injectable, secret, {
          entryDomain: urlDomain,
          overrides,
          submit: opts.submit,
          log: opts.verbose ? (m) => console.error(`[inject] ${m}`) : undefined,
        });

        if (!result.ok) {
          // Capture a redacted, value-free snapshot so a real-world miss can improve site support.
          // Best-effort, two-pronged: upload to the backend (near-real-time team visibility, CVT-155)
          // AND keep a local JSONL copy as the offline fallback. Neither blocks the user's error.
          if (result.diagnostic) {
            const report = buildFailureReport({
              reason: result.reason,
              steps: result.steps,
              vaultId,
              entryId,
              entryDomain: urlDomain,
              pageUrl: result.diagnostic.url,
              html: result.diagnostic.html,
            });
            writeFailureReport(report);
            await uploadInjectFailure(config, keypair, {
              entryId,
              domain: report.entryDomain,
              reason: report.reason,
              pageOrigin: report.pageOrigin,
              controls: report.controls,
            }, signing);
          }
          fail(`${result.reason} (steps: ${result.steps.join(' → ') || 'none'})`);
        }
        console.log(`Injected into ${label}: ${result.steps.join(' → ')}`);
        // Honest, best-effort signal — the agent makes the final call from its own browser.
        if (result.outcome === 'rejected') {
          console.error(
            'Warning: the credential appears to have been rejected (wrong password / sign-in error). ' +
            'The stored credential may be stale — verify in your browser.',
          );
        } else if (result.outcome === 'unknown') {
          console.error(
            'Note: could not confirm the login outcome (no clear success/error signal — possible 2FA, ' +
            'captcha, or a slow page). Check your browser to confirm.',
          );
        }
      } finally {
        await browser.close();
      }
    });
}

// Wrap a Playwright Page as an [InjectablePage] whose every selector resolves to the first VISIBLE
// match (`.filter({ visible: true }).first()`). This is what makes fill/click robust on SPA login
// pages that render an inert, aria-hidden duplicate of the form behind the modal — a raw selector
// would match 2+ nodes and Playwright strict mode would throw.
function toInjectable(page: import('playwright-core').Page): InjectablePage {
  const visibleFirst = (selector: string) => page.locator(selector).filter({ visible: true }).first();
  return {
    url: () => page.url(),
    content: () => page.content(),
    fill: (selector, value) => visibleFirst(selector).fill(value),
    click: (selector) => visibleFirst(selector).click(),
    waitForTimeout: (ms) => page.waitForTimeout(ms),
    isVisible: (selector) => visibleFirst(selector).isVisible().catch(() => false),
  };
}

// Pick the target page across all CDP contexts: the first whose URL matches the prefix, else the
// first page. Returns undefined when the browser has no pages.
function pickPage(
  browser: import('playwright-core').Browser,
  urlPrefix?: string,
): import('playwright-core').Page | undefined {
  const pages = browser.contexts().flatMap((ctx) => ctx.pages());
  if (pages.length === 0) {
    return undefined;
  }
  if (urlPrefix) {
    return pages.find((p) => p.url().startsWith(urlPrefix)) ?? pages[0];
  }
  return pages[0];
}
