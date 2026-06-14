import { parseHTML } from 'linkedom';

/**
 * Best-effort classification of what happened AFTER `inject` submitted a login form (CVT-151
 * follow-up). The CLI cannot definitively know whether a login succeeded — only the agent, looking
 * at its own browser / task result, can. So this is a conservative, three-state OBSERVATION the
 * agent can use as a hint, not a guarantee:
 *
 *   - `succeeded`  — the page navigated away from the login view and no password field remains.
 *                    Strong signal a login went through.
 *   - `rejected`   — an error indicator appeared (role=alert / aria-invalid) — typically wrong
 *                    credentials, a server error, or (less often) a mis-filled field. The agent
 *                    should treat the stored credential as suspect.
 *   - `unknown`    — neither signal is conclusive (still loading, silent handling, a 2FA/captcha
 *                    challenge, or a site that gives no machine-readable cue). The default — we do
 *                    NOT guess.
 *
 * Deliberately language-INDEPENDENT: it keys off URL change, password-field presence and ARIA
 * structure (`role="alert"`, `aria-invalid="true"`), NEVER localised error TEXT (which would be
 * unreliable across languages — see the i18n discussion).
 */
export type InjectOutcome = 'succeeded' | 'rejected' | 'unknown';

interface ElementLike {
  getAttribute(name: string): string | null;
}
interface DocumentLike {
  querySelectorAll(selector: string): ArrayLike<ElementLike>;
}

function isVisible(el: ElementLike): boolean {
  const style = (el.getAttribute('style') ?? '').toLowerCase();
  if (style.includes('display:none') || style.includes('display: none')) {
    return false;
  }
  return el.getAttribute('aria-hidden') !== 'true';
}

function hasVisible(doc: DocumentLike, selector: string): boolean {
  const list = doc.querySelectorAll(selector);
  for (let i = 0; i < list.length; i++) {
    const el = list[i];
    if (el && isVisible(el)) {
      return true;
    }
  }
  return false;
}

// A path/host change between before and after submit. Query strings are ignored (a login page can
// append ?error=... while staying the same view — that is handled by the error-indicator check).
function navigatedAway(preUrl: string, postUrl: string): boolean {
  try {
    const a = new URL(preUrl);
    const b = new URL(postUrl);
    return a.host !== b.host || a.pathname !== b.pathname;
  } catch {
    return preUrl !== postUrl;
  }
}

export function classifyInjectOutcome(input: {
  preUrl: string;
  postUrl: string;
  postHtml: string;
}): InjectOutcome {
  const { document } = parseHTML(input.postHtml);
  const doc = document as unknown as DocumentLike;

  const passwordPresent = hasVisible(doc, 'input[type="password"]');
  const errorPresent =
    hasVisible(doc, '[role="alert"]') || hasVisible(doc, '[aria-invalid="true"]');
  const moved = navigatedAway(input.preUrl, input.postUrl);

  // An explicit error cue is the strongest "rejected" signal — even if the URL changed (some sites
  // redirect to /login?error). Checked first.
  if (errorPresent) {
    return 'rejected';
  }
  // Navigated to a different view with no password field left → very likely logged in.
  if (moved && !passwordPresent) {
    return 'succeeded';
  }
  // Anything else (still on the form, still loading, 2FA/captcha, no machine-readable cue).
  return 'unknown';
}
