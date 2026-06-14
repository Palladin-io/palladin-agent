import { describe, it, expect } from 'vitest';
import { parseHTML } from 'linkedom';
import { detectLoginFields } from '../../src/inject/field-detection.js';
import { injectCredential, InjectablePage } from '../../src/inject/inject-runner.js';
import { ParsedSecret } from '../../src/crypto/secret.js';

function detect(html: string) {
  const { document } = parseHTML(html);
  return detectLoginFields(document as unknown as Parameters<typeof detectLoginFields>[0]);
}

const credential = (u: string, p: string): ParsedSecret => ({
  username: u,
  password: p,
  url: null,
  notes: null,
  fields: { username: u, password: p },
});

// SPA login (X / Facebook style): submit is a div[role=button] whose label is TEXT, plus a hidden
// real input[type=submit]. Detection is pure-DOM (no layout), so both are candidates in order.
const SPA_FORM = `<form>
  <input type="email" name="email" autocomplete="username">
  <input type="password" name="password" autocomplete="current-password">
  <input type="submit" aria-label="hidden-real-submit">
  <div role="button" aria-label="Log In">Log in</div>
</form>`;

describe('detectLoginFields — SPA submit by visible text', () => {
  it('recognises a div[role=button] submit from its text content', () => {
    const r = detect(`<form>
      <input type="email" name="email" autocomplete="username">
      <input type="password" name="password" autocomplete="current-password">
      <div role="button" data-testid="login">Log in</div>
    </form>`);
    expect(r.submitSelector).toBe('div[data-testid="login"]');
  });

  it('matches "Continue" / "Next" text (multi-step verbs)', () => {
    const r = detect(`<form>
      <input type="email" name="email" autocomplete="username">
      <div role="button" aria-label="Next step">Continue</div>
    </form>`);
    expect(r.submitSelector).toBe('div[aria-label="Next step"]');
  });

  it('lists the explicit (possibly hidden) submit first, then the text button', () => {
    const r = detect(SPA_FORM);
    expect(r.submitCandidates).toEqual([
      'input[aria-label="hidden-real-submit"]',
      'div[aria-label="Log In"]',
    ]);
  });
});

/** Fake page with a per-selector visibility map and an optional click that throws. */
class VisibilityFakePage implements InjectablePage {
  clicks: string[] = [];
  constructor(
    private readonly html: string,
    private readonly visible: Record<string, boolean>,
    private readonly throwOnClick?: string,
  ) {}
  url(): string {
    return 'https://x.com/login';
  }
  async content(): Promise<string> {
    return this.html;
  }
  async fill(): Promise<void> {}
  async click(selector: string): Promise<void> {
    if (this.throwOnClick && selector === this.throwOnClick) {
      throw new Error(`Timeout 30000ms exceeded clicking ${selector}`);
    }
    this.clicks.push(selector);
  }
  async waitForTimeout(): Promise<void> {}
  async isVisible(selector: string): Promise<boolean> {
    return this.visible[selector] ?? true;
  }
}

describe('injectCredential — submit visibility fallback', () => {
  it('skips a hidden candidate and clicks the first visible one', async () => {
    const page = new VisibilityFakePage(SPA_FORM, {
      'input[aria-label="hidden-real-submit"]': false,
      'div[aria-label="Log In"]': true,
    });
    const result = await injectCredential(page, credential('alice', 'pw'), {
      entryDomain: 'x.com',
    });
    expect(result.ok).toBe(true);
    expect(page.clicks).toEqual(['div[aria-label="Log In"]']);
  });

  it('leaves the form filled when every candidate is hidden (graceful, no throw)', async () => {
    const page = new VisibilityFakePage(SPA_FORM, {
      'input[aria-label="hidden-real-submit"]': false,
      'div[aria-label="Log In"]': false,
    });
    const result = await injectCredential(page, credential('alice', 'pw'), {
      entryDomain: 'x.com',
    });
    expect(result.ok).toBe(true);
    expect(page.clicks).toEqual([]);
    if (result.ok) {
      expect(result.steps.some((s) => s.includes('no clickable submit'))).toBe(true);
    }
  });
});

describe('injectCredential — graceful capture on a click error', () => {
  it('turns a Playwright click error into ok:false + diagnostic, not an uncaught crash', async () => {
    const page = new VisibilityFakePage(
      SPA_FORM,
      { 'input[aria-label="hidden-real-submit"]': true },
      'input[aria-label="hidden-real-submit"]',
    );
    const result = await injectCredential(page, credential('alice', 'pw'), {
      entryDomain: 'x.com',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain('browser action failed');
      expect(result.diagnostic).toBeDefined();
      expect(result.steps).toContain('filled password');
    }
  });
});
