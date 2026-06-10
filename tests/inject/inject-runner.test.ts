import { describe, it, expect } from 'vitest';
import { injectCredential, InjectablePage } from '../../src/inject/inject-runner.js';
import { ParsedSecret } from '../../src/crypto/secret.js';

function credential(username: string, password: string): ParsedSecret {
  return { username, password, url: null, notes: null, fields: { username, password } };
}

interface FakeOptions {
  url: string;
  /** Sequence of HTML views returned by content() on each call (multi-step). */
  views: string[];
}

class FakePage implements InjectablePage {
  filled: Record<string, string> = {};
  clicks: string[] = [];
  private viewIndex = 0;
  private currentUrl: string;

  constructor(private readonly opts: FakeOptions) {
    this.currentUrl = opts.url;
  }

  url(): string {
    return this.currentUrl;
  }

  async content(): Promise<string> {
    const idx = Math.min(this.viewIndex, this.opts.views.length - 1);
    return this.opts.views[idx]!;
  }

  async fill(selector: string, value: string): Promise<void> {
    this.filled[selector] = value;
  }

  async click(selector: string): Promise<void> {
    this.clicks.push(selector);
    // Advance to the next view, modelling the password step appearing after submit.
    if (this.viewIndex < this.opts.views.length - 1) {
      this.viewIndex += 1;
    }
  }

  async waitForTimeout(): Promise<void> {
    // no-op; content() already reflects the advanced view after click()
  }
}

const COMBINED = `<form>
  <input type="email" name="email" id="email" autocomplete="username">
  <input type="password" name="password" id="password" autocomplete="current-password">
  <button type="submit" id="go">Sign in</button>
</form>`;

const USERNAME_STEP = `<form>
  <input type="email" name="identifier" id="identifier" autocomplete="username">
  <button type="submit" id="next">Next</button>
</form>`;

const PASSWORD_STEP = `<form>
  <input type="password" name="password" id="password" autocomplete="current-password">
  <button type="submit" id="signin">Sign in</button>
</form>`;

describe('injectCredential', () => {
  it('fills and submits a combined form on the matching origin', async () => {
    const page = new FakePage({ url: 'https://github.com/login', views: [COMBINED] });
    const result = await injectCredential(page, credential('alice', 'pw'), { entryDomain: 'github.com' });

    expect(result.ok).toBe(true);
    expect(page.filled['#email']).toBe('alice');
    expect(page.filled['#password']).toBe('pw');
    expect(page.clicks).toContain('#go');
  });

  it('refuses to type on an origin mismatch (phishing) and fills nothing', async () => {
    const page = new FakePage({ url: 'https://github.com.evil.tld/login', views: [COMBINED] });
    const result = await injectCredential(page, credential('alice', 'pw'), { entryDomain: 'github.com' });

    expect(result.ok).toBe(false);
    expect(page.filled).toEqual({});
    expect(page.clicks).toEqual([]);
  });

  it('refuses on a non-HTTPS page', async () => {
    const page = new FakePage({ url: 'http://github.com/login', views: [COMBINED] });
    const result = await injectCredential(page, credential('alice', 'pw'), { entryDomain: 'github.com' });
    expect(result.ok).toBe(false);
    expect(page.filled).toEqual({});
  });

  it('drives a multi-step (username → password) flow', async () => {
    const page = new FakePage({ url: 'https://accounts.google.com/signin', views: [USERNAME_STEP, PASSWORD_STEP] });
    const result = await injectCredential(page, credential('alice@example.com', 'pw'), { entryDomain: 'google.com' });

    expect(result.ok).toBe(true);
    expect(page.filled['#identifier']).toBe('alice@example.com');
    expect(page.filled['#password']).toBe('pw');
    expect(page.clicks).toEqual(['#next', '#signin']);
  });

  it('does not submit when submit:false', async () => {
    const page = new FakePage({ url: 'https://github.com/login', views: [COMBINED] });
    const result = await injectCredential(page, credential('alice', 'pw'), { entryDomain: 'github.com', submit: false });
    expect(result.ok).toBe(true);
    expect(page.clicks).toEqual([]);
    expect(page.filled['#password']).toBe('pw');
  });

  it('fails clearly when no login form is present', async () => {
    const page = new FakePage({ url: 'https://github.com/', views: ['<div>nothing here</div>'] });
    const result = await injectCredential(page, credential('alice', 'pw'), { entryDomain: 'github.com' });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain('no login form');
    }
  });

  it('honours selector overrides', async () => {
    const html = `<form>
      <input type="text" name="weird" id="weird">
      <input type="password" name="pw" id="pw">
      <button type="submit" id="go">Go</button>
    </form>`;
    const page = new FakePage({ url: 'https://example.com/login', views: [html] });
    const result = await injectCredential(page, credential('alice', 'pw'), {
      entryDomain: 'example.com',
      overrides: { usernameSelector: '#weird', passwordSelector: '#pw', submitSelector: '#go' },
    });
    expect(result.ok).toBe(true);
    expect(page.filled['#weird']).toBe('alice');
    expect(page.filled['#pw']).toBe('pw');
  });
});
