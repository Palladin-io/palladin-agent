import { describe, it, expect } from 'vitest';
import { parseHTML } from 'linkedom';
import { detectLoginFields } from '../../src/inject/field-detection.js';
import { LOGIN_FIXTURES } from './login-form-fixtures.js';

function detect(html: string, overrides?: Parameters<typeof detectLoginFields>[1]) {
  const { document } = parseHTML(html);
  return detectLoginFields(document as unknown as Parameters<typeof detectLoginFields>[0], overrides);
}

describe('detectLoginFields — popular portals (100+ fixtures)', () => {
  it('covers at least 100 login forms', () => {
    expect(LOGIN_FIXTURES.length).toBeGreaterThanOrEqual(100);
  });

  for (const fx of LOGIN_FIXTURES) {
    it(`detects fields: ${fx.name}`, () => {
      const result = detect(fx.html);
      expect(result.step).toBe(fx.expect.step);
      expect(result.usernameSelector !== null).toBe(fx.expect.username);
      expect(result.passwordSelector !== null).toBe(fx.expect.password);
      expect(result.submitSelector !== null).toBe(fx.expect.submit);
    });
  }
});

describe('detectLoginFields — specific signals', () => {
  it('does not pick a search box as the username', () => {
    const result = detect(`<form>
      <input type="search" name="q" placeholder="Search">
      <input type="password" name="password" autocomplete="current-password">
      <button type="submit">Go</button>
    </form>`);
    // search box is rejected; the lone password field still makes this a combined-ish form but with
    // no username detected (the search input is filtered out, leaving no username candidate in-form).
    expect(result.passwordSelector).not.toBeNull();
    expect(result.usernameSelector).toBeNull();
  });

  it('prefers current-password over new-password when both exist', () => {
    const result = detect(`<form>
      <input type="text" name="username" autocomplete="username">
      <input type="password" name="new" autocomplete="new-password">
      <input type="password" name="cur" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>`);
    expect(result.passwordSelector).toContain('cur');
  });

  it('returns step "none" for a page with no login form', () => {
    const result = detect('<div><p>Welcome</p><a href="/login">Log in</a></div>');
    expect(result.step).toBe('none');
    expect(result.usernameSelector).toBeNull();
    expect(result.passwordSelector).toBeNull();
  });

  it('ignores hidden inputs', () => {
    const result = detect(`<form>
      <input type="hidden" name="csrf" value="abc">
      <input type="email" name="email" autocomplete="username">
      <input type="password" name="password">
      <button type="submit">Sign in</button>
    </form>`);
    expect(result.usernameSelector).toContain('email');
    expect(result.passwordSelector).not.toBeNull();
  });

  it('builds an id-based selector when an id is present', () => {
    const result = detect(`<form>
      <input type="text" id="login_field" name="login" autocomplete="username">
      <input type="password" id="password" name="password">
      <button type="submit" id="commit">Sign in</button>
    </form>`);
    expect(result.usernameSelector).toBe('#login_field');
    expect(result.passwordSelector).toBe('#password');
    expect(result.submitSelector).toBe('#commit');
  });

  it('honours explicit selector overrides', () => {
    const result = detect(`<form>
      <input type="text" name="weird" id="weird">
      <input type="password" name="pw" id="pw">
      <button type="submit" id="go">Go</button>
    </form>`, {
      usernameSelector: '#weird',
      passwordSelector: '#pw',
      submitSelector: '#go',
    });
    expect(result.usernameSelector).toBe('#weird');
    expect(result.passwordSelector).toBe('#pw');
    expect(result.submitSelector).toBe('#go');
  });
});
