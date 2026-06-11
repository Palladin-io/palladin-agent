import { describe, it, expect } from 'vitest';
import { classifyInjectOutcome } from '../../src/inject/outcome.js';

describe('classifyInjectOutcome', () => {
  it('succeeded: navigated to a new path with no password field', () => {
    expect(classifyInjectOutcome({
      preUrl: 'https://site.com/login',
      postUrl: 'https://site.com/dashboard',
      postHtml: '<main>Welcome</main>',
    })).toBe('succeeded');
  });

  it('rejected: role=alert error indicator present', () => {
    expect(classifyInjectOutcome({
      preUrl: 'https://site.com/login',
      postUrl: 'https://site.com/login',
      postHtml: '<form><input type="password"><div role="alert">Wrong password</div></form>',
    })).toBe('rejected');
  });

  it('rejected: aria-invalid present (even if the URL changed to /login?error)', () => {
    expect(classifyInjectOutcome({
      preUrl: 'https://site.com/login',
      postUrl: 'https://site.com/login?error=1',
      postHtml: '<form><input type="password" aria-invalid="true"></form>',
    })).toBe('rejected');
  });

  it('unknown: still on the form, no error cue (could be loading / silent)', () => {
    expect(classifyInjectOutcome({
      preUrl: 'https://site.com/login',
      postUrl: 'https://site.com/login',
      postHtml: '<form><input type="password"></form>',
    })).toBe('unknown');
  });

  it('unknown: navigated away but a password field is still present (e.g. 2FA password re-entry)', () => {
    expect(classifyInjectOutcome({
      preUrl: 'https://site.com/login',
      postUrl: 'https://site.com/verify',
      postHtml: '<form><input type="password"><label>Enter code</label></form>',
    })).toBe('unknown');
  });

  it('ignores hidden error nodes', () => {
    expect(classifyInjectOutcome({
      preUrl: 'https://site.com/login',
      postUrl: 'https://site.com/dashboard',
      postHtml: '<div role="alert" style="display:none">stale</div><main>Welcome</main>',
    })).toBe('succeeded');
  });

  it('does not classify on localised error TEXT alone (no ARIA) — stays unknown', () => {
    // A site that shows "Niepoprawne hasło" as plain text with no role=alert/aria-invalid is not
    // machine-detectable; we must not guess from localised text.
    expect(classifyInjectOutcome({
      preUrl: 'https://site.com/login',
      postUrl: 'https://site.com/login',
      postHtml: '<form><input type="password"><span class="msg">Niepoprawne hasło</span></form>',
    })).toBe('unknown');
  });
});
