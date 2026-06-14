import { describe, it, expect } from 'vitest';
import { checkOrigin } from '../../src/inject/origin-check.js';

describe('checkOrigin — anti-phishing gate', () => {
  it('matches exact host', () => {
    expect(checkOrigin('https://github.com/login', 'github.com')).toEqual({ ok: true, registrableDomain: 'github.com' });
  });

  it('matches a subdomain against the registrable domain (eTLD+1)', () => {
    expect(checkOrigin('https://accounts.google.com/signin', 'google.com')).toMatchObject({ ok: true });
    expect(checkOrigin('https://login.corp.okta.com/', 'okta.com')).toMatchObject({ ok: true });
  });

  it('accepts the entry domain given as a full URL', () => {
    expect(checkOrigin('https://www.paypal.com/signin', 'https://paypal.com/login')).toMatchObject({ ok: true });
  });

  it('handles multi-label public suffixes (co.uk)', () => {
    expect(checkOrigin('https://www.hsbc.co.uk/login', 'hsbc.co.uk')).toMatchObject({ ok: true });
    expect(checkOrigin('https://evil.co.uk/login', 'hsbc.co.uk')).toMatchObject({ ok: false });
  });

  it('rejects a look-alike sibling domain (phishing)', () => {
    const r = checkOrigin('https://google.com.evil.tld/signin', 'google.com');
    expect(r.ok).toBe(false);
  });

  it('rejects a typosquat', () => {
    expect(checkOrigin('https://goggle.com/signin', 'google.com').ok).toBe(false);
  });

  it('rejects a different registrable domain', () => {
    expect(checkOrigin('https://phishing-site.com/google-login', 'google.com').ok).toBe(false);
  });

  it('refuses non-HTTPS pages', () => {
    expect(checkOrigin('http://github.com/login', 'github.com').ok).toBe(false);
  });

  it('allows http on localhost for development', () => {
    expect(checkOrigin('http://localhost:3000/login', 'localhost').ok).toBe(true);
  });

  it('refuses when the entry has no bound domain', () => {
    expect(checkOrigin('https://github.com/login', null).ok).toBe(false);
    expect(checkOrigin('https://github.com/login', '').ok).toBe(false);
  });

  it('refuses an unparseable current URL', () => {
    expect(checkOrigin('not a url', 'github.com').ok).toBe(false);
  });
});
