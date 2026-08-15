import { describe, expect, it } from 'vitest';
import { formMapFingerprint } from '../../src/form-map-fingerprint.js';
import { parseFormDiscoveryMap } from '../../src/form-map.js';

const map = {
  version: 1, domain: 'x.com', loginUrl: 'https://x.com/i/flow/login', provider: 'playwright',
  status: 'verified', fingerprint: 'a'.repeat(64), form: { version: 1, steps: [{
    fields: [{ entryFieldId: 'credential.username', selector: 'input[name="username"]', control: 'username' }],
    submit: { action: 'click', selector: 'button[type="submit"]' },
  }] },
  cookieOverlays: [{ selectors: ['[data-testid="cookie"]'], dismiss: { action: 'click', selector: '[data-testid="accept"]' }, disappears: '[data-testid="cookie"]' }],
};

describe('form discovery map', () => {
  it('accepts a bounded map with cookie dismissal metadata', () => {
    expect(parseFormDiscoveryMap(map)).toEqual(map);
  });
  it('rejects executable or secret-bearing map extensions', () => {
    expect(parseFormDiscoveryMap({ ...map, javascript: 'alert(1)' })).toBeNull();
    expect(parseFormDiscoveryMap({ ...map, cookieOverlays: [{ ...map.cookieOverlays[0], value: 'cookie' }] })).toBeNull();
    expect(parseFormDiscoveryMap({ ...map, loginUrl: 'https://evil.example/login' })).toBeNull();
    expect(parseFormDiscoveryMap({ ...map, loginUrl: 'https://x.com/login?access_token=secret' }))
      .toBeNull();
    expect(parseFormDiscoveryMap({ ...map, mapVersion: 2_147_483_648 })).toBeNull();
  });
  it('rejects candidate maps with an invalid fingerprint', () => {
    expect(parseFormDiscoveryMap({ ...map, fingerprint: 'bad' })).toBeNull();
  });
  it('accepts new providers, locale-independent routes, and schema-valid login fields', () => {
    const form = map.form;
    expect(parseFormDiscoveryMap({
      ...map,
      provider: 'selenium-grid',
      loginUrl: 'https://x.com/pl/zaloguj/na-konto',
      form: {
        ...form,
        steps: [{
          ...form.steps[0],
          fields: [{ ...form.steps[0].fields[0], entryFieldId: 'credential.totp', control: 'otp' }],
        }],
      },
    })).not.toBeNull();
    expect(parseFormDiscoveryMap({
      ...map,
      domain: 'xn--bcher-kva.example',
      loginUrl: 'https://xn--bcher-kva.example/%D8%AA%D8%B3%D8%AC%D9%8A%D9%84-%D8%A7%D9%84%D8%AF%D8%AE%D9%88%D9%84',
    })).not.toBeNull();
    expect(parseFormDiscoveryMap({ ...map, provider: 'Unknown Provider' })).toBeNull();
    expect(parseFormDiscoveryMap({ ...map, provider: 'unfinished-' })).toBeNull();
  });
  it('counts selector limits in UTF-8 bytes', () => {
    const form = map.form;
    expect(parseFormDiscoveryMap({
      ...map,
      form: {
        ...form,
        steps: [{
          ...form.steps[0],
          fields: [{ ...form.steps[0].fields[0], selector: '😀'.repeat(500) }],
        }],
      },
    })).toBeNull();
  });
  it('matches the typed backend fingerprint for localized paths and selectors', () => {
    expect(formMapFingerprint({
      domain: 'example.org',
      loginUrl: 'https://example.org/pl/zaloguj-się',
      provider: 'custom-browser',
      form: {
        version: 1,
        steps: [{
          fields: [{
            entryFieldId: 'credential.password',
            selector: 'input[aria-label="Hasło użytkownika"]',
            control: 'password',
          }],
          submit: { action: 'click', selector: 'button[type=submit]' },
        }],
      },
      cookieOverlays: [{
        selectors: ['[data-testid=cmp]'],
        dismiss: { selector: 'button[data-action=accept]', action: 'click' },
        disappears: '[data-testid=cmp]',
        frame: 'same-origin',
      }],
    })).toBe('48807755c6780b76aa7842675e59dccdecd1aab96874c7979078ac489d934e9a');
  });
});
