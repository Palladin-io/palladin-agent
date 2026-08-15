import { describe, expect, it } from 'vitest';
import { parseFormDiscoveryMap } from '../../src/form-map.js';

const map = {
  version: 1, domain: 'x.com', loginUrl: 'https://x.com/i/flow/login', provider: 'playwright',
  status: 'verified', fingerprint: 'a'.repeat(64), form: { version: 1, steps: [{
    fields: [{ entryFieldId: 'username', selector: 'input[name="username"]', control: 'username' }],
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
  });
  it('rejects candidate maps with an invalid fingerprint', () => {
    expect(parseFormDiscoveryMap({ ...map, fingerprint: 'bad' })).toBeNull();
  });
});
