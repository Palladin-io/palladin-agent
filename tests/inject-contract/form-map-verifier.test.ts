import { describe, expect, it } from 'vitest';
import { fingerprint } from '../../scripts/verify-form-maps.js';
import { parseFormDiscoveryMap } from '../../src/form-map.js';

describe('form map verifier', () => {
  it('uses the same parsed map shape as the provider', () => {
    const map = parseFormDiscoveryMap({
      version: 1, domain: 'example.com', loginUrl: 'https://example.com/login', provider: 'playwright',
      status: 'verified', fingerprint: 'a'.repeat(64), form: { version: 1, steps: [{
        fields: [{ entryFieldId: 'credential.username', selector: '#username', control: 'username' }],
        submit: { action: 'click', selector: '#submit' },
      }] },
    });
    expect(map).not.toBeNull();
    expect(fingerprint(map!)).toMatch(/^[a-f0-9]{64}$/);
  });
});
