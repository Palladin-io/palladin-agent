import { describe, expect, it } from 'vitest';
import { popularFormMaps } from '../../src/popular-form-maps.js';
import { parseFormDiscoveryMap } from '../../src/form-map.js';
import { formMapFingerprint } from '../../src/form-map-fingerprint.js';

describe('popular form map catalog', () => {
  it('contains exactly 50 independently parseable maps', () => {
    expect(popularFormMaps).toHaveLength(50);
    expect(new Set(popularFormMaps.map((map) => map.domain)).size).toBe(50);
    for (const map of popularFormMaps) {
      expect(parseFormDiscoveryMap(map)).not.toBeNull();
      expect(map.status).toBe('candidate');
      expect(map.fingerprint).toBe(formMapFingerprint(map));
    }
  });
});
