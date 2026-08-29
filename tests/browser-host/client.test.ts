import { describe, expect, it } from 'vitest';

import { isExtensionInject } from '../../src/browser-host/client.js';

describe('existing-extension CLI routing', () => {
  it('routes only default or explicit extension Inject through Native Messaging', () => {
    expect(isExtensionInject(['inject', 'vault', 'entry'])).toBe(true);
    expect(isExtensionInject(['inject', 'vault', 'entry', '--provider', 'extension'])).toBe(true);
    expect(isExtensionInject(['inject', 'vault', 'entry', '--provider', 'playwright'])).toBe(false);
    expect(isExtensionInject(['inject', '--help'])).toBe(false);
    expect(isExtensionInject(['inject', '-h'])).toBe(false);
    expect(isExtensionInject([
      'inject', 'vault', 'entry', '--provider-transport-stdio', '--provider', 'extension',
    ])).toBe(false);
    expect(isExtensionInject(['get', 'vault', 'entry'])).toBe(false);
  });

  it('keeps the value-free form plan distinct from credential values', () => {
    const form = JSON.stringify({
      version: 1,
      steps: [{
        fields: [{ entryFieldId: 'credential.password', selector: '#password', control: 'password' }],
        submit: { action: 'press-enter', selector: '#password' },
      }],
    });
    expect(isExtensionInject([
      'inject', 'vault', 'entry', '--form-json', form,
    ])).toBe(true);
    expect(form).not.toContain('fixture-password');
  });
});
