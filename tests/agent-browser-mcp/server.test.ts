import { describe, expect, it } from 'vitest';

import {
  parseInjectArguments,
  parseProviderCredential,
  verifyDomain,
} from '../../packages/agent-browser-mcp/src/server.js';

const form = {
  version: 1 as const,
  steps: [{
    fields: [{ entryFieldId: 'credential.password', selector: '@e23', control: 'password' as const }],
    submit: { action: 'press-enter' as const, selector: '@e23' },
  }],
};

describe('AgentBrowser MCP Inject provider boundary', () => {
  it('accepts only bounded value-free tool arguments', () => {
    expect(parseInjectArguments({ vaultId: 'vault', entryId: 'entry', form })).not.toBeNull();
    expect(parseInjectArguments({ vaultId: 'vault', entryId: 'entry' })).not.toBeNull();
    expect(parseInjectArguments({ vaultId: 'vault', entryId: 'entry', form, selector: '#password' }))
      .toBeNull();
  });

  it('accepts a verified runtime-owned map when no manual form was supplied', () => {
    const frame = JSON.stringify({
      protocol: 'palladin.inject-provider.v1', type: 'credential', provider: 'agent-browser',
      nonce: 'nonce', transactionId: 'tx', grantId: 'grant', entryId: 'entry',
      expectedDomain: 'example.com', form,
      formMap: {
        version: 1, mapVersion: 1, domain: 'example.com', loginUrl: 'https://example.com/login',
        provider: 'agent-browser', status: 'verified', fingerprint: 'a'.repeat(64), form,
      },
      values: [{ entryFieldId: 'credential.password', value: 'fixture-value-not-production' }],
    });
    expect(parseProviderCredential(frame, 'nonce', 'entry')).not.toBeNull();
    expect(parseProviderCredential(
      frame.replace('"status":"verified"', '"status":"candidate"'), 'nonce', 'entry',
    )).toBeNull();
  });

  it('binds a credential frame to nonce, entry and exact form', () => {
    const frame = JSON.stringify({
      protocol: 'palladin.inject-provider.v1', type: 'credential', provider: 'agent-browser',
      nonce: 'nonce', transactionId: 'tx', grantId: 'grant', entryId: 'entry',
      expectedDomain: 'example.com', form,
      values: [{ entryFieldId: 'credential.password', value: 'fixture-value-not-production' }],
    });
    expect(parseProviderCredential(frame, 'nonce', 'entry', form)).not.toBeNull();
    expect(parseProviderCredential(frame, 'different', 'entry', form)).toBeNull();
    expect(parseProviderCredential(
      frame.replace('"expectedDomain":"example.com"', '"expectedDomain":"example.com","extra":true'),
      'nonce', 'entry', form,
    )).toBeNull();
  });

  it('requires HTTPS and the authenticated host boundary', () => {
    expect(() => verifyDomain('https://login.example.com/path', 'example.com')).not.toThrow();
    expect(() => verifyDomain('https://deep.login.example.com/path', 'login.example.com')).not.toThrow();
    expect(() => verifyDomain('https://evil.example.com/path', 'login.example.com')).toThrow('origin mismatch');
    expect(() => verifyDomain('https://example.com/path', 'login.example.com')).toThrow('origin mismatch');
    expect(() => verifyDomain('http://example.com', 'example.com')).toThrow('insecure origin');
    expect(() => verifyDomain('https://example.net', 'example.com')).toThrow('origin mismatch');
  });
});
