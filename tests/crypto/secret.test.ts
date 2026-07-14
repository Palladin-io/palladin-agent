import { describe, it, expect } from 'vitest';
import { parseSecret, parseTotpParams, envFieldKey } from '../../src/crypto/secret.js';
import { expectSensitiveEqual, expectSensitiveExcludes } from '../helpers/sensitive-assert.js';

describe('parseSecret', () => {
  it('parses a CREDENTIAL payload', () => {
    const s = parseSecret(JSON.stringify({ username: 'alice', password: 'hunter2', url: 'https://x.com', notes: 'n' }));
    expectSensitiveEqual(s.username, 'alice', 'credential username');
    expectSensitiveEqual(s.password, 'hunter2', 'credential password');
    expectSensitiveEqual(s.url, 'https://x.com', 'credential URL');
    expectSensitiveEqual(
      { username: s.fields.username, password: s.fields.password },
      { username: 'alice', password: 'hunter2' },
      'credential fields',
    );
  });

  it('parses a KEY payload (value, no username)', () => {
    const s = parseSecret(JSON.stringify({ value: 'sk-abc123', notes: 'api key' }));
    expect(s.username).toBeNull();
    expectSensitiveEqual(s.password, 'sk-abc123', 'key primary value');
    expectSensitiveEqual(s.fields.value, 'sk-abc123', 'key injection value');
  });

  it('falls back to raw plaintext when not JSON', () => {
    const s = parseSecret('raw-secret-token');
    expect(s.username).toBeNull();
    expectSensitiveEqual(s.password, 'raw-secret-token', 'raw primary value');
    expectSensitiveEqual(s.fields.value, 'raw-secret-token', 'raw injection value');
  });

  it('falls back when JSON is a non-object', () => {
    const s = parseSecret('"just-a-string"');
    expectSensitiveEqual(s.password, '"just-a-string"', 'JSON scalar fallback');
  });

  it('only keeps string fields', () => {
    const s = parseSecret(JSON.stringify({ value: 'v', count: 5, nested: { a: 1 } }));
    expectSensitiveEqual(s.fields, { value: 'v' }, 'filtered credential fields');
  });

  it('treats a v1 blob (no `v`) as having no custom fields or script', () => {
    const s = parseSecret(JSON.stringify({ username: 'a', password: 'b' }));
    expect(s.customFields).toEqual([]);
    expect(s.script).toBeNull();
  });

  it('keeps a legacy top-level TOTP URI out of the generic injection map', () => {
    const uri = 'otpauth://totp/GitHub?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const s = parseSecret(JSON.stringify({ username: 'a', password: 'b', totp: uri }));
    expectSensitiveEqual(s.legacyTotp, uri, 'legacy TOTP descriptor');
    expect(s.fields.totp).toBeUndefined();
  });
});

describe('parseSecret — v2 custom fields', () => {
  it('parses fields[] alongside well-known keys', () => {
    const s = parseSecret(
      JSON.stringify({
        v: 2,
        username: 'alice',
        password: 'pw',
        fields: [
          { id: 'f1', label: 'Recovery email', type: 'text', value: 'a@b.com' },
          { id: 'f2', label: 'PIN', type: 'concealed', value: '4242' },
        ],
      }),
    );
    expect(s.customFields).toHaveLength(2);
    expect(s.customFields[0]).toMatchObject({ id: 'f1', label: 'Recovery email', type: 'text' });
  });

  it('exposes non-totp custom fields for env injection under a sanitised key', () => {
    const s = parseSecret(
      JSON.stringify({ v: 2, value: 'x', fields: [{ id: 'f1', label: 'Recovery email', type: 'text', value: 'a@b.com' }] }),
    );
    expectSensitiveEqual(s.fields.RECOVERY_EMAIL, 'a@b.com', 'custom credential field');
  });

  it('parses a multiline field and exposes it for env injection like text', () => {
    const s = parseSecret(
      JSON.stringify({ v: 2, value: 'x', fields: [{ id: 'm1', label: 'SSH key', type: 'multiline', value: 'line1\nline2' }] }),
    );
    expectSensitiveEqual(s.customFields[0]?.value, 'line1\nline2', 'multiline custom field');
    expect(s.customFields[0]?.type).toBe('multiline');
    expectSensitiveEqual(s.fields.SSH_KEY, 'line1\nline2', 'multiline injection field');
  });

  it('carries the agentVisible flag when set, omits it otherwise', () => {
    const s = parseSecret(
      JSON.stringify({
        v: 2,
        value: 'x',
        fields: [
          { id: 'a', label: 'Public note', type: 'text', value: 'hi', agentVisible: true },
          { id: 'b', label: 'Private', type: 'text', value: 'secret' },
        ],
      }),
    );
    expect(s.customFields[0]!.agentVisible).toBe(true);
    expect(s.customFields[1]!.agentVisible).toBeUndefined();
  });

  it('never puts a totp shared secret into the env-injection map', () => {
    const s = parseSecret(
      JSON.stringify({ v: 2, value: 'x', fields: [{ id: 'f3', label: 'Authy', type: 'totp', value: JSON.stringify({ secret: 'JBSWY3DP' }) }] }),
    );
    expectSensitiveExcludes(Object.values(s.fields).join('\n'), 'JBSWY3DP', 'TOTP injection fields');
    expect(s.customFields[0]!.type).toBe('totp');
  });

  it('normalises a totp value written as a JSON object into a descriptor string', () => {
    const s = parseSecret(
      JSON.stringify({ v: 2, value: 'x', fields: [{ id: 'f3', label: 'Authy', type: 'totp', value: { secret: 'JBSWY3DP', period: 60 } }] }),
    );
    const params = parseTotpParams(s.customFields[0]!.value);
    expectSensitiveEqual(params?.secret, 'JBSWY3DP', 'normalized TOTP seed');
    expect(params?.period).toBe(60);
  });

  it('ignores unknown field types and malformed field entries (forward-compat)', () => {
    const s = parseSecret(
      JSON.stringify({
        v: 2,
        value: 'x',
        fields: [
          { id: 'f1', label: 'Future', type: 'date', value: '2026-01-01' },
          { id: 'f2', label: 'Keep', type: 'text', value: 'ok' },
          { label: 'no-id', type: 'text', value: 'x' },
        ],
      }),
    );
    expect(s.customFields).toHaveLength(1);
    expect(s.customFields[0]!.label).toBe('Keep');
  });
});

describe('parseSecret — Script entries', () => {
  it('parses a script payload with refs', () => {
    const s = parseSecret(
      JSON.stringify({
        v: 2,
        script: '#!/usr/bin/env bash\ncurl -H "Authorization: Bearer $GITHUB_TOKEN" ...',
        interpreter: 'bash',
        notes: 'deploy',
        refs: [{ env: 'GITHUB_TOKEN', vaultId: 'v1', entryId: 'e1', field: 'value' }],
      }),
    );
    expect(s.script).not.toBeNull();
    expect(s.script!.interpreter).toBe('bash');
    expect(s.script!.refs).toEqual([{ env: 'GITHUB_TOKEN', vaultId: 'v1', entryId: 'e1', field: 'value' }]);
    // Script structural keys are never surfaced as injectable well-known fields.
    expect(s.fields.script).toBeUndefined();
    expect(s.fields.interpreter).toBeUndefined();
  });

  it('accepts `placeholder` as a legacy alias for a ref env name', () => {
    const s = parseSecret(JSON.stringify({
      v: 2,
      script: 'echo hi',
      interpreter: 'sh',
      refs: [{ placeholder: 'TOKEN', entryId: 'e1' }],
    }));
    expect(s.script!.refs).toEqual([{ env: 'TOKEN', vaultId: null, entryId: 'e1', field: null }]);
  });

  it('fails closed when any Script credential reference is malformed', () => {
    expect(() => parseSecret(JSON.stringify({
      v: 2,
      script: 'echo hi',
      interpreter: 'sh',
      refs: [{ placeholder: 'TOKEN', entryId: 'e1' }, { env: 'BAD' }],
    }))).toThrow(/malformed credential reference/);
    expect(() => parseSecret(JSON.stringify({
      v: 2,
      script: 'echo hi',
      interpreter: 'sh',
      refs: null,
    }))).toThrow(/malformed credential references/);
  });

  it('is not a script when interpreter is absent', () => {
    const s = parseSecret(JSON.stringify({ v: 2, script: 'echo hi' }));
    expect(s.script).toBeNull();
  });
});

describe('envFieldKey', () => {
  it('sanitises labels to upper-snake env fragments', () => {
    expect(envFieldKey('Recovery email')).toBe('RECOVERY_EMAIL');
    expect(envFieldKey('  API-Key!! ')).toBe('API_KEY');
  });
});
