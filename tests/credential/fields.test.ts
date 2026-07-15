import { describe, it, expect } from 'vitest';
import { parseSecret } from '../../src/crypto/secret.js';
import { resolveField, injectionValue, redactTotpSecrets, FieldSelectionError } from '../../src/credential/fields.js';
import { base32Encode } from '../../src/credential/totp.js';
import {
  expectSensitiveEqual,
  expectSensitiveExcludes,
  expectSensitiveMatches,
  expectSensitiveContains,
} from '../helpers/sensitive-assert.js';

const TOTP_SECRET = base32Encode(Buffer.from('12345678901234567890', 'ascii'));

function credentialV2() {
  return parseSecret(
    JSON.stringify({
      v: 2,
      username: 'alice',
      password: 'hunter2',
      url: 'https://x.com',
      notes: 'n',
      fields: [
        { id: 'f1', label: 'Recovery email', type: 'text', value: 'a@b.com' },
        { id: 'f2', label: 'PIN', type: 'concealed', value: '4242' },
        { id: 'f3', label: 'Authenticator', type: 'totp', value: JSON.stringify({ secret: TOTP_SECRET }) },
      ],
    }),
  );
}

describe('resolveField — well-known aliases', () => {
  it('resolves username/password/url/notes case-insensitively', () => {
    const s = credentialV2();
    expectSensitiveEqual(injectionValue(resolveField(s, { field: 'Username' })), 'alice', 'username field');
    expectSensitiveEqual(injectionValue(resolveField(s, { field: 'password' })), 'hunter2', 'password field');
    expectSensitiveEqual(injectionValue(resolveField(s, { field: 'URL' })), 'https://x.com', 'URL field');
    expectSensitiveEqual(injectionValue(resolveField(s, { field: 'notes' })), 'n', 'notes field');
  });

  it('resolves `value` to the primary secret for a KEY entry', () => {
    const s = parseSecret(JSON.stringify({ v: 2, value: 'sk-abc', fields: [] }));
    expectSensitiveEqual(injectionValue(resolveField(s, { field: 'value' })), 'sk-abc', 'primary key field');
  });
});

describe('resolveField — custom fields', () => {
  it('resolves a custom field by label (case-insensitive, trimmed)', () => {
    const resolved = resolveField(credentialV2(), { field: '  recovery EMAIL ' });
    expect(resolved).toMatchObject({ kind: 'value', type: 'text' });
    expectSensitiveEqual(injectionValue(resolved), 'a@b.com', 'custom text field');
  });

  it('resolves a custom field by id', () => {
    const resolved = resolveField(credentialV2(), { fieldId: 'f2' });
    expect(resolved).toMatchObject({ kind: 'value', type: 'concealed' });
    expectSensitiveEqual(injectionValue(resolved), '4242', 'concealed custom field');
  });

  it('resolves a multiline field, preserving newlines', () => {
    const s = parseSecret(JSON.stringify({ v: 2, value: 'x', fields: [{ id: 'm', label: 'SSH key', type: 'multiline', value: 'a\nb' }] }));
    const resolved = resolveField(s, { field: 'SSH key' });
    expect(resolved).toMatchObject({ kind: 'value', type: 'multiline' });
    expectSensitiveEqual(injectionValue(resolved), 'a\nb', 'multiline custom field');
  });

  it('returns a TOTP code (not the secret) for a totp field', () => {
    const resolved = resolveField(credentialV2(), { field: 'Authenticator' });
    expect(resolved.kind).toBe('totp');
    if (resolved.kind === 'totp') {
      expectSensitiveMatches(resolved.code, /^\d{6}$/, 'resolved TOTP code');
      expectSensitiveExcludes(resolved.code, TOTP_SECRET, 'resolved TOTP code');
      expect(resolved.expiresIn).toBeGreaterThan(0);
      expect(resolved.expiresIn).toBeLessThanOrEqual(30);
    }
    expectSensitiveMatches(injectionValue(resolved), /^\d{6}$/, 'TOTP injection value');
  });
});

describe('resolveField — errors', () => {
  it('reports duplicate labels with their ids', () => {
    const s = parseSecret(
      JSON.stringify({
        v: 2,
        value: 'x',
        fields: [
          { id: 'a', label: 'Token', type: 'text', value: '1' },
          { id: 'b', label: 'Token', type: 'text', value: '2' },
        ],
      }),
    );
    expect(() => resolveField(s, { field: 'Token' })).toThrowError(/--field-id/);
    try {
      resolveField(s, { field: 'Token' });
    } catch (err) {
      expect((err as FieldSelectionError).message).toContain('a');
      expect((err as FieldSelectionError).message).toContain('b');
    }
  });

  it('errors on an unknown field, listing available names', () => {
    expect(() => resolveField(credentialV2(), { field: 'nope' })).toThrowError(FieldSelectionError);
    expect(() => resolveField(credentialV2(), { fieldId: 'zzz' })).toThrowError(/no custom field/);
  });

  it('fails closed when a custom field id is duplicated', () => {
    const s = parseSecret(JSON.stringify({
      value: 'x',
      fields: [
        { id: 'same', label: 'One', type: 'text', value: '1' },
        { id: 'same', label: 'Two', type: 'text', value: '2' },
      ],
    }));
    expect(() => resolveField(s, { fieldId: 'same' })).toThrow(/duplicated/);
  });

  it('uses Unicode case folding consistently for custom labels', () => {
    const s = parseSecret(JSON.stringify({
      value: 'x',
      fields: [{ id: 'unicode', label: 'ŻÓŁĆ', type: 'text', value: 'ok' }],
    }));
    expectSensitiveEqual(injectionValue(resolveField(s, { field: 'żółć' })), 'ok', 'Unicode label field');
  });
});

describe('redactTotpSecrets', () => {
  it('replaces a totp descriptor with a fresh code, dropping the shared secret', () => {
    const plaintext = JSON.stringify({
      v: 2,
      value: 'x',
      fields: [{ id: 'f3', label: 'Authenticator', type: 'totp', value: { secret: TOTP_SECRET } }],
    });
    const redacted = redactTotpSecrets(plaintext);
    expectSensitiveExcludes(redacted, TOTP_SECRET, 'redacted credential');
    const parsed = JSON.parse(redacted);
    expectSensitiveMatches(parsed.fields[0].value.code as string, /^\d{6}$/, 'redacted TOTP code');
    expect(parsed.fields[0].value.secret).toBeUndefined();
  });

  it('leaves a blob without totp fields unchanged', () => {
    const plaintext = JSON.stringify({ v: 2, username: 'a', password: 'b', fields: [] });
    expectSensitiveEqual(redactTotpSecrets(plaintext), plaintext, 'credential without TOTP');
  });

  it('passes non-JSON plaintext through untouched', () => {
    expectSensitiveEqual(redactTotpSecrets('raw-token'), 'raw-token', 'raw credential');
  });

  it('resolves and redacts a legacy top-level otpauth URI', () => {
    const uri = `otpauth://totp/GitHub?secret=${TOTP_SECRET}`;
    const plaintext = JSON.stringify({ username: 'a', password: 'b', totp: uri });
    const parsed = parseSecret(plaintext);
    const resolved = resolveField(parsed, { field: 'totp' });
    expect(resolved.kind).toBe('totp');
    expectSensitiveExcludes(redactTotpSecrets(plaintext), TOTP_SECRET, 'legacy redacted credential');
  });

  it('withholds malformed TOTP values instead of returning the seed-like input', () => {
    const plaintext = JSON.stringify({
      value: 'x',
      fields: [{ id: 'bad', label: 'OTP', type: 'totp', value: { secret: 'must-not-leak', period: 0 } }],
    });
    const redacted = redactTotpSecrets(plaintext);
    expectSensitiveExcludes(redacted, 'must-not-leak', 'malformed TOTP redaction');
    expectSensitiveContains(redacted, 'withheld', 'malformed TOTP redaction');
  });

  it('withholds a malformed object-valued legacy TOTP seed', () => {
    const plaintext = JSON.stringify({
      username: 'a',
      password: 'b',
      totp: { secret: 'legacy-must-not-leak', period: 0 },
    });
    const redacted = redactTotpSecrets(plaintext);
    expectSensitiveExcludes(redacted, 'legacy-must-not-leak', 'legacy malformed TOTP redaction');
    expectSensitiveContains(redacted, 'withheld', 'legacy malformed TOTP redaction');
  });
});
