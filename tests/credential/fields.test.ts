import { describe, it, expect } from 'vitest';
import { parseSecret } from '../../src/crypto/secret.js';
import { resolveField, injectionValue, redactTotpSecrets, FieldSelectionError } from '../../src/credential/fields.js';
import { base32Encode } from '../../src/credential/totp.js';

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
    expect(resolveField(s, { field: 'Username' })).toMatchObject({ kind: 'value', value: 'alice' });
    expect(resolveField(s, { field: 'password' })).toMatchObject({ kind: 'value', value: 'hunter2' });
    expect(resolveField(s, { field: 'URL' })).toMatchObject({ kind: 'value', value: 'https://x.com' });
    expect(resolveField(s, { field: 'notes' })).toMatchObject({ kind: 'value', value: 'n' });
  });

  it('resolves `value` to the primary secret for a KEY entry', () => {
    const s = parseSecret(JSON.stringify({ v: 2, value: 'sk-abc', fields: [] }));
    expect(resolveField(s, { field: 'value' })).toMatchObject({ kind: 'value', value: 'sk-abc' });
  });
});

describe('resolveField — custom fields', () => {
  it('resolves a custom field by label (case-insensitive, trimmed)', () => {
    expect(resolveField(credentialV2(), { field: '  recovery EMAIL ' })).toMatchObject({ kind: 'value', type: 'text', value: 'a@b.com' });
  });

  it('resolves a custom field by id', () => {
    expect(resolveField(credentialV2(), { fieldId: 'f2' })).toMatchObject({ kind: 'value', type: 'concealed', value: '4242' });
  });

  it('resolves a multiline field, preserving newlines', () => {
    const s = parseSecret(JSON.stringify({ v: 2, value: 'x', fields: [{ id: 'm', label: 'SSH key', type: 'multiline', value: 'a\nb' }] }));
    expect(resolveField(s, { field: 'SSH key' })).toMatchObject({ kind: 'value', type: 'multiline', value: 'a\nb' });
  });

  it('returns a TOTP code (not the secret) for a totp field', () => {
    const resolved = resolveField(credentialV2(), { field: 'Authenticator' });
    expect(resolved.kind).toBe('totp');
    if (resolved.kind === 'totp') {
      expect(resolved.code).toMatch(/^\d{6}$/);
      expect(resolved.code).not.toContain(TOTP_SECRET);
      expect(resolved.expiresIn).toBeGreaterThan(0);
      expect(resolved.expiresIn).toBeLessThanOrEqual(30);
    }
    expect(injectionValue(resolved)).toMatch(/^\d{6}$/);
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
    expect(resolveField(s, { field: 'żółć' })).toMatchObject({ value: 'ok' });
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
    expect(redacted).not.toContain(TOTP_SECRET);
    const parsed = JSON.parse(redacted);
    expect(parsed.fields[0].value.code).toMatch(/^\d{6}$/);
    expect(parsed.fields[0].value.secret).toBeUndefined();
  });

  it('leaves a blob without totp fields unchanged', () => {
    const plaintext = JSON.stringify({ v: 2, username: 'a', password: 'b', fields: [] });
    expect(redactTotpSecrets(plaintext)).toBe(plaintext);
  });

  it('passes non-JSON plaintext through untouched', () => {
    expect(redactTotpSecrets('raw-token')).toBe('raw-token');
  });

  it('resolves and redacts a legacy top-level otpauth URI', () => {
    const uri = `otpauth://totp/GitHub?secret=${TOTP_SECRET}`;
    const plaintext = JSON.stringify({ username: 'a', password: 'b', totp: uri });
    const parsed = parseSecret(plaintext);
    const resolved = resolveField(parsed, { field: 'totp' });
    expect(resolved.kind).toBe('totp');
    expect(redactTotpSecrets(plaintext)).not.toContain(TOTP_SECRET);
  });

  it('withholds malformed TOTP values instead of returning the seed-like input', () => {
    const plaintext = JSON.stringify({
      value: 'x',
      fields: [{ id: 'bad', label: 'OTP', type: 'totp', value: { secret: 'must-not-leak', period: 0 } }],
    });
    const redacted = redactTotpSecrets(plaintext);
    expect(redacted).not.toContain('must-not-leak');
    expect(redacted).toContain('withheld');
  });

  it('withholds a malformed object-valued legacy TOTP seed', () => {
    const plaintext = JSON.stringify({
      username: 'a',
      password: 'b',
      totp: { secret: 'legacy-must-not-leak', period: 0 },
    });
    const redacted = redactTotpSecrets(plaintext);
    expect(redacted).not.toContain('legacy-must-not-leak');
    expect(redacted).toContain('withheld');
  });
});
