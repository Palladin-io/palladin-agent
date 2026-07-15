import { describe, it, expect } from 'vitest';
import { prepareScriptEnv, applyDefaultVaultId } from '../../src/exec/script-refs.js';
import { parseSecret, ScriptRef } from '../../src/crypto/secret.js';
import { base32Encode } from '../../src/credential/totp.js';
import { expectSensitiveEqual, expectSensitiveMatches } from '../helpers/sensitive-assert.js';

const ref = (over: Partial<ScriptRef> = {}): ScriptRef => ({ env: 'TOKEN', vaultId: 'v1', entryId: 'e1', field: null, ...over });

describe('applyDefaultVaultId', () => {
  it('fills a missing ref vaultId with the script entry\'s vault, leaving explicit ones untouched', () => {
    const refs = applyDefaultVaultId(
      [ref({ env: 'A', vaultId: null }), ref({ env: 'B', vaultId: 'other' })],
      'script-vault',
    );
    expect(refs[0]!.vaultId).toBe('script-vault');
    expect(refs[1]!.vaultId).toBe('other');
  });
});

describe('prepareScriptEnv', () => {
  it('delivers each ref and builds the environment (primary secret by default)', async () => {
    const prepared = await prepareScriptEnv([ref({ env: 'GH_TOKEN' })], async () => ({
      ok: true,
      secret: parseSecret(JSON.stringify({ value: 'gh-secret' })),
    }));
    expectSensitiveEqual(
      prepared,
      { ok: true, env: { GH_TOKEN: 'gh-secret' }, secretValues: ['gh-secret'] },
      'prepared script credential environment',
    );
  });

  it('resolves a named ref field, mapping a totp field to its code', async () => {
    const totp = JSON.stringify({ secret: base32Encode(Buffer.from('12345678901234567890', 'ascii')) });
    const prepared = await prepareScriptEnv([ref({ env: 'OTP', field: 'Authy' })], async () => ({
      ok: true,
      secret: parseSecret(JSON.stringify({ v: 2, value: 'x', fields: [{ id: 'a', label: 'Authy', type: 'totp', value: totp }] })),
    }));
    expect(prepared.ok).toBe(true);
    if (prepared.ok) {
      expectSensitiveMatches(prepared.env.OTP, /^\d{6}$/, 'prepared script TOTP');
    }
  });

  it('aborts when a ref is missing its vaultId (nothing runs)', async () => {
    const prepared = await prepareScriptEnv([ref({ vaultId: null })], async () => {
      throw new Error('resolver must not be called');
    });
    expect(prepared).toMatchObject({ ok: false });
    if (!prepared.ok) expect(prepared.message).toMatch(/missing its vaultId/);
  });

  it('rejects an invalid env var name', async () => {
    const prepared = await prepareScriptEnv([ref({ env: '1BAD-NAME' })], async () => ({ ok: true, secret: parseSecret('x') }));
    expect(prepared).toMatchObject({ ok: false });
    if (!prepared.ok) expect(prepared.message).toMatch(/invalid env var name/);
  });

  it('surfaces a non-granted ref with a request hint', async () => {
    const prepared = await prepareScriptEnv([ref({ env: 'GH_TOKEN', vaultId: 'v9', entryId: 'e9' })], async () => ({
      ok: false,
      message: 'Access is pending user approval.',
    }));
    expect(prepared).toMatchObject({ ok: false });
    if (!prepared.ok) {
      expect(prepared.message).toContain('pending user approval');
      expect(prepared.message).toContain('palladin get v9 e9');
    }
  });
});
