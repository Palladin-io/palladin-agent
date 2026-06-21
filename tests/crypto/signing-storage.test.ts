import { mkdtempSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mirror the keychain mock pattern from secure-storage.test.ts so storage is exercised via the file
// tier (keychain throwing) without touching the real OS keychain.
const { mockGetPassword, mockSetPassword, mockDeletePassword, MockEntry } = vi.hoisted(() => {
  const mockGetPassword    = vi.fn<() => string | null>();
  const mockSetPassword    = vi.fn<() => void>();
  const mockDeletePassword = vi.fn<() => void>();
  const MockEntry = vi.fn().mockImplementation(function () {
    return { getPassword: mockGetPassword, setPassword: mockSetPassword, deletePassword: mockDeletePassword };
  });
  return { mockGetPassword, mockSetPassword, mockDeletePassword, MockEntry };
});

vi.mock('@napi-rs/keyring', () => ({ Entry: MockEntry }));

import { ensureSigningKeypair, loadSigningKeypair, signingPublicKeyBase64 } from '../../src/crypto/signing.js';
import { hasKey } from '../../src/crypto/secure-storage.js';

function makePaths(root: string) {
  return {
    root,
    privateKey: join(root, 'agent.key'),
    publicKey:  join(root, 'agent.pub'),
    config:     join(root, 'config.json'),
  };
}

describe('signing key storage (file tier)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cv-sign-'));
    vi.resetAllMocks();
    // Force the file tier: keychain set/get unavailable.
    mockSetPassword.mockImplementation(() => { throw new Error('no keychain'); });
    mockGetPassword.mockReturnValue(null);
  });

  afterEach(() => rmSync(tmpDir, { recursive: true, force: true }));

  it('stores the signing key in a SEPARATE file from the box key', async () => {
    const paths = makePaths(tmpDir);
    await ensureSigningKeypair('default', paths);

    expect(existsSync(join(tmpDir, 'signing.key'))).toBe(true);
    // The box key file ('agent.key') must NOT be created by the signing flow.
    expect(existsSync(join(tmpDir, 'agent.key'))).toBe(false);
  });

  it('ensureSigningKeypair is idempotent — loads the same key on the second call', async () => {
    const paths = makePaths(tmpDir);
    const first = await ensureSigningKeypair('default', paths);
    const second = await ensureSigningKeypair('default', paths);
    expect(signingPublicKeyBase64(second)).toBe(signingPublicKeyBase64(first));
  });

  it('loadSigningKeypair reconstructs the public key from the stored secret key', async () => {
    const paths = makePaths(tmpDir);
    const created = await ensureSigningKeypair('default', paths);
    const loaded = await loadSigningKeypair('default', paths);
    expect(Buffer.from(loaded.publicKey)).toEqual(Buffer.from(created.publicKey));
    expect(loaded.privateKey).toHaveLength(64);
  });

  it('hasKey reports the signing slot present after enrollment, box slot absent', async () => {
    const paths = makePaths(tmpDir);
    await ensureSigningKeypair('default', paths);
    expect(await hasKey('default', paths, 'signing')).toBe(true);
    expect(await hasKey('default', paths, 'box')).toBe(false);
  });
});
