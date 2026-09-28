import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  VersionPolicyError, canonicalizeVersionPolicyEnvelope, canonicalizeVersionPolicyPayload,
  loadBundledVerifiedArtifactBinding, parseAndVerifyVersionPolicy, verifyArtifactIntegrityBinding,
  type VersionPolicyPayload,
} from '../../src/runtime/version-policy.js';

const sourceSha = '1234567890abcdef1234567890abcdef12345678';
const request = {
  packageName: '@palladin/runtime-linux-x64-gnu', version: '0.0.1', sourceSha,
  executableSha256: '11'.repeat(32),
};
function fixture() {
  const keys = generateKeyPairSync('ed25519');
  const payload: VersionPolicyPayload = {
    artifacts: [{ ...request, workerExecutableSha256: '22'.repeat(32) }], schemaVersion: 2,
  };
  const signature = sign(null, Buffer.from(canonicalizeVersionPolicyPayload(payload)), keys.privateKey)
    .toString('base64');
  return {
    bytes: Buffer.from(canonicalizeVersionPolicyEnvelope({ signed: payload, signature })),
    publicKeyBase64: keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64'),
  };
}

describe('immutable signed release manifest', () => {
  it('verifies the exact release without a network request or an expiration date', () => {
    const publicPolicyFetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network disabled'));
    const { bytes, publicKeyBase64 } = fixture();
    vi.useFakeTimers();
    try {
      for (const date of ['2026-01-01', '2099-01-01']) {
        vi.setSystemTime(new Date(date));
        expect(verifyArtifactIntegrityBinding(bytes, request, { publicKeyBase64 }))
          .toMatchObject({ ...request, workerExecutableSha256: '22'.repeat(32) });
      }
      expect(publicPolicyFetch).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); publicPolicyFetch.mockRestore(); }
  });

  it('loads the configured release bundle offline even years after release', async () => {
    const { bytes, publicKeyBase64 } = fixture();
    const publicPolicyFetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network disabled'));
    vi.doMock('../../src/runtime/version-policy-build.js', () => ({
      VERSION_POLICY_PUBLIC_KEY_BASE64: publicKeyBase64,
      RUNTIME_SOURCE_SHA: sourceSha,
      VERSION_POLICY_BUNDLE_BASE64: bytes.toString('base64'),
    }));
    vi.resetModules();
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2099-01-01'));
      const configured = await import('../../src/runtime/version-policy.js');
      expect(configured.loadBundledVerifiedArtifactBinding(request))
        .toMatchObject({ ...request, workerExecutableSha256: '22'.repeat(32) });
      expect(publicPolicyFetch).not.toHaveBeenCalled();
    } finally {
      vi.doUnmock('../../src/runtime/version-policy-build.js');
      vi.resetModules();
      vi.useRealTimers();
      publicPolicyFetch.mockRestore();
    }
  });

  it('rejects wrong keys, tampering and noncanonical or legacy policy fields', () => {
    const { bytes, publicKeyBase64 } = fixture();
    expect(() => parseAndVerifyVersionPolicy(bytes, fixture())).toThrow(VersionPolicyError);
    const changed = bytes.toString().replace('11'.repeat(32), '33'.repeat(32));
    expect(() => parseAndVerifyVersionPolicy(Buffer.from(changed), { publicKeyBase64 }))
      .toThrow(VersionPolicyError);
    const value = JSON.parse(bytes.toString()) as { signed: Record<string, unknown> };
    value.signed.expiresAt = '2099-01-01T00:00:00Z';
    expect(() => parseAndVerifyVersionPolicy(Buffer.from(JSON.stringify(value)), { publicKeyBase64 }))
      .toThrow(VersionPolicyError);
    expect(() => parseAndVerifyVersionPolicy(Buffer.concat([bytes, Buffer.from('\n')]), { publicKeyBase64 }))
      .toThrow(VersionPolicyError);
  });

  it.each([
    { executableSha256: 'ff'.repeat(32) }, { sourceSha: 'ab'.repeat(20) },
    { version: '0.0.2' }, { packageName: '@palladin/runtime-linux-arm64-gnu' },
  ])('rejects artifact substitution: %j', (changed) => {
    const { bytes, publicKeyBase64 } = fixture();
    expect(() => verifyArtifactIntegrityBinding(bytes, { ...request, ...changed }, { publicKeyBase64 }))
      .toThrow(VersionPolicyError);
  });

  it('fails closed when the release bundle is not configured', () => {
    expect(() => loadBundledVerifiedArtifactBinding(request)).toThrow(VersionPolicyError);
  });
});
