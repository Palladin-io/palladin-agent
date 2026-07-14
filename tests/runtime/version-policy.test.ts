import {
  generateKeyPairSync,
  sign,
  type KeyObject,
} from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import {
  VersionPolicyError,
  canonicalizeVersionPolicyEnvelope,
  canonicalizeVersionPolicyPayload,
  loadSystemVerifiedArtifactBinding,
  parseAndVerifyVersionPolicy,
  parseAndVerifyHistoricalVersionPolicy,
  selectArtifact,
  verifyArtifactIntegrityBinding,
  type VersionPolicyEnvelope,
  type VersionPolicyPayload,
} from '../../src/runtime/version-policy.js';

const source = 'https://releases.palladin.io/agent/version-policy.json';
const sourceSha = '1234567890abcdef1234567890abcdef12345678';
const now = new Date('2026-07-14T12:00:00Z');

function fixture(): { envelope: VersionPolicyEnvelope; publicKey: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const payload: VersionPolicyPayload = {
    schemaVersion: 1,
    sequence: 7,
    source,
    issuedAt: '2026-07-14T11:55:00Z',
    expiresAt: '2026-07-21T11:55:00Z',
    minimumVersion: '0.1.0',
    recommendedVersion: '0.1.2',
    blockedVersions: ['0.1.1', '0.1.3'],
    artifacts: [
      {
        packageName: '@palladin/runtime-darwin-arm64',
        version: '0.1.2',
        sourceSha,
        executableSha256: '11'.repeat(32),
        workerExecutableSha256: '33'.repeat(32),
      },
      {
        packageName: '@palladin/runtime-win32-x64',
        version: '0.1.2',
        sourceSha,
        executableSha256: '22'.repeat(32),
        workerExecutableSha256: '44'.repeat(32),
        authenticodePublisher: 'CN=Palladin Test Signing',
        authenticodeThumbprint: 'AB'.repeat(20),
      },
    ],
  };
  const signature = sign(
    null,
    Buffer.from(canonicalizeVersionPolicyPayload(payload)),
    privateKey,
  ).toString('base64');
  const rawPublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return {
    envelope: { signed: payload, signature },
    publicKey: rawPublicKey.toString('base64'),
    privateKey,
  };
}

function encode(envelope: VersionPolicyEnvelope): Buffer {
  return Buffer.from(canonicalizeVersionPolicyEnvelope(envelope));
}

function response(bytes: Buffer, overrides: { url?: string; contentType?: string } = {}): Response {
  const result = new Response(bytes, {
    status: 200,
    headers: {
      'content-type': overrides.contentType ?? 'application/json',
      'content-length': String(bytes.length),
    },
  });
  Object.defineProperty(result, 'url', { value: overrides.url ?? source });
  return result;
}

describe('signed public version policy', () => {
  it('verifies canonical Ed25519 policy and returns the exact artifact trust binding', async () => {
    const { envelope, publicKey } = fixture();
    const fetchPolicy = vi.fn(async () => response(encode(envelope)));
    const binding = await loadSystemVerifiedArtifactBinding({
      packageName: '@palladin/runtime-win32-x64',
      version: '0.1.2',
      executableSha256: '22'.repeat(32),
      sourceSha,
    }, { fetch: fetchPolicy, publicKeyBase64: publicKey, source, now });

    expect(binding).toMatchObject({
      packageName: '@palladin/runtime-win32-x64',
      version: '0.1.2',
      executableSha256: '22'.repeat(32),
      workerExecutableSha256: '44'.repeat(32),
      authenticodePublisher: 'CN=Palladin Test Signing',
      authenticodeThumbprint: 'AB'.repeat(20),
      policySequence: 7,
      sourceSha,
    });
    expect(fetchPolicy).toHaveBeenCalledWith(source, expect.objectContaining({
      method: 'GET',
      redirect: 'error',
      cache: 'no-store',
      credentials: 'omit',
    }));
  });

  it('rejects tampering, an untrusted key, unknown fields, and non-canonical sets', () => {
    const { envelope, publicKey } = fixture();
    const options = { publicKeyBase64: publicKey, source, now };
    expect(parseAndVerifyVersionPolicy(encode(envelope), options).signed.sequence).toBe(7);

    const tampered = structuredClone(envelope);
    tampered.signed.minimumVersion = '0.1.2';
    expect(() => parseAndVerifyVersionPolicy(encode(tampered), options))
      .toThrow(VersionPolicyError);

    const other = fixture();
    expect(() => parseAndVerifyVersionPolicy(encode(envelope), {
      ...options,
      publicKeyBase64: other.publicKey,
    })).toThrow(VersionPolicyError);

    const unknown = JSON.parse(JSON.stringify(envelope)) as Record<string, unknown>;
    unknown.attacker = true;
    expect(() => parseAndVerifyVersionPolicy(Buffer.from(JSON.stringify(unknown)), options))
      .toThrow(VersionPolicyError);

    const duplicateKey = encode(envelope).toString('utf8').replace(
      '{"signature":',
      '{"signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","signature":',
    );
    expect(() => parseAndVerifyVersionPolicy(Buffer.from(duplicateKey), options))
      .toThrow(VersionPolicyError);

    const unsorted = structuredClone(envelope);
    unsorted.signed.blockedVersions.reverse();
    expect(() => canonicalizeVersionPolicyPayload(unsorted.signed)).toThrow(VersionPolicyError);

    const unicodePublisher = structuredClone(envelope);
    unicodePublisher.signed.artifacts[1]!.authenticodePublisher = 'CN=Zażółć';
    expect(() => canonicalizeVersionPolicyPayload(unicodePublisher.signed))
      .toThrow(VersionPolicyError);
  });

  it('fails closed for expired/future policy, wrong source/source SHA, redirects, and oversized data', async () => {
    const { envelope, publicKey } = fixture();
    for (const invalidNow of [
      new Date('2026-07-01T00:00:00Z'),
      new Date('2026-07-22T00:00:00Z'),
    ]) {
      expect(() => parseAndVerifyVersionPolicy(encode(envelope), {
        publicKeyBase64: publicKey,
        source,
        now: invalidNow,
        expectedSourceSha: sourceSha,
      })).toThrow(VersionPolicyError);
    }
    expect(() => parseAndVerifyVersionPolicy(encode(envelope), {
      publicKeyBase64: publicKey,
      source: 'https://attacker.invalid/policy.json',
      now,
    })).toThrow(VersionPolicyError);
    await expect(loadSystemVerifiedArtifactBinding({
      packageName: '@palladin/runtime-darwin-arm64',
      version: '0.1.2',
      executableSha256: '11'.repeat(32),
      sourceSha,
    }, {
      fetch: async () => response(encode(envelope), { url: 'https://attacker.invalid/policy.json' }),
      publicKeyBase64: publicKey,
      source,
      now,
    })).rejects.toThrow(VersionPolicyError);

    let cancelled = false;
    const oversized = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(40 * 1024));
        controller.enqueue(new Uint8Array(40 * 1024));
      },
      cancel() { cancelled = true; },
    });
    const oversizedResponse = new Response(oversized, {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    Object.defineProperty(oversizedResponse, 'url', { value: source });
    await expect(loadSystemVerifiedArtifactBinding({
      packageName: '@palladin/runtime-darwin-arm64',
      version: '0.1.2',
      executableSha256: '11'.repeat(32),
      sourceSha,
    }, {
      fetch: async () => oversizedResponse,
      publicKeyBase64: publicKey,
      source,
      now,
    })).rejects.toThrow(VersionPolicyError);
    expect(cancelled).toBe(true);
  });

  it('blocks revoked and downgraded versions and refuses an unsigned artifact/hash substitution', async () => {
    const { envelope, publicKey } = fixture();
    expect(() => selectArtifact(
      envelope.signed,
      '@palladin/runtime-darwin-arm64',
      '0.1.1',
    )).toThrow('blocked by signed policy');
    expect(() => selectArtifact(
      envelope.signed,
      '@palladin/runtime-darwin-arm64',
      '0.0.9',
    )).toThrow('blocked by signed policy');
    expect(() => selectArtifact(
      envelope.signed,
      '@palladin/runtime-linux-x64-gnu',
      '0.1.2',
    )).toThrow(VersionPolicyError);

    await expect(loadSystemVerifiedArtifactBinding({
      packageName: '@palladin/runtime-darwin-arm64',
      version: '0.1.2',
      executableSha256: 'ff'.repeat(32),
      sourceSha,
    }, {
      fetch: async () => response(encode(envelope)),
      publicKeyBase64: publicKey,
      source,
      now,
    })).rejects.toThrow(VersionPolicyError);
  });

  it('never falls back below a valid higher emergency policy', async () => {
    const current = fixture();
    const older = structuredClone(current.envelope);
    older.signed.sequence = 6;
    older.signature = sign(
      null,
      Buffer.from(canonicalizeVersionPolicyPayload(older.signed)),
      current.privateKey,
    ).toString('base64');
    current.envelope.signed.blockedVersions = ['0.1.1', '0.1.2', '0.1.3'];
    current.envelope.signed.recommendedVersion = '0.1.0';
    current.envelope.signature = sign(
      null,
      Buffer.from(canonicalizeVersionPolicyPayload(current.envelope.signed)),
      current.privateKey,
    ).toString('base64');
    const binding = await loadSystemVerifiedArtifactBinding({
      packageName: '@palladin/runtime-darwin-arm64',
      version: '0.1.2',
      executableSha256: '11'.repeat(32),
      sourceSha,
    }, {
      fetch: async () => response(encode(current.envelope)),
      publicKeyBase64: current.publicKey,
      source,
      now,
      offlineEnvelopes: [encode(older)],
    });
    expect(binding.policySequence).toBe(7);
    expect(binding.runtimeAllowed).toBe(false);

    const omitted = structuredClone(current.envelope);
    omitted.signed.artifacts = [omitted.signed.artifacts[1] as typeof omitted.signed.artifacts[number]];
    omitted.signature = sign(
      null,
      Buffer.from(canonicalizeVersionPolicyPayload(omitted.signed)),
      current.privateKey,
    ).toString('base64');
    await expect(loadSystemVerifiedArtifactBinding({
      packageName: '@palladin/runtime-darwin-arm64',
      version: '0.1.2',
      executableSha256: '11'.repeat(32),
      sourceSha,
    }, {
      fetch: async () => response(encode(omitted)),
      publicKeyBase64: current.publicKey,
      source,
      now,
      offlineEnvelopes: [encode(older)],
    })).rejects.toThrow(VersionPolicyError);
  });

  it('diagnostic artifact verification accepts an expired bundle but never skips its signature/binding', () => {
    const { envelope, publicKey } = fixture();
    const binding = verifyArtifactIntegrityBinding(encode(envelope), {
      packageName: '@palladin/runtime-darwin-arm64',
      version: '0.1.2',
      executableSha256: '11'.repeat(32),
      sourceSha,
    }, { publicKeyBase64: publicKey, source });
    expect(binding.executableSha256).toBe('11'.repeat(32));
    expect(binding.workerExecutableSha256).toBe('33'.repeat(32));
    const tampered = structuredClone(envelope);
    tampered.signed.artifacts[0]!.executableSha256 = 'ff'.repeat(32);
    expect(() => verifyArtifactIntegrityBinding(encode(tampered), {
      packageName: '@palladin/runtime-darwin-arm64',
      version: '0.1.2',
      executableSha256: 'ff'.repeat(32),
      sourceSha,
    }, { publicKeyBase64: publicKey, source })).toThrow(VersionPolicyError);
  });

  it('keeps sequence and semver components within the cross-language safe integer range', () => {
    const { envelope, publicKey } = fixture();
    const oversizedSequence = structuredClone(envelope) as unknown as Record<string, unknown>;
    (oversizedSequence.signed as Record<string, unknown>).sequence = Number.MAX_SAFE_INTEGER + 1;
    expect(() => parseAndVerifyVersionPolicy(Buffer.from(JSON.stringify(oversizedSequence)), {
      publicKeyBase64: publicKey,
      source,
      now,
    })).toThrow(VersionPolicyError);
    const oversizedVersion = structuredClone(envelope);
    oversizedVersion.signed.minimumVersion = '9007199254740992.0.0';
    expect(() => canonicalizeVersionPolicyPayload(oversizedVersion.signed))
      .toThrow(VersionPolicyError);
  });

  it('allows owner tooling to advance an expired signed sequence without weakening runtime freshness', () => {
    const { envelope, publicKey } = fixture();
    expect(() => parseAndVerifyVersionPolicy(encode(envelope), {
      publicKeyBase64: publicKey,
      source,
      now: new Date('2026-07-22T00:00:00Z'),
    })).toThrow(VersionPolicyError);
    expect(parseAndVerifyHistoricalVersionPolicy(encode(envelope), {
      publicKeyBase64: publicKey,
      source,
    }).signed.sequence).toBe(7);
  });

  it('uses the highest still-valid signed offline candidate and rejects an expired cache', async () => {
    const current = fixture();
    const older = structuredClone(current.envelope);
    older.signed.sequence = 6;
    older.signature = sign(
      null,
      Buffer.from(canonicalizeVersionPolicyPayload(older.signed)),
      current.privateKey,
    ).toString('base64');
    const request = {
      packageName: '@palladin/runtime-darwin-arm64',
      version: '0.1.2',
      executableSha256: '11'.repeat(32),
      sourceSha,
    };
    const binding = await loadSystemVerifiedArtifactBinding(request, {
      fetch: async () => { throw new Error('offline'); },
      publicKeyBase64: current.publicKey,
      source,
      now,
      offlineEnvelopes: [encode(older), encode(current.envelope)],
    });
    expect(binding.policySequence).toBe(7);

    await expect(loadSystemVerifiedArtifactBinding(request, {
      fetch: async () => { throw new Error('offline'); },
      publicKeyBase64: current.publicKey,
      source,
      now: new Date('2026-07-22T00:00:00Z'),
      offlineEnvelopes: [encode(current.envelope)],
    })).rejects.toThrow(VersionPolicyError);
  });

  it('rejects the unconfigured all-zero build trust anchor', () => {
    const { envelope } = fixture();
    expect(() => parseAndVerifyVersionPolicy(encode(envelope), {
      publicKeyBase64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      source,
      now,
    })).toThrow(VersionPolicyError);
  });
});
