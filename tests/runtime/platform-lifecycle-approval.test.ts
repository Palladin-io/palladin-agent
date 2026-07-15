import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { canonicalJson } from '../../security/lifecycle/report.mjs';
import {
  createOperatorApprovalPayload,
  verifyOperatorApproval,
} from '../../security/lifecycle/operator-approval.mjs';

const sourceSha = 'a'.repeat(40);
const approvedAt = '2026-07-15T10:02:00.000Z';
const now = new Date('2026-07-15T10:03:00.000Z');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const report = {
  sourceSha,
  contentSha256: 'b'.repeat(64),
  releaseDecision: 'eligible',
  generatedAt: '2026-07-15T10:01:00.000Z',
  evidenceFreshnessHours: 168,
  targets: [{
    targetId: 'macos-arm64',
    artifacts: [{ sha256: 'c'.repeat(64) }],
    steps: [{
      stepId: 'install',
      result: 'passed',
      observedAt: '2026-07-15T10:00:00.000Z',
      evidenceRef: 'github-actions://runs/123/attempts/1/targets/macos-arm64/steps/install',
    }],
  }],
};

function approval(input = report) {
  const signed = createOperatorApprovalPayload({ report: input, operator: 'patryk-roguszewski', approvedAt });
  return {
    signed,
    signature: sign(null, Buffer.from(canonicalJson(signed), 'utf8'), privateKey).toString('base64'),
  };
}

describe('platform lifecycle operator approval', () => {
  it('binds the owner signature to the report and every manual cell', () => {
    const payload = createOperatorApprovalPayload({ report, operator: 'patryk-roguszewski', approvedAt });
    expect(payload.physicalEvidence).toEqual([expect.objectContaining({
      targetId: 'macos-arm64', cellCount: 1, cellsSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      artifactSha256: ['c'.repeat(64)],
    })]);
    expect(Buffer.byteLength(canonicalJson(payload))).toBeLessThan(64 * 1024);
    expect(verifyOperatorApproval({
      report,
      approval: approval(),
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
      expectedOperator: 'patryk-roguszewski',
      expectedSourceSha: sourceSha,
      now,
    })).toBe(true);
  });

  it('rejects a changed report, operator or signature', () => {
    const signed = approval();
    expect(() => verifyOperatorApproval({
      report: { ...report, contentSha256: 'd'.repeat(64) },
      approval: signed,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
      expectedOperator: 'patryk-roguszewski', expectedSourceSha: sourceSha, now,
    })).toThrow('does not match');
    expect(() => verifyOperatorApproval({
      report, approval: signed,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
      expectedOperator: 'someone-else', expectedSourceSha: sourceSha, now,
    })).toThrow('does not match');
    expect(() => verifyOperatorApproval({
      report, approval: { ...signed, signature: Buffer.alloc(64).toString('base64') },
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
      expectedOperator: 'patryk-roguszewski', expectedSourceSha: sourceSha, now,
    })).toThrow('signature is invalid');
  });

  it('rejects stale approval and blocked reports', () => {
    expect(() => createOperatorApprovalPayload({
      report: { ...report, releaseDecision: 'blocked' },
      operator: 'patryk-roguszewski', approvedAt,
    })).toThrow('not eligible');
    expect(() => verifyOperatorApproval({
      report, approval: approval(),
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
      expectedOperator: 'patryk-roguszewski', expectedSourceSha: sourceSha,
      now: new Date('2026-07-23T10:03:00.000Z'),
    })).toThrow('stale');
  });
});
