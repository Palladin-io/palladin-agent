import { generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { canonicalJson, generateReport, renderMarkdown } from '../../security/lifecycle/report.mjs';
import {
  createOperatorApprovalPayload,
  verifyOperatorApproval,
} from '../../security/lifecycle/operator-approval.mjs';
import { lifecycleFixture } from './platform-lifecycle-fixture';

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

  it('assembles and verifies raw KMS signature bytes through the CLI', () => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-lifecycle-approval-'));
    try {
      const { manifest, evidence } = lifecycleFixture();
      const input = generateReport({ manifest, evidence, expectedSourceSha: sourceSha, now });
      const manifestPath = join(directory, 'manifest.json');
      const reportPath = join(directory, 'report.json');
      const markdownPath = join(directory, 'report.md');
      const payloadPath = join(directory, 'payload.json');
      const signaturePath = join(directory, 'signature.bin');
      const publicKeyPath = join(directory, 'public-key.pem');
      const approvalPath = join(directory, 'approval.json');
      writeFileSync(manifestPath, JSON.stringify(manifest));
      writeFileSync(reportPath, JSON.stringify(input));
      writeFileSync(markdownPath, renderMarkdown(input));
      writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }));
      const common = [
        '--manifest', manifestPath, '--report', reportPath, '--markdown', markdownPath,
        '--source-sha', sourceSha, '--operator', 'patryk-roguszewski', '--now', now.toISOString(),
      ];
      execFileSync(process.execPath, [
        'security/lifecycle/operator-approval.mjs', 'payload', ...common,
        '--approved-at', now.toISOString(), '--output', payloadPath,
      ]);
      const signatureBytes = sign(null, readFileSync(payloadPath), privateKey);
      writeFileSync(signaturePath, signatureBytes);
      const assemble = [
        'security/lifecycle/operator-approval.mjs', 'assemble', ...common,
        '--payload', payloadPath, '--signature', signaturePath,
        '--public-key', publicKeyPath, '--output', approvalPath,
      ];
      execFileSync(process.execPath, assemble);
      expect(() => execFileSync(process.execPath, [
        'security/lifecycle/operator-approval.mjs', 'verify', ...common,
        '--approval', approvalPath, '--public-key', publicKeyPath,
      ])).not.toThrow();
      signatureBytes[0] ^= 1;
      writeFileSync(signaturePath, signatureBytes);
      expect(spawnSync(process.execPath, assemble).status).not.toBe(0);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
