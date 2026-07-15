import { generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  canonicalJson,
  canonicalSha256,
  generateReport,
  loadManifest,
  renderMarkdown,
} from '../../security/adversarial/report.mjs';
import {
  createOperatorApprovalPayload,
  verifyOperatorApproval,
} from '../../security/adversarial/operator-approval.mjs';

const sourceSha = '1234567890abcdef1234567890abcdef12345678';
const now = new Date('2026-07-15T12:00:00.000Z');
const manifest = loadManifest();

function report() {
  const evidence = manifest.targetTiers
    .filter(({ disposition }) => disposition === 'evidence-required')
    .flatMap((target) => manifest.attacks.map((attack) => {
      const expectedResidual = target.expectedResidualAttacks.includes(attack.id);
      return {
        targetTierId: target.id,
        attackId: attack.id,
        result: expectedResidual ? 'expected-residual' : 'passed',
        observedAt: '2026-07-15T11:00:00.000Z',
        evidenceRef: target.manualRequiredAttacks.includes(attack.id)
          ? `manual://operator-attestation/${target.id}/${attack.id}/20260715T110000Z`
          : `artifact://github-actions/123/${target.id}/${attack.id}`,
        artifactSha256: canonicalSha256({ targetTierId: target.id }),
        residualRiskIds: expectedResidual ? [...target.expectedResidualRiskIds] : [],
      };
    }));
  return generateReport({
    manifest,
    evidenceBundle: {
      schemaVersion: 1,
      sourceSha,
      manifestSha256: canonicalSha256(manifest),
      evidence,
      findings: [],
    },
    expectedSourceSha: sourceSha,
    now,
  });
}

function signedApproval(input = report()) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const signed = createOperatorApprovalPayload({
    report: input,
    operator: 'patryk-roguszewski',
    approvedAt: '2026-07-15T12:00:00.000Z',
  });
  const signature = sign(null, Buffer.from(canonicalJson(signed), 'utf8'), privateKey).toString('base64');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  return {
    approval: { signature, signed },
    publicKeyValue: publicKeyDer.subarray(-32).toString('base64'),
  };
}

describe('adversarial operator approval', () => {
  it('authenticates every manual cell, source SHA and artifact digest with Ed25519', () => {
    const input = report();
    const { approval, publicKeyValue } = signedApproval(input);
    expect(approval.signed.manualEvidence.length).toBeGreaterThan(0);
    expect(verifyOperatorApproval({
      report: input,
      approval,
      publicKeyPem: publicKeyValue,
      expectedOperator: 'patryk-roguszewski',
      expectedSourceSha: sourceSha,
      now,
    })).toBe(true);
  });

  it('rejects a forged operator or signature', () => {
    const input = report();
    const { approval, publicKeyValue } = signedApproval(input);
    expect(() => verifyOperatorApproval({
      report: input,
      approval,
      publicKeyPem: publicKeyValue,
      expectedOperator: 'another-operator',
      expectedSourceSha: sourceSha,
      now,
    })).toThrow(/does not match/);
    const forged = structuredClone(approval);
    forged.signature = Buffer.alloc(64, 7).toString('base64');
    expect(() => verifyOperatorApproval({
      report: input,
      approval: forged,
      publicKeyPem: publicKeyValue,
      expectedOperator: 'patryk-roguszewski',
      expectedSourceSha: sourceSha,
      now,
    })).toThrow(/signature is invalid/);
  });

  it('rejects approval copied to a report with another manual artifact digest', () => {
    const input = report();
    const { approval, publicKeyValue } = signedApproval(input);
    const changed = structuredClone(input);
    const manual = changed.coverage.find(({ evidenceRequirement }) => evidenceRequirement === 'manual-required');
    expect(manual).toBeDefined();
    if (!manual) return;
    manual.artifactSha256 = 'f'.repeat(64);
    expect(() => verifyOperatorApproval({
      report: changed,
      approval,
      publicKeyPem: publicKeyValue,
      expectedOperator: 'patryk-roguszewski',
      expectedSourceSha: sourceSha,
      now,
    })).toThrow(/does not match/);
  });

  it('executes the payload, assemble and verify CLI flow with exact signed bytes', () => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-adversarial-approval-'));
    try {
      const input = report();
      const reportPath = join(directory, 'report.json');
      const markdownPath = join(directory, 'report.md');
      const payloadPath = join(directory, 'payload.json');
      const signaturePath = join(directory, 'signature.txt');
      const publicKeyPath = join(directory, 'public-key.txt');
      const approvalPath = join(directory, 'approval.json');
      writeFileSync(reportPath, `${JSON.stringify(input, null, 2)}\n`);
      writeFileSync(markdownPath, renderMarkdown(input));
      const common = [
        '--report', reportPath,
        '--markdown', markdownPath,
        '--source-sha', sourceSha,
        '--operator', 'patryk-roguszewski',
        '--now', now.toISOString(),
      ];
      execFileSync(process.execPath, [
        'security/adversarial/operator-approval.mjs',
        'payload',
        ...common,
        '--approved-at', now.toISOString(),
        '--output', payloadPath,
      ]);
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      writeFileSync(signaturePath, sign(null, readFileSync(payloadPath), privateKey).toString('base64'));
      const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
      writeFileSync(publicKeyPath, publicKeyDer.subarray(-32).toString('base64'));
      execFileSync(process.execPath, [
        'security/adversarial/operator-approval.mjs',
        'assemble',
        ...common,
        '--payload', payloadPath,
        '--signature', signaturePath,
        '--public-key', publicKeyPath,
        '--output', approvalPath,
      ]);
      expect(() => execFileSync(process.execPath, [
        'security/adversarial/operator-approval.mjs',
        'verify',
        ...common,
        '--approval', approvalPath,
        '--public-key', publicKeyPath,
      ])).not.toThrow();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
