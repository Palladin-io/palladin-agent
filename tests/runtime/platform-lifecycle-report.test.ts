import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  generateReport, renderMarkdown, validateManifest, validateReport,
} from '../../security/lifecycle/report.mjs';
import {
  lifecycleFixture, lifecycleFixtureGrants as grants, lifecycleFixtureIdentity as identity,
  lifecycleFixtureNow as now, lifecycleFixtureRunId as runId, lifecycleFixtureSourceSha as sourceSha,
} from './platform-lifecycle-fixture';

describe('platform lifecycle release report', () => {
  it('requires 12 physical targets, three artifact phases, and the complete lifecycle', () => {
    const { manifest } = lifecycleFixture();
    expect(validateManifest(manifest)).toBe(manifest);
    expect(manifest.targets).toHaveLength(12);
    expect(manifest.artifactPhases).toEqual(['baseline', 'candidate', 'forward-rollback']);
    expect(manifest.steps.map((step: { id: string }) => step.id)).toEqual([
      'install', 'enroll', 'mcp', 'update', 'concurrent-mcp', 'repair',
      'downgrade-rejected', 'rollback', 'reinstall', 'purge', 'uninstall',
    ]);
  });

  it('generates an eligible report only for all 132 fresh passing cells', () => {
    const { manifest, evidence } = lifecycleFixture();
    const report = generateReport({ manifest, evidence, expectedSourceSha: sourceSha, now });
    expect(report.summary).toEqual({ targetCount: 12, stepCount: 132, passed: 132, failed: 0 });
    expect(report.runId).toBe(runId);
    const markdown = renderMarkdown(report);
    expect(validateReport({ manifest, report, expectedSourceSha: sourceSha, now, markdown })).toBe(true);
    expect(markdown).not.toContain(identity);
    expect(markdown).not.toContain(grants);
  });

  it('rejects missing targets, reordered steps, and a foreign physical run reference', () => {
    const missing = lifecycleFixture(); missing.evidence.targets.pop();
    expect(() => generateReport({ ...missing, expectedSourceSha: sourceSha, now })).toThrow('missing a required target');
    const reordered = lifecycleFixture();
    [reordered.evidence.targets[0]!.steps[0], reordered.evidence.targets[0]!.steps[1]] = [reordered.evidence.targets[0]!.steps[1]!, reordered.evidence.targets[0]!.steps[0]!];
    expect(() => generateReport({ ...reordered, expectedSourceSha: sourceSha, now })).toThrow('out of order');
    const foreign = lifecycleFixture(); foreign.evidence.targets[0]!.steps[0]!.evidenceRef = foreign.evidence.targets[0]!.steps[0]!.evidenceRef.replace(runId, '999');
    expect(() => generateReport({ ...foreign, expectedSourceSha: sourceSha, now })).toThrow('exact physical workflow run');
  });

  it('rejects phase version/source substitution and non-monotonic evidence time', () => {
    const wrongVersion = lifecycleFixture(); wrongVersion.evidence.targets[0]!.artifacts[0]!.version = '9.0.0';
    expect(() => generateReport({ ...wrongVersion, expectedSourceSha: sourceSha, now })).toThrow('conflicts within its phase');
    const wrongSource = lifecycleFixture();
    const candidateArtifact = wrongSource.evidence.targets[0]!.artifacts.find((item) => item.phase === 'candidate')!;
    candidateArtifact.sourceSha = '9'.repeat(40);
    expect(() => generateReport({ ...wrongSource, expectedSourceSha: sourceSha, now })).toThrow(/conflicts|candidate source/);
    const timeTravel = lifecycleFixture(); timeTravel.evidence.targets[0]!.steps[4]!.observedAt = '2026-07-15T09:00:00.000Z';
    expect(() => generateReport({ ...timeTravel, expectedSourceSha: sourceSha, now })).toThrow('not monotonic');
  });

  it('rejects identity/grant discontinuity, literal downgrade, and incomplete purge', () => {
    const drift = lifecycleFixture(); drift.evidence.targets[0]!.steps[5]!.identityFingerprintBefore = '1'.repeat(64);
    expect(() => generateReport({ ...drift, expectedSourceSha: sourceSha, now })).toThrow('does not continue');
    const downgrade = lifecycleFixture(); downgrade.evidence.targets[0]!.steps[7]!.rollbackMode = null;
    expect(() => generateReport({ ...downgrade, expectedSourceSha: sourceSha, now })).toThrow('forward rebuild');
    const purge = lifecycleFixture(); purge.evidence.targets[0]!.steps[9]!.identityFingerprintAfter = identity;
    expect(() => generateReport({ ...purge, expectedSourceSha: sourceSha, now })).toThrow('purge state');
    const unverifiedRepair = lifecycleFixture(); unverifiedRepair.evidence.targets[0]!.steps[5]!.repairVerified = false;
    expect(() => generateReport({ ...unverifiedRepair, expectedSourceSha: sourceSha, now })).toThrow('repair state');
  });

  it('blocks failed cells and rejects stale or secret-shaped evidence', () => {
    const failed = lifecycleFixture(); failed.evidence.targets[0]!.steps[3]!.result = 'failed';
    const report = generateReport({ ...failed, expectedSourceSha: sourceSha, now });
    expect(report.releaseDecision).toBe('blocked');
    expect(() => validateReport({ manifest: failed.manifest, report, expectedSourceSha: sourceSha, now, markdown: renderMarkdown(report) })).toThrow('release gate blocked');
    const stale = lifecycleFixture(); stale.evidence.targets[0]!.steps[0]!.observedAt = '2026-07-01T00:00:00.000Z';
    expect(() => generateReport({ ...stale, expectedSourceSha: sourceSha, now })).toThrow('stale');
    const secret = lifecycleFixture(); secret.evidence.targets[0]!.artifacts[0]!.filename = 'npm_abcdefghijklmnop.tgz';
    expect(() => generateReport({ ...secret, expectedSourceSha: sourceSha, now })).toThrow('secret-shaped');
  });

  it('writes and revalidates byte-matching JSON and Markdown through the CLI', () => {
    const { manifest, evidence } = lifecycleFixture();
    const directory = mkdtempSync(join(tmpdir(), 'palladin-lifecycle-report-'));
    try {
      const manifestPath = join(directory, 'manifest.json'); const evidencePath = join(directory, 'evidence.json');
      const reportPath = join(directory, 'report.json'); const markdownPath = join(directory, 'report.md');
      writeFileSync(manifestPath, JSON.stringify(manifest)); writeFileSync(evidencePath, JSON.stringify(evidence));
      execFileSync(process.execPath, ['security/lifecycle/report.mjs', 'generate', '--manifest', manifestPath, '--evidence', evidencePath, '--source-sha', sourceSha, '--json', reportPath, '--markdown', markdownPath, '--now', now.toISOString()]);
      execFileSync(process.execPath, ['security/lifecycle/report.mjs', 'validate', '--manifest', manifestPath, '--source-sha', sourceSha, '--json', reportPath, '--markdown', markdownPath, '--now', now.toISOString()]);
      const report = JSON.parse(readFileSync(reportPath, 'utf8'));
      expect(readFileSync(markdownPath, 'utf8')).toBe(renderMarkdown(report));
      writeFileSync(markdownPath, '# stale\n');
      const rejected = spawnSync(process.execPath, ['security/lifecycle/report.mjs', 'validate', '--manifest', manifestPath, '--source-sha', sourceSha, '--json', reportPath, '--markdown', markdownPath, '--now', now.toISOString()], { encoding: 'utf8' });
      expect(rejected.status).not.toBe(0);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
});
