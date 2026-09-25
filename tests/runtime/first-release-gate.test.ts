import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { validateManifest as validateAdversarialManifest } from '../../security/adversarial/report.mjs';
import {
  canonicalSha256, generateReport, loadManifest, renderMarkdown, validateManifest, validateReport,
} from '../../security/lifecycle/report.mjs';
import { aggregateShards } from '../../security/lifecycle/shards.mjs';
import {
  lifecycleFixture, lifecycleFixtureNow as now, lifecycleFixtureRunAttempt as runAttempt,
  lifecycleFixtureRunId as runId, lifecycleFixtureSourceSha as sourceSha,
} from './platform-lifecycle-fixture';

function firstReleaseFixture() {
  const manifest = loadManifest('security/lifecycle/first-release-manifest.json');
  const original = lifecycleFixture();
  const targets = manifest.targets.map((target: { id: string; requiredArtifactRoles: string[] }) => {
    const run = original.evidence.targets.find((item: { targetId: string }) => item.targetId === target.id)!;
    return {
      ...run,
      artifacts: run.artifacts.filter((item: { phase: string; role: string }) => item.phase === 'candidate' && target.requiredArtifactRoles.includes(item.role)).map((item: { version: string }) => ({
        ...item, version: '0.0.1',
      })),
      steps: run.steps.filter((step: { stepId: string }) => manifest.steps.some((item: { id: string }) => item.id === step.stepId))
        .map((step: { order: number; versionBefore: string | null; versionAfter: string | null }, index: number) => ({
          ...step,
          order: index + 1,
          versionBefore: step.versionBefore === null ? null : '0.0.1',
          versionAfter: step.versionAfter === null ? null : '0.0.1',
        })),
    };
  });
  const evidence = {
    schemaVersion: 2,
    sourceSha,
    manifestSha256: canonicalSha256(manifest),
    runId,
    runAttempt,
    targets,
  };
  return { manifest, evidence };
}

describe('0.0.1 macOS/Linux release gate', () => {
  it('accepts exactly six candidate-only physical targets and 48 passing steps', () => {
    const { manifest, evidence } = firstReleaseFixture();
    expect(validateManifest(manifest)).toBe(manifest);
    const report = generateReport({ manifest, evidence, expectedSourceSha: sourceSha, now });
    expect(report.summary).toEqual({ targetCount: 6, stepCount: 48, passed: 48, failed: 0 });
    expect(validateReport({ manifest, report, expectedSourceSha: sourceSha, now, markdown: renderMarkdown(report) })).toBe(true);
  });

  it('rejects missing targets, foreign versions, mixed phases, and a forged shard', () => {
    const missing = firstReleaseFixture(); missing.evidence.targets.pop();
    expect(() => generateReport({ ...missing, expectedSourceSha: sourceSha, now })).toThrow('missing a required target');
    const version = firstReleaseFixture(); version.evidence.targets[0]!.artifacts.forEach((item: { version: string }) => { item.version = '0.0.2'; });
    expect(() => generateReport({ ...version, expectedSourceSha: sourceSha, now })).toThrow('first release');
    const phase = firstReleaseFixture(); phase.evidence.targets[0]!.artifacts[0]!.phase = 'baseline';
    expect(() => generateReport({ ...phase, expectedSourceSha: sourceSha, now })).toThrow('phase/role');
    const valid = firstReleaseFixture();
    const shards = valid.evidence.targets.map((target: { targetId: string }) => ({
      schemaVersion: 2, sourceSha, manifestSha256: valid.evidence.manifestSha256,
      runId, runAttempt, target,
    }));
    expect(aggregateShards({ manifest: valid.manifest, shards, expectedSourceSha: sourceSha, expectedRunId: runId, expectedRunAttempt: runAttempt })).toEqual(valid.evidence);
    shards[0]!.schemaVersion = 1;
    expect(() => aggregateShards({ manifest: valid.manifest, shards, expectedSourceSha: sourceSha, expectedRunId: runId, expectedRunAttempt: runAttempt })).toThrow('binding');
  });

  it('pins the adversarial matrix to macOS Hardened and Linux Convenience', () => {
    const manifest = JSON.parse(readFileSync('security/adversarial/first-release-manifest.json', 'utf8'));
    expect(validateAdversarialManifest(manifest)).toBe(manifest);
    expect(manifest.targetTiers).toHaveLength(6);
    const forged = structuredClone(manifest);
    forged.targetTiers[2].tier = 'Hardened';
    expect(() => validateAdversarialManifest(forged)).toThrow('first-release adversarial tier');
  });
});
