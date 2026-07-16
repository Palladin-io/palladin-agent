import { canonicalSha256, loadManifest } from '../../security/lifecycle/report.mjs';

const sourceSha = 'a'.repeat(40);
const phaseSources = { baseline: 'b'.repeat(40), candidate: sourceSha, 'forward-rollback': 'c'.repeat(40) };
const phaseVersions = { baseline: '1.0.0', candidate: '1.1.0', 'forward-rollback': '1.2.0' };
const artifactSha = 'd'.repeat(64);
export const lifecycleFixtureIdentity = 'e'.repeat(64);
export const lifecycleFixtureGrants = 'f'.repeat(64);
const identity = lifecycleFixtureIdentity;
const grants = lifecycleFixtureGrants;

const transition = [
  [null, '1.0.0', null, null],
  ['1.0.0', '1.0.0', null, identity],
  ['1.0.0', '1.0.0', identity, identity],
  ['1.0.0', '1.1.0', identity, identity],
  ['1.1.0', '1.1.0', identity, identity],
  ['1.1.0', '1.1.0', identity, identity],
  ['1.1.0', '1.1.0', identity, identity],
  ['1.1.0', '1.2.0', identity, identity],
  ['1.2.0', '1.2.0', identity, identity],
  ['1.2.0', '1.2.0', identity, null],
  ['1.2.0', null, null, null],
] as const;

export const lifecycleFixtureSourceSha = sourceSha;
export const lifecycleFixtureNow = new Date('2026-07-15T10:20:00.000Z');
export const lifecycleFixtureRunId = '123456';
export const lifecycleFixtureRunAttempt = 2;

export function lifecycleFixture() {
  const manifest = loadManifest();
  const steps = manifest.steps.map((definition: { id: string; order: number }, index: number) => {
    const [versionBefore, versionAfter, identityBefore, identityAfter] = transition[index]!;
    const grantBefore = index < 3 || index >= 10 ? null : grants;
    const grantAfter = index < 2 || index >= 9 ? null : grants;
    return {
      stepId: definition.id,
      order: definition.order,
      result: 'passed',
      observedAt: new Date(Date.parse('2026-07-15T10:00:00.000Z') + index * 1_000).toISOString(),
      evidenceRef: `github-actions://runs/${lifecycleFixtureRunId}/attempts/${lifecycleFixtureRunAttempt}/targets/TARGET/steps/${definition.id}`,
      versionBefore, versionAfter,
      identityFingerprintBefore: identityBefore,
      identityFingerprintAfter: identityAfter,
      grantSetDigestBefore: grantBefore,
      grantSetDigestAfter: grantAfter,
      rollbackMode: definition.id === 'rollback' ? 'forward-rebuild' : null,
      concurrentMcpVerified: definition.id === 'concurrent-mcp',
      repairVerified: definition.id === 'repair',
      downgradeRejected: definition.id === 'downgrade-rejected',
      purgeVerified: definition.id === 'purge',
    };
  });
  return {
    manifest,
    evidence: {
      schemaVersion: 1,
      sourceSha,
      manifestSha256: canonicalSha256(manifest),
      runId: lifecycleFixtureRunId,
      runAttempt: lifecycleFixtureRunAttempt,
      targets: manifest.targets.map((target: { id: string; requiredArtifactRoles: string[] }) => ({
        targetId: target.id,
        artifacts: manifest.artifactPhases.flatMap((phase: keyof typeof phaseVersions) => (
          target.requiredArtifactRoles.map((role) => ({
            phase, role, version: phaseVersions[phase], sourceSha: phaseSources[phase],
            filename: `${target.id}-${phase}-${role}.tgz`, sha256: artifactSha,
          }))
        )),
        steps: steps.map((step) => ({ ...step, evidenceRef: step.evidenceRef.replace('TARGET', target.id) })),
      })),
    },
  };
}
