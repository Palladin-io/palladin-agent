import { describe, expect, it } from 'vitest';

import { verifyReleaseArtifactBindings } from '../../security/lifecycle/verify-release-artifacts.mjs';

const sourceSha = 'a'.repeat(40);
const digest = (value: string) => value.repeat(64);
const version = '1.2.3';
const artifact = (filename: string, sha256: string) => ({ filename, sha256, sbom: { filename: 'fixture.spdx.json', sha256: digest('f') } });
const platformArtifacts = [
  artifact('palladin-runtime-darwin-arm64-1.2.3.tgz', digest('1')),
  artifact('palladin-runtime-darwin-x64-1.2.3.tgz', digest('2')),
  artifact('palladin-runtime-darwin-universal.zip', digest('3')),
  artifact('palladin-runtime-win32-arm64-1.2.3.tgz', digest('4')),
  artifact('palladin-runtime-win32-x64-1.2.3.tgz', digest('5')),
  artifact('palladin-runtime-setup-arm64-1.2.3.zip', digest('6')),
  artifact('palladin-runtime-setup-x64-1.2.3.zip', digest('7')),
  artifact('palladin-runtime-linux-arm64-gnu-1.2.3.tgz', digest('8')),
  artifact('palladin-runtime-linux-x64-gnu-1.2.3.tgz', digest('9')),
  artifact('palladin-runtime-linux-arm64-musl-1.2.3.tgz', digest('a')),
  artifact('palladin-runtime-linux-x64-musl-1.2.3.tgz', digest('b')),
  artifact('palladin-runtime_1.2.3_arm64.deb', digest('c')),
  artifact('palladin-runtime_1.2.3_amd64.deb', digest('d')),
  artifact('palladin-runtime-1.2.3-1.aarch64.rpm', digest('e')),
  artifact('palladin-runtime-1.2.3-1.x86_64.rpm', digest('f')),
];
const agent = artifact('palladin-agent-1.2.3.tgz', digest('0'));
const artifacts = new Map([...platformArtifacts, agent].map((item) => [item.filename, item.sha256]));
const target = (targetId: string, roles: Array<[string, string]>) => ({
  targetId,
  artifacts: roles.map(([role, filename]) => ({
    phase: 'candidate', role, version, sourceSha, filename, sha256: artifacts.get(filename),
  })),
  steps: [],
});
const report = {
  sourceSha,
  targets: [
    target('macos-arm64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-darwin-arm64-1.2.3.tgz'], ['signed-runtime', 'palladin-runtime-darwin-universal.zip']]),
    target('macos-x64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-darwin-x64-1.2.3.tgz'], ['signed-runtime', 'palladin-runtime-darwin-universal.zip']]),
    target('windows-arm64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-win32-arm64-1.2.3.tgz'], ['signed-installer', 'palladin-runtime-setup-arm64-1.2.3.zip']]),
    target('windows-x64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-win32-x64-1.2.3.tgz'], ['signed-installer', 'palladin-runtime-setup-x64-1.2.3.zip']]),
    target('ubuntu-24.04-arm64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-linux-arm64-gnu-1.2.3.tgz'], ['deb', 'palladin-runtime_1.2.3_arm64.deb']]),
    target('ubuntu-24.04-x64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-linux-x64-gnu-1.2.3.tgz'], ['deb', 'palladin-runtime_1.2.3_amd64.deb']]),
    target('debian-13-arm64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-linux-arm64-gnu-1.2.3.tgz'], ['deb', 'palladin-runtime_1.2.3_arm64.deb']]),
    target('debian-13-x64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-linux-x64-gnu-1.2.3.tgz'], ['deb', 'palladin-runtime_1.2.3_amd64.deb']]),
    target('fedora-42-arm64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-linux-arm64-gnu-1.2.3.tgz'], ['rpm', 'palladin-runtime-1.2.3-1.aarch64.rpm']]),
    target('fedora-42-x64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-linux-x64-gnu-1.2.3.tgz'], ['rpm', 'palladin-runtime-1.2.3-1.x86_64.rpm']]),
    target('alpine-3.22-arm64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-linux-arm64-musl-1.2.3.tgz']]),
    target('alpine-3.22-x64', [['agent-npm', agent.filename], ['platform-npm', 'palladin-runtime-linux-x64-musl-1.2.3.tgz']]),
  ],
};
const platformManifest = { version, sourceSha, artifacts: platformArtifacts };
const agentManifest = { version, sourceSha, artifacts: [agent] };

describe('platform lifecycle release artifact binding', () => {
  it('binds every role and digest to the exact platform and agent manifests', () => {
    expect(verifyReleaseArtifactBindings({ report, platformManifest, agentManifest })).toBe(true);
  });

  it('rejects a digest from another artifact or a role from another target', () => {
    const wrongDigest = structuredClone(report);
    wrongDigest.targets[0]!.artifacts[1]!.sha256 = digest('9');
    expect(() => verifyReleaseArtifactBindings({ report: wrongDigest, platformManifest, agentManifest }))
      .toThrow('does not match the staged release');

    const wrongRole = structuredClone(report);
    wrongRole.targets[2]!.artifacts[2]!.filename = 'palladin-runtime-setup-x64-1.2.3.zip';
    expect(() => verifyReleaseArtifactBindings({ report: wrongRole, platformManifest, agentManifest }))
      .toThrow('artifact role is invalid');
  });

  it('rejects foreign source manifests', () => {
    expect(() => verifyReleaseArtifactBindings({
      report,
      platformManifest: { ...platformManifest, sourceSha: 'f'.repeat(40) },
      agentManifest,
    })).toThrow('release binding is invalid');
  });

  it('requires the exact candidate agent manifest', () => {
    expect(() => verifyReleaseArtifactBindings({ report, platformManifest, agentManifest: undefined }))
      .toThrow('agent manifest is required');
  });
});
