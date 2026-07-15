import { describe, expect, it } from 'vitest';

import { verifyReleaseArtifactBindings } from '../../security/adversarial/verify-release-artifacts.mjs';

const sourceSha = 'a'.repeat(40);
const digest = (character: string): string => character.repeat(64);
const artifact = (filename: string, sha256: string) => ({
  filename,
  size: 1,
  sha256,
  sbom: { filename: 'release.spdx.json', sha256: digest('f') },
});
const cell = (targetTierId: string, artifactSha256: string) => ({
  targetTierId,
  evidenceRequirement: 'automated',
  artifactSha256,
});

const platformManifest = {
  sourceSha,
  version: '1.2.3',
  artifacts: [
    artifact('palladin-runtime-darwin-arm64-1.2.3.tgz', digest('1')),
    artifact('palladin-runtime-win32-x64-1.2.3.tgz', digest('2')),
    artifact('palladin-runtime-linux-arm64-musl-1.2.3.tgz', digest('3')),
    artifact('palladin-runtime_1.2.3_amd64.deb', digest('4')),
    artifact('palladin-runtime-1.2.3-1.x86_64.rpm', digest('6')),
  ],
};
const agentManifest = {
  sourceSha,
  version: '1.2.3',
  artifacts: [artifact('palladin-agent-1.2.3.tgz', digest('5'))],
};

describe('adversarial release artifact binding', () => {
  it('binds every public target to the matching staged release artifact', () => {
    expect(verifyReleaseArtifactBindings({
      report: {
        sourceSha,
        coverage: [
          cell('macos-arm64-hardened', digest('1')),
          cell('windows-x64-hardened', digest('2')),
          cell('linux-musl-arm64-convenience', digest('3')),
          cell('linux-gnu-x64-hardened-deb', digest('4')),
          cell('linux-gnu-x64-hardened-rpm', digest('6')),
          cell('macos-x64-convenience-source', digest('7')),
        ],
      },
      platformManifest,
    })).toBe(true);
  });

  it('rejects a supplied meta-package manifest from another source commit', () => {
    expect(() => verifyReleaseArtifactBindings({
      report: { sourceSha, coverage: [cell('macos-arm64-hardened', digest('1'))] },
      platformManifest,
      agentManifest: { ...agentManifest, sourceSha: 'b'.repeat(40) },
    })).toThrow(/agent manifest release binding is invalid/);
  });

  it('rejects a digest copied from a different staged target', () => {
    expect(() => verifyReleaseArtifactBindings({
      report: { sourceSha, coverage: [cell('macos-arm64-hardened', digest('2'))] },
      platformManifest,
      agentManifest,
    })).toThrow(/does not match the staged target/);
  });

  it('does not let DEB evidence authorize the RPM target', () => {
    expect(() => verifyReleaseArtifactBindings({
      report: { sourceSha, coverage: [cell('linux-gnu-x64-hardened-rpm', digest('4'))] },
      platformManifest,
      agentManifest,
    })).toThrow(/does not match the staged target/);
  });

  it('rejects mixed artifact digests inside one target-tier run', () => {
    expect(() => verifyReleaseArtifactBindings({
      report: {
        sourceSha,
        coverage: [
          cell('macos-arm64-hardened', digest('1')),
          cell('macos-arm64-hardened', digest('2')),
        ],
      },
      platformManifest,
      agentManifest,
    })).toThrow(/more than one artifact digest/);
  });
});
