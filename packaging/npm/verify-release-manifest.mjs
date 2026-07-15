#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import {
  expectedChecksums,
  expectedReleaseManifest,
  loadReleaseInputs,
} from './release-manifest-policy.mjs';
import { assertRegularFile, fail, readJsonObject } from './release-policy.mjs';

try {
  const inputs = loadReleaseInputs(process.argv.slice(2));
  assertRegularFile(inputs.manifestPath, 'release manifest');
  assertRegularFile(inputs.checksumsPath, 'release checksums');
  const actualManifest = readJsonObject(inputs.manifestPath, 'release manifest');
  const expectedManifest = expectedReleaseManifest(inputs);
  if (JSON.stringify(actualManifest) !== JSON.stringify(expectedManifest)) {
    fail('release manifest does not exactly match the artifacts, version, source SHA, and SBOM');
  }
  const actualChecksums = readFileSync(inputs.checksumsPath, 'utf8');
  if (actualChecksums !== expectedChecksums(inputs)) fail('SHA256SUMS does not exactly match release artifacts and SBOM');
} catch (error) {
  process.stderr.write(`Error: ${error instanceof Error ? error.message : 'unknown release verification failure'}\n`);
  process.exitCode = 1;
}
