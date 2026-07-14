#!/usr/bin/env node
import { renameSync, writeFileSync } from 'node:fs';
import {
  assertOutputParent,
  expectedChecksums,
  expectedReleaseManifest,
  loadReleaseInputs,
} from './release-manifest-policy.mjs';

function atomicWrite(path, contents) {
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, contents, { encoding: 'utf8', flag: 'wx', mode: 0o644 });
  renameSync(temporary, path);
}

try {
  const inputs = loadReleaseInputs(process.argv.slice(2));
  assertOutputParent(inputs.manifestPath, 'manifest');
  assertOutputParent(inputs.checksumsPath, 'checksums');
  atomicWrite(inputs.manifestPath, `${JSON.stringify(expectedReleaseManifest(inputs), null, 2)}\n`);
  atomicWrite(inputs.checksumsPath, expectedChecksums(inputs));
} catch (error) {
  process.stderr.write(`Error: ${error instanceof Error ? error.message : 'unknown release manifest failure'}\n`);
  process.exitCode = 1;
}
