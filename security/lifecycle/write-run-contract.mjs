#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadManifest, validateManifest } from './report.mjs';

const SOURCE_SHA = /^[0-9a-f]{40}$/;
function fail(message) { throw new Error(message); }
function parse(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index]; const value = argv[index + 1];
    if (!['--target', '--release-sets', '--source-sha', '--run-id', '--run-attempt', '--vault-id', '--entry-id', '--output', '--contract'].includes(flag)
      || value === undefined || values.has(flag)) fail('invalid arguments');
    values.set(flag, value);
  }
  for (const flag of ['--target', '--release-sets', '--source-sha', '--run-id', '--run-attempt', '--vault-id', '--entry-id', '--output', '--contract']) {
    if (!values.has(flag)) fail(`${flag} is required`);
  }
  return values;
}
function writeAtomic(path, value) {
  const absolute = resolve(path); mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(absolute), `.${basename(absolute)}.${randomUUID()}.tmp`);
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, absolute);
  } finally { rmSync(temporary, { force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const values = parse(process.argv.slice(2));
    const manifest = validateManifest(loadManifest());
    const target = values.get('--target');
    const sourceSha = values.get('--source-sha');
    const runId = values.get('--run-id');
    const runAttempt = Number(values.get('--run-attempt'));
    const vaultId = values.get('--vault-id');
    const entryId = values.get('--entry-id');
    if (!manifest.targets.some((item) => item.id === target) || !SOURCE_SHA.test(sourceSha)
      || !/^[1-9][0-9]*$/.test(runId) || !Number.isSafeInteger(runAttempt) || runAttempt < 1
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(vaultId)
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(entryId)) {
      fail('contract context is invalid');
    }
    const root = resolve(values.get('--release-sets'));
    const phases = Object.fromEntries(['baseline', 'candidate', 'forward-rollback'].map((phase) => {
      const directory = join(root, phase);
      const releaseManifest = JSON.parse(readFileSync(join(directory, 'release-manifest.json'), 'utf8'));
      return [phase, { version: releaseManifest.version, sourceSha: releaseManifest.sourceSha, directory }];
    }));
    if (phases.candidate.sourceSha !== sourceSha) fail('candidate release set does not match the contract source');
    writeAtomic(values.get('--contract'), {
      schemaVersion: 1,
      sourceSha,
      runId,
      runAttempt,
      targetId: target,
      apiHost: 'https://api.stage.palladin.io',
      vaultId,
      entryId,
      phases,
      output: resolve(values.get('--output')),
    });
  } catch (error) {
    process.stderr.write(`lifecycle contract generation failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  }
}
