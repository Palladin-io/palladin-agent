#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import {
  closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync,
  readdirSync, renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalSha256, loadManifest, validateManifest } from './report.mjs';

const SOURCE_SHA = /^[0-9a-f]{40}$/;
const RUN_ID = /^[1-9][0-9]*$/;
function fail(message) { throw new Error(message); }
function record(value, label) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}
function exactKeys(value, keys, label) {
  const actual = Object.keys(record(value, label)).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has an invalid shape`);
  }
}
function readJson(path, label) {
  const absolute = resolve(path);
  const descriptor = openSync(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor);
    const linked = lstatSync(absolute);
    if (!opened.isFile() || linked.isSymbolicLink() || opened.dev !== linked.dev || opened.ino !== linked.ino) {
      fail(`${label} must be an unchanged regular file`);
    }
    return JSON.parse(readFileSync(descriptor, 'utf8'));
  } catch (error) {
    fail(`${label} is invalid: ${error instanceof Error ? error.message : 'unknown error'}`);
  } finally { closeSync(descriptor); }
}
function writeAtomic(path, value) {
  const absolute = resolve(path);
  mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(absolute), `.${basename(absolute)}.${randomUUID()}.tmp`);
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, absolute);
  } finally { rmSync(temporary, { force: true }); }
}

export function aggregateShards({ manifest: manifestInput, shards, expectedSourceSha, expectedRunId, expectedRunAttempt }) {
  const manifest = validateManifest(manifestInput);
  if (!SOURCE_SHA.test(expectedSourceSha) || !RUN_ID.test(expectedRunId)
    || !Number.isSafeInteger(expectedRunAttempt) || expectedRunAttempt < 1) fail('aggregation context is invalid');
  const expectedManifestSha = canonicalSha256(manifest);
  const targetById = new Map(manifest.targets.map((target) => [target.id, target]));
  const targets = [];
  for (const [index, shardInput] of shards.entries()) {
    const label = `shards[${index}]`;
    const shard = record(shardInput, label);
    exactKeys(shard, ['schemaVersion', 'sourceSha', 'manifestSha256', 'runId', 'runAttempt', 'target'], label);
    if (shard.schemaVersion !== 1 || shard.sourceSha !== expectedSourceSha
      || shard.manifestSha256 !== expectedManifestSha || shard.runId !== expectedRunId
      || shard.runAttempt !== expectedRunAttempt) fail(`${label} binding is invalid`);
    const target = record(shard.target, `${label}.target`);
    exactKeys(target, ['targetId', 'artifacts', 'steps'], `${label}.target`);
    if (!targetById.has(target.targetId) || targets.some((item) => item.targetId === target.targetId)) {
      fail(`${label} target is unknown or duplicate`);
    }
    targets.push(target);
  }
  if (targets.length !== manifest.targets.length) fail('required physical target shard is missing');
  return {
    schemaVersion: 1,
    sourceSha: expectedSourceSha,
    manifestSha256: expectedManifestSha,
    runId: expectedRunId,
    runAttempt: expectedRunAttempt,
    targets: manifest.targets.map((target) => targets.find((item) => item.targetId === target.id)),
  };
}

function parse(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index]; const value = argv[index + 1];
    if (!['--manifest', '--shards', '--source-sha', '--run-id', '--run-attempt', '--output'].includes(flag)
      || value === undefined || values.has(flag)) fail('invalid arguments');
    values.set(flag, value);
  }
  for (const required of ['--shards', '--source-sha', '--run-id', '--run-attempt', '--output']) {
    if (!values.has(required)) fail(`${required} is required`);
  }
  return values;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const values = parse(process.argv.slice(2));
    const manifest = values.has('--manifest') ? readJson(values.get('--manifest'), 'manifest') : loadManifest();
    const directory = resolve(values.get('--shards'));
    const entries = readdirSync(directory).sort();
    if (entries.length === 0 || entries.some((entry) => !/^lifecycle-[A-Za-z0-9._-]+\.json$/.test(entry))) {
      fail('shard directory contains a missing or unexpected entry');
    }
    const shards = entries.map((entry) => readJson(join(directory, entry), `shard ${entry}`));
    const evidence = aggregateShards({
      manifest,
      shards,
      expectedSourceSha: values.get('--source-sha'),
      expectedRunId: values.get('--run-id'),
      expectedRunAttempt: Number(values.get('--run-attempt')),
    });
    writeAtomic(values.get('--output'), evidence);
  } catch (error) {
    process.stderr.write(`lifecycle shard aggregation failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  }
}
