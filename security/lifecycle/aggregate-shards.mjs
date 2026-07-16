#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import {
  closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync,
  readdirSync, renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadManifest } from './report.mjs';
import { aggregateShards } from './shards.mjs';

function fail(message) { throw new Error(message); }
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
