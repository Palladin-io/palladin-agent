#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function fail(message) {
  process.stderr.write(`Error: ${message}\n`);
  process.exit(1);
}

const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith('--') || value === undefined) fail('invalid verifier arguments');
  values.set(key.slice(2), value);
}

for (const required of ['package', 'name', 'os', 'cpu', 'libc', 'files']) {
  if (!values.has(required)) fail(`missing --${required}`);
}

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const rootManifest = JSON.parse(readFileSync(resolve(scriptDirectory, '../../package.json'), 'utf8'));
const packageDirectory = resolve(values.get('package'));
const manifest = JSON.parse(readFileSync(resolve(packageDirectory, 'package.json'), 'utf8'));
const expectedFiles = JSON.parse(values.get('files'));
const expectedLibc = values.get('libc') === 'none' ? undefined : [values.get('libc')];

const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);
if (manifest.name !== values.get('name')) fail('unexpected package name');
if (manifest.version !== rootManifest.version) fail('platform version does not match launcher version');
if (Object.hasOwn(manifest, 'private')) fail('staged package must be public');
if (!equal(manifest.os, [values.get('os')])) fail('unexpected os metadata');
if (!equal(manifest.cpu, [values.get('cpu')])) fail('unexpected cpu metadata');
if (!equal(manifest.libc, expectedLibc)) fail('unexpected libc metadata');
if (!equal(manifest.files, expectedFiles)) fail('unexpected files allowlist');
if (!equal(manifest.publishConfig, { access: 'public', provenance: true })) {
  fail('public provenance configuration is required');
}
for (const field of ['scripts', 'dependencies', 'optionalDependencies']) {
  if (Object.hasOwn(manifest, field)) fail(`platform package must not contain ${field}`);
}
