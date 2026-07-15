#!/usr/bin/env node
import { gunzipSync } from 'node:zlib';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import {
  PLATFORM_PACKAGE_NAMES,
  assertNoLifecycleScripts,
  assertVersion,
  fail,
  parseArguments,
} from './release-policy.mjs';

const MAX_UNPACKED_BYTES = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 128 * 1024;

function tarString(buffer, start, length) {
  const end = buffer.indexOf(0, start);
  return buffer.subarray(start, end === -1 || end > start + length ? start + length : end).toString('utf8');
}

function tarOctal(buffer, start, length) {
  const value = tarString(buffer, start, length).trim();
  if (value === '') return 0;
  if (!/^[0-7]+$/.test(value)) fail('npm archive contains an invalid tar number');
  return Number.parseInt(value, 8);
}

function assertTarChecksum(block, archivePath) {
  const expected = tarOctal(block, 148, 8);
  let actual = 0;
  for (let index = 0; index < block.length; index += 1) {
    actual += index >= 148 && index < 156 ? 32 : block[index];
  }
  if (actual !== expected) fail(`npm archive has an invalid tar checksum: ${basename(archivePath)}`);
}

function readPackageManifest(archivePath) {
  const compressed = readFileSync(archivePath);
  let tar;
  try {
    tar = gunzipSync(compressed, { maxOutputLength: MAX_UNPACKED_BYTES });
  } catch {
    fail(`invalid or oversized npm archive: ${basename(archivePath)}`);
  }
  let found;
  for (let offset = 0; offset + 512 <= tar.length;) {
    const block = tar.subarray(offset, offset + 512);
    if (block.every((byte) => byte === 0)) break;
    assertTarChecksum(block, archivePath);
    const name = tarString(block, 0, 100);
    const prefix = tarString(block, 345, 155);
    const path = prefix ? `${prefix}/${name}` : name;
    const size = tarOctal(block, 124, 12);
    const type = block[156];
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (!Number.isSafeInteger(size) || dataEnd > tar.length) fail(`truncated npm archive: ${basename(archivePath)}`);
    if (path === 'package/package.json' && (type === 0 || type === 48)) {
      if (found !== undefined) fail(`npm archive contains duplicate package manifests: ${basename(archivePath)}`);
      if (size > MAX_MANIFEST_BYTES) fail(`npm package manifest is oversized: ${basename(archivePath)}`);
      try {
        found = JSON.parse(tar.subarray(dataStart, dataEnd).toString('utf8'));
      } catch {
        fail(`npm archive package manifest is invalid JSON: ${basename(archivePath)}`);
      }
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  if (found === undefined || found === null || typeof found !== 'object' || Array.isArray(found)) {
    fail(`npm archive is missing a package manifest: ${basename(archivePath)}`);
  }
  return found;
}

try {
  const values = parseArguments(process.argv.slice(2), ['directory', 'version']);
  const directory = resolve(values.get('directory'));
  const version = values.get('version');
  assertVersion(version);
  const directoryStat = lstatSync(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) fail('platform release set must be a real directory');
  const archivePaths = [];
  for (const entry of readdirSync(directory).sort()) {
    const path = join(directory, entry);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) fail(`platform release set contains a symbolic link: ${entry}`);
    if (entry.endsWith('.tgz')) {
      if (!stat.isFile()) fail(`unexpected package artifact: ${entry}`);
      archivePaths.push(path);
    }
  }
  if (archivePaths.length !== PLATFORM_PACKAGE_NAMES.length) {
    fail(`platform release set must contain exactly ${PLATFORM_PACKAGE_NAMES.length} npm tarballs`);
  }
  const seen = new Set();
  for (const archivePath of archivePaths) {
    const manifest = readPackageManifest(archivePath);
    if (!PLATFORM_PACKAGE_NAMES.includes(manifest.name)) fail(`unexpected platform package name: ${String(manifest.name)}`);
    if (seen.has(manifest.name)) fail(`duplicate platform package: ${manifest.name}`);
    seen.add(manifest.name);
    if (manifest.version !== version) fail(`platform package version does not match ${version}: ${manifest.name}`);
    if (Object.hasOwn(manifest, 'private')) fail(`staged platform package must be public: ${manifest.name}`);
    assertNoLifecycleScripts(manifest, manifest.name);
    const windows = manifest.name.startsWith('@palladin/runtime-win32-');
    const workerBinding = manifest.palladinRuntime;
    if (windows) {
      if (workerBinding === null || typeof workerBinding !== 'object'
        || Array.isArray(workerBinding)
        || Object.keys(workerBinding).join('\0') !== 'workerExecutableSha256'
        || !/^[0-9a-f]{64}$/.test(workerBinding.workerExecutableSha256)) {
        fail(`Windows platform package has no exact worker binding: ${manifest.name}`);
      }
    } else if (workerBinding !== undefined) {
      fail(`non-Windows platform package contains a Windows worker binding: ${manifest.name}`);
    }
  }
  if (seen.size !== PLATFORM_PACKAGE_NAMES.length) fail('platform release set is incomplete');
} catch (error) {
  process.stderr.write(`Error: ${error instanceof Error ? error.message : 'unknown platform release verification failure'}\n`);
  process.exitCode = 1;
}
