#!/usr/bin/env node
import { copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PLATFORM_PACKAGE_NAMES,
  assertNoLifecycleScripts,
  assertVersion,
  fail,
  parseArguments,
  readJsonObject,
} from './release-policy.mjs';

const EXPECTED_FILES = Object.freeze(['dist/bin/', 'dist/runtime/', 'README.md', 'LICENSE', 'SECURITY.md']);
const OUTPUT_FIELDS = Object.freeze([
  'name', 'version', 'description', 'license', 'repository', 'homepage', 'bugs',
  'files', 'publishConfig', 'type', 'bin', 'engines', 'optionalDependencies',
]);

function copyAllowlisted(source, destination) {
  const stat = lstatSync(source);
  if (stat.isSymbolicLink()) fail(`refusing to stage symbolic link: ${source}`);
  if (stat.isDirectory()) {
    mkdirSync(destination, { recursive: true, mode: 0o755 });
    for (const entry of readdirSync(source).sort()) copyAllowlisted(join(source, entry), join(destination, entry));
    return;
  }
  if (!stat.isFile()) fail(`refusing to stage non-file entry: ${source}`);
  mkdirSync(dirname(destination), { recursive: true, mode: 0o755 });
  copyFileSync(source, destination);
}

function stage(argv) {
  const values = parseArguments(argv, ['output-dir', 'version']);
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  const source = resolve(values.get('source') ?? repositoryRoot);
  const output = resolve(values.get('output-dir'));
  const version = values.get('version');
  assertVersion(version);
  if (source === output) fail('source and output directories must differ');
  const manifest = readJsonObject(join(source, 'package.json'), 'source package manifest');
  if (manifest.name !== '@palladin/agent') fail('unexpected meta package name');
  if (manifest.private !== true) fail('source meta package must remain private');
  if (manifest.version !== version) fail('source meta package version does not match --version');
  assertNoLifecycleScripts(manifest, 'source meta package');
  if (JSON.stringify(manifest.files) !== JSON.stringify(EXPECTED_FILES)) fail('source files allowlist is not exact');
  if (JSON.stringify(manifest.publishConfig) !== JSON.stringify({ access: 'public', provenance: true })) {
    fail('source meta package must require public provenance publishing');
  }
  const dependencies = manifest.optionalDependencies;
  if (dependencies === null || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
    fail('source meta package optionalDependencies must be an object');
  }
  if (JSON.stringify(Object.keys(dependencies).sort()) !== JSON.stringify([...PLATFORM_PACKAGE_NAMES].sort())) {
    fail('source meta package must reference exactly the supported platform packages');
  }
  for (const name of PLATFORM_PACKAGE_NAMES) {
    if (dependencies[name] !== version) fail(`platform package must use exact version ${version}: ${name}`);
  }
  try {
    mkdirSync(output, { mode: 0o755 });
  } catch {
    fail('output directory must not already exist and its parent must exist');
  }
  for (const entry of EXPECTED_FILES) {
    if (isAbsolute(entry) || entry.includes('..') || entry.includes('\\')) fail('unsafe source files allowlist entry');
    const normalized = entry.replace(/\/$/, '');
    const sourcePath = resolve(source, normalized);
    const sourceRelative = relative(source, sourcePath);
    if (sourceRelative.startsWith(`..${sep}`) || sourceRelative === '..') fail('source files allowlist escapes the package');
    copyAllowlisted(sourcePath, join(output, normalized));
  }
  const staged = {};
  for (const field of OUTPUT_FIELDS) {
    if (Object.hasOwn(manifest, field)) staged[field] = manifest[field];
  }
  writeFileSync(join(output, 'package.json'), `${JSON.stringify(staged, null, 2)}\n`, { mode: 0o644 });
}

try {
  stage(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`Error: ${error instanceof Error ? error.message : 'unknown staging failure'}\n`);
  process.exitCode = 1;
}
