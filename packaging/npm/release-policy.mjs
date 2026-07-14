import { lstatSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export const PLATFORM_PACKAGE_NAMES = Object.freeze([
  '@palladin/runtime-darwin-arm64',
  '@palladin/runtime-darwin-x64',
  '@palladin/runtime-linux-arm64-gnu',
  '@palladin/runtime-linux-arm64-musl',
  '@palladin/runtime-linux-x64-gnu',
  '@palladin/runtime-linux-x64-musl',
  '@palladin/runtime-win32-arm64',
  '@palladin/runtime-win32-x64',
]);

export const PUBLIC_PACKAGE_NAMES = Object.freeze([
  '@palladin/agent',
  ...PLATFORM_PACKAGE_NAMES,
]);

export const LIFECYCLE_SCRIPT_NAMES = Object.freeze([
  'preinstall', 'install', 'postinstall',
  'prepack', 'prepare', 'postpack',
  'prepublish', 'prepublishOnly', 'publish', 'postpublish',
]);

export function fail(message) {
  throw new Error(message);
}

export function parseArguments(argv, required) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined || values.has(key.slice(2))) {
      fail('invalid or duplicate command-line argument');
    }
    values.set(key.slice(2), value);
  }
  for (const key of required) {
    if (!values.has(key)) fail(`missing --${key}`);
  }
  return values;
}

export function assertVersion(version) {
  if (typeof version !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(version)) {
    fail('version must be an exact semantic version');
  }
}

export function assertSourceSha(sourceSha) {
  if (typeof sourceSha !== 'string' || !/^[0-9a-f]{40}$/.test(sourceSha)) {
    fail('source SHA must be a lowercase 40-character Git commit hash');
  }
}

export function assertNoLifecycleScripts(manifest, subject = 'package') {
  const scripts = manifest?.scripts;
  if (scripts === undefined) return;
  if (scripts === null || typeof scripts !== 'object' || Array.isArray(scripts)) {
    fail(`${subject} scripts must be an object`);
  }
  for (const lifecycle of LIFECYCLE_SCRIPT_NAMES) {
    if (Object.hasOwn(scripts, lifecycle)) fail(`${subject} contains forbidden lifecycle script: ${lifecycle}`);
  }
}

export function readJsonObject(path, subject) {
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    fail(`${subject} is not valid JSON`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${subject} must contain a JSON object`);
  }
  return value;
}

export function assertRegularFile(path, subject) {
  let stat;
  try {
    stat = lstatSync(resolve(path));
  } catch {
    fail(`${subject} does not exist`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${subject} must be a regular file`);
  return stat;
}
