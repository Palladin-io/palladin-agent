import { createHash } from 'node:crypto';
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync, writeFileSync,
} from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

import {
  canonicalizeVersionPolicyPayload,
} from '../../dist/runtime/version-policy.js';

const values = argumentsOf([
  'node-modules', 'version', 'source-sha', 'output',
]);
const version = required('version');
const sourceSha = required('source-sha');
if (!exactVersion(version) || !/^[0-9a-f]{40}$/.test(sourceSha)) fail();
const modules = resolve(required('node-modules'));
const canonicalModules = realpathSync(modules);
const packages = [
  ['@palladin/runtime-darwin-arm64', 'PalladinRuntime.app/Contents/MacOS/palladin', 'PalladinRuntime.app/Contents/MacOS/palladin'],
  ['@palladin/runtime-linux-arm64-gnu', 'bin/palladin-linux-client', 'bin/palladin-worker'],
  ['@palladin/runtime-linux-arm64-musl', 'bin/palladin-linux-client', 'bin/palladin-worker'],
  ['@palladin/runtime-linux-x64-gnu', 'bin/palladin-linux-client', 'bin/palladin-worker'],
  ['@palladin/runtime-linux-x64-musl', 'bin/palladin-linux-client', 'bin/palladin-worker'],
];
const releaseArtifacts = packages.map(([name, executable, worker]) => {
  const root = join(modules, ...name.split('/'));
  const rootMetadata = lstatSync(root);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) fail();
  const canonicalRoot = realpathSync(root);
  assertInside(canonicalModules, canonicalRoot);
  const manifest = JSON.parse(readVerifiedFile(
    join(canonicalRoot, 'package.json'), canonicalRoot, 128 * 1024,
  ).toString('utf8'));
  if (manifest.name !== name || manifest.version !== version) fail();
  const executablePath = join(canonicalRoot, executable);
  const canonicalExecutable = realpathSync(executablePath);
  assertInside(canonicalRoot, canonicalExecutable);
  const executableBytes = readVerifiedFile(
    executablePath, canonicalRoot, 256 * 1024 * 1024,
  );
  const workerPath = join(canonicalRoot, worker);
  const canonicalWorker = realpathSync(workerPath);
  assertInside(canonicalRoot, canonicalWorker);
  const workerExecutableSha256 = createHash('sha256').update(readVerifiedFile(
    workerPath, canonicalRoot, 256 * 1024 * 1024,
  )).digest('hex');
  const artifact = {
    executableSha256: createHash('sha256').update(executableBytes).digest('hex'),
    packageName: name,
    sourceSha,
    version,
    workerExecutableSha256,
  };
  return artifact;
});

const payload = { artifacts: releaseArtifacts, schemaVersion: 2 };
writeFileSync(resolve(required('output')), canonicalizeVersionPolicyPayload(payload), { mode: 0o600 });

function argumentsOf(allowed) {
  const result = new Map();
  for (let index = 2; index < process.argv.length; index += 2) {
    const key = process.argv[index];
    const value = process.argv[index + 1];
    if (!key?.startsWith('--') || value === undefined || result.has(key.slice(2))
      || !allowed.includes(key.slice(2))) fail();
    result.set(key.slice(2), value);
  }
  return result;
}
function required(name) { const value = values.get(name); if (value === undefined) fail(); return value; }
function exactVersion(value) { return /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value) && value.split('.').every((part) => Number.isSafeInteger(Number(part))); }
function assertInside(parent, child) {
  const path = relative(parent, child);
  if (path === '' || path === '..' || path.startsWith(`..${sep}`) || isAbsolute(path)) fail();
}
function readVerifiedFile(path, parent, maximumSize) {
  const canonicalPath = realpathSync(path);
  assertInside(parent, canonicalPath);
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maximumSize) fail();
    const bytes = readFileSync(descriptor);
    if (bytes.length !== metadata.size) fail();
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}
function fail() { process.stderr.write('release policy inputs or immutable artifact bindings are invalid\n'); process.exit(1); }
