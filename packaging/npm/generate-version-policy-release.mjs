import { createHash } from 'node:crypto';
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync, writeFileSync,
} from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

import {
  canonicalizeVersionPolicyPayload,
  parseAndVerifyHistoricalVersionPolicy,
} from '../../dist/runtime/version-policy.js';

const values = argumentsOf([
  'node-modules', 'version', 'source-sha', 'current', 'public-key', 'issued-at',
  'windows-publisher', 'windows-thumbprint', 'output',
]);
const version = required('version');
const sourceSha = required('source-sha');
const issuedAt = required('issued-at');
if (!exactVersion(version) || !/^[0-9a-f]{40}$/.test(sourceSha)
  || !exactTimestamp(issuedAt) || !/^(?:[0-9A-F]{40}|[0-9A-F]{64})$/.test(required('windows-thumbprint'))) fail();
const issued = new Date(issuedAt);
const modules = resolve(required('node-modules'));
const canonicalModules = realpathSync(modules);
const packages = [
  ['@palladin/runtime-darwin-arm64', 'PalladinRuntime.app/Contents/MacOS/palladin', 'PalladinRuntime.app/Contents/MacOS/palladin'],
  ['@palladin/runtime-darwin-x64', 'PalladinRuntime.app/Contents/MacOS/palladin', 'PalladinRuntime.app/Contents/MacOS/palladin'],
  ['@palladin/runtime-linux-arm64-gnu', 'bin/palladin-linux-client', 'bin/palladin-worker'],
  ['@palladin/runtime-linux-arm64-musl', 'bin/palladin-linux-client', 'bin/palladin-worker'],
  ['@palladin/runtime-linux-x64-gnu', 'bin/palladin-linux-client', 'bin/palladin-worker'],
  ['@palladin/runtime-linux-x64-musl', 'bin/palladin-linux-client', 'bin/palladin-worker'],
  ['@palladin/runtime-win32-arm64', 'bin/palladin-client.exe', null],
  ['@palladin/runtime-win32-x64', 'bin/palladin-client.exe', null],
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
  let workerExecutableSha256;
  if (worker === null) {
    workerExecutableSha256 = manifest.palladinRuntime?.workerExecutableSha256;
    if (!/^[0-9a-f]{64}$/.test(workerExecutableSha256 ?? '')) fail();
  } else {
    const workerPath = join(canonicalRoot, worker);
    const canonicalWorker = realpathSync(workerPath);
    assertInside(canonicalRoot, canonicalWorker);
    workerExecutableSha256 = createHash('sha256').update(readVerifiedFile(
      workerPath, canonicalRoot, 256 * 1024 * 1024,
    )).digest('hex');
  }
  const artifact = {
    executableSha256: createHash('sha256').update(executableBytes).digest('hex'),
    packageName: name,
    sourceSha,
    version,
    workerExecutableSha256,
  };
  return name.includes('/runtime-win32-') ? {
    authenticodePublisher: required('windows-publisher'),
    authenticodeThumbprint: required('windows-thumbprint'),
    ...artifact,
  } : artifact;
});

let current;
const currentPath = resolve(required('current'));
const currentBytes = readOptionalRegularFile(currentPath, 4 * 1024 * 1024);
if (currentBytes !== undefined && currentBytes.length > 0) {
  current = parseAndVerifyHistoricalVersionPolicy(currentBytes, {
    publicKeyBase64: required('public-key'),
    source: 'https://releases.palladin.io/agent/version-policy.json',
  }).signed;
}
if (current !== undefined) {
  for (const artifact of releaseArtifacts) {
    const immutable = current.artifacts.find((candidate) => candidate.packageName === artifact.packageName
      && candidate.version === artifact.version);
    if (immutable !== undefined && !sameArtifact(immutable, artifact)) fail();
  }
  if (current.recommendedVersion === version) {
    const currentRelease = current.artifacts.filter((artifact) => artifact.version === version);
    if (currentRelease.length !== releaseArtifacts.length
      || releaseArtifacts.some((artifact) => !currentRelease.some(
        (candidate) => sameArtifact(candidate, artifact),
      ))) fail();
    writeFileSync(resolve(required('output')), canonicalizeVersionPolicyPayload(current), { mode: 0o600 });
    process.exit(0);
  }
}
const previous = current?.artifacts.filter(
  (artifact) => artifact.version === current.recommendedVersion && artifact.version !== version,
) ?? [];
const expiresAt = new Date(issued.getTime() + 30 * 24 * 60 * 60 * 1000)
  .toISOString().replace('.000Z', 'Z');
const payload = {
  artifacts: [...previous, ...releaseArtifacts]
    .sort((left, right) => ascii(`${left.packageName}@${left.version}`, `${right.packageName}@${right.version}`)),
  blockedVersions: current?.blockedVersions ?? [],
  expiresAt,
  issuedAt,
  minimumVersion: current?.recommendedVersion ?? version,
  recommendedVersion: version,
  schemaVersion: 1,
  sequence: (current?.sequence ?? 0) + 1,
  source: 'https://releases.palladin.io/agent/version-policy.json',
};
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
function exactTimestamp(value) { const date = new Date(value); return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && date.toISOString() === value.replace('Z', '.000Z'); }
function ascii(left, right) { return left < right ? -1 : left > right ? 1 : 0; }
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
function readOptionalRegularFile(path, maximumSize) {
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (error?.code === 'ENOENT') return undefined;
    fail();
  }
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size < 0 || metadata.size > maximumSize) fail();
    const bytes = readFileSync(descriptor);
    if (bytes.length !== metadata.size) fail();
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}
function sameArtifact(left, right) {
  return left.packageName === right.packageName && left.version === right.version
    && left.sourceSha === right.sourceSha && left.executableSha256 === right.executableSha256
    && left.workerExecutableSha256 === right.workerExecutableSha256
    && left.authenticodePublisher === right.authenticodePublisher
    && left.authenticodeThumbprint === right.authenticodeThumbprint;
}
function fail() { process.stderr.write('release policy inputs or immutable artifact bindings are invalid\n'); process.exit(1); }
