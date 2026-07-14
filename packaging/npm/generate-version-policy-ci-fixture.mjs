import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  lstatSync, readFileSync, realpathSync, writeFileSync,
} from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

import {
  canonicalizeVersionPolicyEnvelope,
  canonicalizeVersionPolicyPayload,
} from '../../dist/runtime/version-policy.js';

const packageRoots = [];
const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith('--') || value === undefined) fail();
  const name = key.slice(2);
  if (name === 'package-root') {
    packageRoots.push(value);
  } else if (['version', 'source-sha', 'output-bundle', 'output-public-key'].includes(name)
    && !values.has(name)) {
    values.set(name, value);
  } else {
    fail();
  }
}

const version = required('version');
const sourceSha = required('source-sha');
if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)
  || !/^[0-9a-f]{40}$/.test(sourceSha) || /^0{40}$/.test(sourceSha)
  || packageRoots.length === 0) fail();

const seen = new Set();
const artifacts = packageRoots.map((rootHint) => {
  const rootMetadata = lstatSync(rootHint);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) fail();
  const root = realpathSync(rootHint);
  const manifest = JSON.parse(readRegularFile(root, 'package.json', 128 * 1024).toString('utf8'));
  if (typeof manifest !== 'object' || manifest === null
    || !/^@palladin\/runtime-linux-(?:arm64|x64)-(?:gnu|musl)$/.test(manifest.name)
    || manifest.version !== version || manifest.private !== undefined
    || manifest.scripts !== undefined || manifest.dependencies !== undefined
    || manifest.optionalDependencies !== undefined || seen.has(manifest.name)) fail();
  seen.add(manifest.name);
  return {
    executableSha256: hash(readRegularFile(root, 'bin/palladin-linux-client')),
    packageName: manifest.name,
    sourceSha,
    version,
    workerExecutableSha256: hash(readRegularFile(root, 'bin/palladin-worker')),
  };
}).sort((left, right) => left.packageName < right.packageName ? -1 : 1);

const issued = new Date(Math.floor(Date.now() / 1000) * 1000);
const payload = {
  artifacts,
  blockedVersions: [],
  expiresAt: timestamp(new Date(issued.getTime() + 24 * 60 * 60 * 1000)),
  issuedAt: timestamp(issued),
  minimumVersion: version,
  recommendedVersion: version,
  schemaVersion: 1,
  sequence: 1,
  source: 'https://releases.palladin.io/agent/version-policy.json',
};
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const signature = sign(
  null,
  Buffer.from(canonicalizeVersionPolicyPayload(payload)),
  privateKey,
).toString('base64');
const envelope = canonicalizeVersionPolicyEnvelope({ signed: payload, signature });
const publicKeyBase64 = publicKey.export({ format: 'der', type: 'spki' })
  .subarray(-32)
  .toString('base64');
writeFileSync(resolve(required('output-bundle')), envelope, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
writeFileSync(resolve(required('output-public-key')), publicKeyBase64, {
  encoding: 'utf8', flag: 'wx', mode: 0o600,
});

function readRegularFile(root, path, maximum = 256 * 1024 * 1024) {
  const candidate = join(root, path);
  const metadata = lstatSync(candidate);
  if (!metadata.isFile() || metadata.isSymbolicLink()
    || metadata.size <= 0 || metadata.size > maximum) fail();
  const canonical = realpathSync(candidate);
  const pathFromRoot = relative(root, canonical);
  if (pathFromRoot === '' || pathFromRoot === '..' || pathFromRoot.startsWith(`..${sep}`)
    || isAbsolute(pathFromRoot)) fail();
  return readFileSync(canonical);
}

function hash(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function timestamp(date) {
  return date.toISOString().replace('.000Z', 'Z');
}

function required(name) {
  const value = values.get(name);
  if (value === undefined) fail();
  return value;
}

function fail() {
  process.stderr.write('CI version-policy fixture inputs are invalid\n');
  process.exit(1);
}
