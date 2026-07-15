import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA256 = /^[0-9a-f]{64}$/;
const SOURCE_SHA = /^[0-9a-f]{40}$/;

function fail(message) {
  throw new Error(message);
}

function readJson(path, label) {
  const absolute = resolve(path);
  const descriptor = openSync(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor);
    const linked = lstatSync(absolute);
    if (!opened.isFile() || linked.isSymbolicLink()
      || opened.dev !== linked.dev || opened.ino !== linked.ino) {
      fail(`${label} changed while it was opened`);
    }
    return JSON.parse(readFileSync(descriptor, 'utf8'));
  } catch {
    fail(`${label} must be valid JSON`);
  } finally {
    closeSync(descriptor);
  }
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!['--report', '--platform-manifest', '--agent-manifest'].includes(flag)
      || !value || values.has(flag)) fail('invalid arguments');
    values.set(flag, value);
  }
  for (const flag of ['--report', '--platform-manifest']) {
    if (!values.has(flag)) fail(`${flag} is required`);
  }
  return values;
}

function artifactSelector(targetTierId) {
  let match = /^macos-(arm64|x64)-hardened$/.exec(targetTierId);
  if (match) return (name) => new RegExp(`^palladin-runtime-darwin-${match[1]}-.+\\.tgz$`).test(name);
  match = /^windows-(arm64|x64)-hardened$/.exec(targetTierId);
  if (match) return (name) => new RegExp(`^palladin-runtime-win32-${match[1]}-.+\\.tgz$`).test(name);
  match = /^linux-(gnu|musl)-(arm64|x64)-convenience$/.exec(targetTierId);
  if (match) return (name) => new RegExp(`^palladin-runtime-linux-${match[2]}-${match[1]}-.+\\.tgz$`).test(name);
  match = /^linux-gnu-(arm64|x64)-hardened-(deb|rpm)$/.exec(targetTierId);
  if (match) {
    const debArchitecture = match[1] === 'arm64' ? 'arm64' : 'amd64';
    const rpmArchitecture = match[1] === 'arm64' ? 'aarch64' : 'x86_64';
    if (match[2] === 'deb') {
      return (name) => name.startsWith('palladin-runtime_') && name.endsWith(`_${debArchitecture}.deb`);
    }
    return (name) => name.startsWith('palladin-runtime-') && name.endsWith(`.${rpmArchitecture}.rpm`);
  }
  if (/^(?:macos|windows)-(?:arm64|x64)-convenience-source$/.test(targetTierId)) return null;
  fail(`report contains an unknown release target: ${targetTierId}`);
}

function manifestArtifacts(manifest, label, expectedSourceSha, expectedVersion) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)
    || manifest.sourceSha !== expectedSourceSha || manifest.version !== expectedVersion
    || !Array.isArray(manifest.artifacts)) fail(`${label} release binding is invalid`);
  return manifest.artifacts.map((artifact) => {
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)
      || typeof artifact.filename !== 'string' || basename(artifact.filename) !== artifact.filename
      || !SHA256.test(artifact.sha256)) fail(`${label} contains an invalid artifact binding`);
    return { filename: artifact.filename, sha256: artifact.sha256 };
  });
}

export function verifyReleaseArtifactBindings({ report, platformManifest, agentManifest }) {
  if (!report || typeof report !== 'object' || Array.isArray(report)
    || !SOURCE_SHA.test(report.sourceSha) || !Array.isArray(report.coverage)) {
    fail('adversarial report release binding is invalid');
  }
  if (!platformManifest || typeof platformManifest.version !== 'string') {
    fail('platform release version is invalid');
  }
  const artifacts = manifestArtifacts(
    platformManifest,
    'platform manifest',
    report.sourceSha,
    platformManifest.version,
  );
  if (agentManifest !== undefined) {
    artifacts.push(...manifestArtifacts(
      agentManifest,
      'agent manifest',
      report.sourceSha,
      platformManifest.version,
    ));
  }
  const digestByTarget = new Map();
  for (const cell of report.coverage) {
    if (!cell || typeof cell !== 'object' || Array.isArray(cell)
      || typeof cell.targetTierId !== 'string') fail('report contains an invalid coverage cell');
    if (cell.evidenceRequirement === 'not-applicable') continue;
    if (!SHA256.test(cell.artifactSha256)) fail('report contains an invalid artifact digest');
    const existing = digestByTarget.get(cell.targetTierId);
    if (existing !== undefined && existing !== cell.artifactSha256) {
      fail(`target uses more than one artifact digest: ${cell.targetTierId}`);
    }
    digestByTarget.set(cell.targetTierId, cell.artifactSha256);
  }
  for (const [targetTierId, digest] of digestByTarget) {
    const selector = artifactSelector(targetTierId);
    if (selector === null) continue;
    if (!artifacts.some((artifact) => selector(artifact.filename) && artifact.sha256 === digest)) {
      fail(`report artifact digest does not match the staged target: ${targetTierId}`);
    }
  }
  return true;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const values = parseArguments(process.argv.slice(2));
    verifyReleaseArtifactBindings({
      report: readJson(values.get('--report'), 'report'),
      platformManifest: readJson(values.get('--platform-manifest'), 'platform manifest'),
      agentManifest: values.has('--agent-manifest')
        ? readJson(values.get('--agent-manifest'), 'agent manifest')
        : undefined,
    });
  } catch (error) {
    process.stderr.write(`adversarial artifact binding failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  }
}
