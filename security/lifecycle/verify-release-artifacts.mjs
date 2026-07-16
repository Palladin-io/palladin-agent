import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA256 = /^[0-9a-f]{64}$/;
const SOURCE_SHA = /^[0-9a-f]{40}$/;
function fail(message) { throw new Error(message); }
function record(value, label) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(`${label} is invalid`);
  return value;
}
function readJson(path, label) {
  const absolute = resolve(path);
  const descriptor = openSync(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor);
    const linked = lstatSync(absolute);
    if (!opened.isFile() || linked.isSymbolicLink() || opened.dev !== linked.dev || opened.ino !== linked.ino) {
      fail(`${label} changed while it was opened`);
    }
    return JSON.parse(readFileSync(descriptor, 'utf8'));
  } catch (error) {
    fail(`${label} must be valid JSON: ${error instanceof Error ? error.message : 'unknown error'}`);
  } finally { closeSync(descriptor); }
}
function manifestArtifacts(manifestInput, label, sourceSha, version) {
  const manifest = record(manifestInput, label);
  if (manifest.sourceSha !== sourceSha || manifest.version !== version || !Array.isArray(manifest.artifacts)) {
    fail(`${label} release binding is invalid`);
  }
  return manifest.artifacts.map((artifactInput, index) => {
    const artifact = record(artifactInput, `${label}.artifacts[${index}]`);
    if (typeof artifact.filename !== 'string' || basename(artifact.filename) !== artifact.filename
      || typeof artifact.sha256 !== 'string' || !SHA256.test(artifact.sha256)) {
      fail(`${label}.artifacts[${index}] is invalid`);
    }
    return { filename: artifact.filename, sha256: artifact.sha256 };
  });
}
function roleMatches(targetId, role, filename, version) {
  if (role === 'agent-npm') return filename === `palladin-agent-${version}.tgz`;
  let match = /^macos-(arm64|x64)$/.exec(targetId);
  if (match) {
    if (role === 'platform-npm') return filename === `palladin-runtime-darwin-${match[1]}-${version}.tgz`;
    if (role === 'signed-runtime') return filename === 'palladin-runtime-darwin-universal.zip';
  }
  match = /^windows-(arm64|x64)$/.exec(targetId);
  if (match) {
    if (role === 'platform-npm') return filename === `palladin-runtime-win32-${match[1]}-${version}.tgz`;
    if (role === 'signed-installer') return filename === `palladin-runtime-setup-${match[1]}-${version}.zip`;
  }
  match = /^(?:ubuntu-24\.04|debian-13)-(arm64|x64)$/.exec(targetId);
  if (match) {
    if (role === 'platform-npm') return filename === `palladin-runtime-linux-${match[1]}-gnu-${version}.tgz`;
    if (role === 'deb') return filename === `palladin-runtime_${version}_${match[1] === 'arm64' ? 'arm64' : 'amd64'}.deb`;
  }
  match = /^fedora-42-(arm64|x64)$/.exec(targetId);
  if (match) {
    if (role === 'platform-npm') return filename === `palladin-runtime-linux-${match[1]}-gnu-${version}.tgz`;
    if (role === 'rpm') return filename === `palladin-runtime-${version}-1.${match[1] === 'arm64' ? 'aarch64' : 'x86_64'}.rpm`;
  }
  match = /^alpine-3\.22-(arm64|x64)$/.exec(targetId);
  if (match && role === 'platform-npm') return filename === `palladin-runtime-linux-${match[1]}-musl-${version}.tgz`;
  return false;
}

export function verifyReleaseArtifactBindings({ report: reportInput, platformManifest, agentManifest }) {
  const report = record(reportInput, 'lifecycle report');
  if (!SOURCE_SHA.test(report.sourceSha) || !Array.isArray(report.targets)) fail('lifecycle report binding is invalid');
  const platform = record(platformManifest, 'platform manifest');
  if (typeof platform.version !== 'string') fail('platform version is invalid');
  const artifacts = manifestArtifacts(platform, 'platform manifest', report.sourceSha, platform.version);
  if (agentManifest === undefined) fail('agent manifest is required');
  artifacts.push(...manifestArtifacts(agentManifest, 'agent manifest', report.sourceSha, platform.version));
  const known = new Map(artifacts.map((artifact) => [artifact.filename, artifact.sha256]));
  for (const [targetIndex, targetInput] of report.targets.entries()) {
    const target = record(targetInput, `report.targets[${targetIndex}]`);
    if (typeof target.targetId !== 'string' || !Array.isArray(target.artifacts)) fail('report target is invalid');
    for (const [artifactIndex, artifactInput] of target.artifacts.entries()) {
      const artifact = record(artifactInput, `report.targets[${targetIndex}].artifacts[${artifactIndex}]`);
      if (artifact.phase !== 'candidate') continue;
      if (artifact.version !== platform.version || artifact.sourceSha !== report.sourceSha
        || typeof artifact.role !== 'string' || typeof artifact.filename !== 'string'
        || typeof artifact.sha256 !== 'string' || !SHA256.test(artifact.sha256)
        || !roleMatches(target.targetId, artifact.role, artifact.filename, platform.version)) {
        fail(`lifecycle report artifact role is invalid: ${target.targetId}`);
      }
      if (known.get(artifact.filename) !== artifact.sha256) {
        fail(`lifecycle report artifact does not match the staged release: ${target.targetId}/${artifact.role}`);
      }
    }
  }
  return true;
}

function parse(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index]; const value = argv[index + 1];
    if (!['--report', '--platform-manifest', '--agent-manifest'].includes(flag)
      || !value || values.has(flag)) fail('invalid arguments');
    values.set(flag, value);
  }
  for (const required of ['--report', '--platform-manifest', '--agent-manifest']) {
    if (!values.has(required)) fail(`${required} is required`);
  }
  return values;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const values = parse(process.argv.slice(2));
    verifyReleaseArtifactBindings({
      report: readJson(values.get('--report'), 'lifecycle report'),
      platformManifest: readJson(values.get('--platform-manifest'), 'platform manifest'),
      agentManifest: readJson(values.get('--agent-manifest'), 'agent manifest'),
    });
  } catch (error) {
    process.stderr.write(`lifecycle release artifact verification failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  }
}
