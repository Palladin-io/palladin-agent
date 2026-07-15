import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { basename, dirname, relative, resolve, sep } from 'node:path';
import {
  assertRegularFile,
  assertSourceSha,
  assertVersion,
  fail,
  parseArguments,
  readJsonObject,
} from './release-policy.mjs';

export const MANIFEST_SCHEMA_VERSION = 1;

export function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function directChild(directory, path, subject) {
  const rel = relative(directory, path);
  if (rel === '' || rel.startsWith(`..${sep}`) || rel === '..' || rel.includes(sep)) {
    fail(`${subject} must be a direct child of the artifacts directory`);
  }
  if (basename(path).includes('\n') || basename(path).includes('\r')) fail(`${subject} has an unsafe filename`);
}

export function loadReleaseInputs(argv) {
  const values = parseArguments(argv, ['artifacts', 'version', 'source-sha', 'sbom', 'manifest', 'checksums']);
  const artifactsDirectory = resolve(values.get('artifacts'));
  const version = values.get('version');
  const sourceSha = values.get('source-sha');
  const sbomPath = resolve(values.get('sbom'));
  const manifestPath = resolve(values.get('manifest'));
  const checksumsPath = resolve(values.get('checksums'));
  assertVersion(version);
  assertSourceSha(sourceSha);
  const directoryStat = lstatSync(artifactsDirectory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) fail('artifacts must be a real directory');
  directChild(artifactsDirectory, sbomPath, 'SBOM');
  assertRegularFile(sbomPath, 'SBOM');
  readJsonObject(sbomPath, 'SBOM');
  if (manifestPath === checksumsPath || manifestPath === sbomPath || checksumsPath === sbomPath) {
    fail('SBOM, manifest, and checksums paths must be distinct');
  }
  const excluded = new Set([manifestPath, checksumsPath, sbomPath]);
  const artifactPaths = [];
  for (const entry of readdirSync(artifactsDirectory).sort()) {
    const path = resolve(artifactsDirectory, entry);
    if (excluded.has(path)) continue;
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isFile()) fail(`unexpected non-file release entry: ${entry}`);
    if (entry.includes('\n') || entry.includes('\r')) fail('artifact has an unsafe filename');
    artifactPaths.push(path);
  }
  if (artifactPaths.length === 0) fail('release contains no artifacts');
  return { artifactsDirectory, version, sourceSha, sbomPath, manifestPath, checksumsPath, artifactPaths };
}

export function expectedReleaseManifest(inputs) {
  const sbom = { filename: basename(inputs.sbomPath), sha256: sha256(inputs.sbomPath) };
  return {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    version: inputs.version,
    sourceSha: inputs.sourceSha,
    artifacts: inputs.artifactPaths.map((path) => {
      const stat = assertRegularFile(path, `artifact ${basename(path)}`);
      return {
        filename: basename(path),
        size: stat.size,
        sha256: sha256(path),
        sbom,
      };
    }),
  };
}

export function expectedChecksums(inputs) {
  return [...inputs.artifactPaths, inputs.sbomPath]
    .sort((left, right) => basename(left).localeCompare(basename(right)))
    .map((path) => `${sha256(path)}  ${basename(path)}`)
    .join('\n') + '\n';
}

export function assertOutputParent(path, subject) {
  const parent = dirname(path);
  const stat = lstatSync(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${subject} parent must be a real directory`);
}
