import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_MANIFEST_PATH = resolve(HERE, 'coverage-manifest.json');
const SOURCE_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const SECRET_FIELD = /^(?:secret|password|apiKey|privateKey|accessToken|authorization|cookie|mnemonic)$/i;
const SECRET_VALUE = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+\S+|\b(?:pl|sk|ghp|npm)_[A-Za-z0-9_-]{8,})/i;

function fail(message) { throw new Error(message); }
function isRecord(value) { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function record(value, label) { if (!isRecord(value)) fail(`${label} must be an object`); return value; }
function array(value, label) { if (!Array.isArray(value)) fail(`${label} must be an array`); return value; }
function string(value, label) { if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a non-empty string`); return value; }
function integer(value, label) { if (!Number.isSafeInteger(value)) fail(`${label} must be an integer`); return value; }
function exactKeys(value, keys, label) {
  const actual = Object.keys(record(value, label)).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} must contain exactly: ${expected.join(', ')}`);
  }
}
function unique(items, key, label) {
  const seen = new Set();
  for (const [index, item] of items.entries()) {
    const value = string(record(item, `${label}[${index}]`)[key], `${label}[${index}].${key}`);
    if (!ID.test(value) || seen.has(value)) fail(`${label} contains an invalid or duplicate ${key}`);
    seen.add(value);
  }
  return seen;
}
function timestamp(value, label) {
  const text = string(value, label);
  const time = Date.parse(text);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== text) fail(`${label} must be an ISO-8601 UTC timestamp`);
  return time;
}
function fresh(value, now, hours, label) {
  const observed = timestamp(value, label);
  if (observed > now.getTime() + 5 * 60 * 1000) fail(`${label} is in the future`);
  if (now.getTime() - observed > hours * 60 * 60 * 1000) fail(`${label} is stale`);
}
function sha(value, pattern, label) {
  const text = string(value, label);
  if (!pattern.test(text)) fail(`${label} has an invalid digest`);
  return text;
}
function nullableSha(value, label) { return value === null ? null : sha(value, SHA256, label); }
function version(value, label) {
  const text = string(value, label);
  if (!VERSION.test(text)) fail(`${label} must be strict semantic version core`);
  return text;
}
function nullableVersion(value, label) { return value === null ? null : version(value, label); }
function compareVersion(left, right) {
  const a = left.split('.').map(Number);
  const b = right.split('.').map(Number);
  for (let index = 0; index < 3; index += 1) if (a[index] !== b[index]) return a[index] - b[index];
  return 0;
}
function noSecrets(value, label = 'value') {
  if (Array.isArray(value)) return value.forEach((item, index) => noSecrets(item, `${label}[${index}]`));
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_FIELD.test(key)) fail(`${label}.${key} is a secret-bearing field`);
      noSecrets(item, `${label}.${key}`);
    }
  } else if (typeof value === 'string' && SECRET_VALUE.test(value)) fail(`${label} contains secret-shaped material`);
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
export function canonicalSha256(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}
export function loadManifest(path = DEFAULT_MANIFEST_PATH) { return JSON.parse(readFileSync(path, 'utf8')); }

export function validateManifest(input) {
  const manifest = record(input, 'manifest');
  exactKeys(manifest, ['schemaVersion', 'reportSchemaVersion', 'evidenceFreshnessHours', 'steps', 'artifactPhases', 'targets'], 'manifest');
  if (integer(manifest.schemaVersion, 'manifest.schemaVersion') !== 1
    || integer(manifest.reportSchemaVersion, 'manifest.reportSchemaVersion') !== 1) fail('unsupported lifecycle schema');
  const freshness = integer(manifest.evidenceFreshnessHours, 'manifest.evidenceFreshnessHours');
  if (freshness < 1 || freshness > 720) fail('manifest.evidenceFreshnessHours is invalid');
  const steps = array(manifest.steps, 'manifest.steps');
  unique(steps, 'id', 'manifest.steps');
  const requiredSteps = [
    'install', 'enroll', 'mcp', 'update', 'concurrent-mcp', 'repair',
    'downgrade-rejected', 'rollback', 'reinstall', 'purge', 'uninstall',
  ];
  if (canonicalJson(steps.map((step) => step.id)) !== canonicalJson(requiredSteps)) fail('manifest.steps has an invalid lifecycle');
  steps.forEach((step, index) => {
    exactKeys(step, ['id', 'order'], `manifest.steps[${index}]`);
    if (integer(step.order, `manifest.steps[${index}].order`) !== index + 1) fail('manifest.steps order is invalid');
  });
  const phases = array(manifest.artifactPhases, 'manifest.artifactPhases');
  if (canonicalJson(phases) !== canonicalJson(['baseline', 'candidate', 'forward-rollback'])) {
    fail('manifest.artifactPhases is invalid');
  }
  const targets = array(manifest.targets, 'manifest.targets');
  unique(targets, 'id', 'manifest.targets');
  const matrix = new Set();
  for (const [index, target] of targets.entries()) {
    const label = `manifest.targets[${index}]`;
    exactKeys(target, ['id', 'os', 'arch', 'distribution', 'libc', 'requiredArtifactRoles'], label);
    if (!['macos', 'windows', 'linux'].includes(target.os)) fail(`${label}.os is invalid`);
    if (!['arm64', 'x64'].includes(target.arch)) fail(`${label}.arch is invalid`);
    string(target.distribution, `${label}.distribution`);
    if (!['none', 'gnu', 'musl'].includes(target.libc)) fail(`${label}.libc is invalid`);
    const roles = array(target.requiredArtifactRoles, `${label}.requiredArtifactRoles`);
    if (roles.length < 2 || new Set(roles).size !== roles.length) fail(`${label}.requiredArtifactRoles is invalid`);
    roles.forEach((role, roleIndex) => {
      if (!ID.test(string(role, `${label}.requiredArtifactRoles[${roleIndex}]`))) fail(`${label} contains an invalid artifact role`);
    });
    matrix.add(`${target.distribution}:${target.arch}`);
  }
  for (const distribution of ['macos', 'windows-11', 'ubuntu-24.04', 'debian-13', 'fedora-42', 'alpine-3.22']) {
    for (const arch of ['arm64', 'x64']) if (!matrix.has(`${distribution}:${arch}`)) fail(`manifest misses ${distribution}/${arch}`);
  }
  noSecrets(manifest, 'manifest');
  return manifest;
}

function evidenceRef(value, runId, runAttempt, targetId, stepId, label) {
  const ref = string(value, label);
  const match = /^github-actions:\/\/runs\/([1-9][0-9]*)\/attempts\/([1-9][0-9]*)\/targets\/([A-Za-z0-9._-]+)\/steps\/([A-Za-z0-9._-]+)$/.exec(ref);
  if (!match || match[1] !== runId || Number(match[2]) !== runAttempt
    || match[3] !== targetId || match[4] !== stepId) {
    fail(`${label} must bind the exact physical workflow run, attempt, target and step`);
  }
  return ref;
}

function normalizeArtifacts(input, target, phases, candidateSourceSha, label) {
  const artifacts = array(input, label);
  if (artifacts.length !== target.requiredArtifactRoles.length * phases.length) fail(`${label} has an invalid artifact count`);
  const byPhaseRole = new Map();
  const phaseVersions = new Map();
  const phaseSources = new Map();
  for (const [index, artifact] of artifacts.entries()) {
    const item = `${label}[${index}]`;
    exactKeys(artifact, ['phase', 'role', 'version', 'sourceSha', 'filename', 'sha256'], item);
    const phase = string(artifact.phase, `${item}.phase`);
    const role = string(artifact.role, `${item}.role`);
    const filename = string(artifact.filename, `${item}.filename`);
    const key = `${phase}:${role}`;
    if (!phases.includes(phase) || !target.requiredArtifactRoles.includes(role) || byPhaseRole.has(key)) {
      fail(`${item}.phase/role is invalid or duplicate`);
    }
    if (basename(filename) !== filename || filename.includes('\n') || filename.includes('\r')) fail(`${item}.filename is invalid`);
    const artifactVersion = version(artifact.version, `${item}.version`);
    const artifactSource = sha(artifact.sourceSha, SOURCE_SHA, `${item}.sourceSha`);
    if (phaseVersions.has(phase) && phaseVersions.get(phase) !== artifactVersion) fail(`${item}.version conflicts within its phase`);
    if (phaseSources.has(phase) && phaseSources.get(phase) !== artifactSource) fail(`${item}.sourceSha conflicts within its phase`);
    phaseVersions.set(phase, artifactVersion);
    phaseSources.set(phase, artifactSource);
    byPhaseRole.set(key, {
      phase, role, version: artifactVersion, sourceSha: artifactSource, filename,
      sha256: sha(artifact.sha256, SHA256, `${item}.sha256`),
    });
  }
  if (phaseSources.get('candidate') !== candidateSourceSha) fail(`${label} candidate source does not match the release source`);
  const baseline = phaseVersions.get('baseline');
  const candidate = phaseVersions.get('candidate');
  const rollback = phaseVersions.get('forward-rollback');
  if (!baseline || !candidate || !rollback
    || compareVersion(baseline, candidate) >= 0 || compareVersion(candidate, rollback) >= 0) {
    fail(`${label} must bind strictly increasing baseline, candidate and forward-rollback versions`);
  }
  return {
    artifacts: phases.flatMap((phase) => target.requiredArtifactRoles.map((role) => byPhaseRole.get(`${phase}:${role}`))),
    versions: { baseline, candidate, rollback },
  };
}

function normalizeStep(input, runId, runAttempt, targetId, expected, previous, versions, now, freshnessHours, label) {
  const step = record(input, label);
  exactKeys(step, [
    'stepId', 'order', 'result', 'observedAt', 'evidenceRef',
    'versionBefore', 'versionAfter', 'identityFingerprintBefore', 'identityFingerprintAfter',
    'grantSetDigestBefore', 'grantSetDigestAfter', 'rollbackMode',
    'concurrentMcpVerified', 'repairVerified', 'downgradeRejected', 'purgeVerified',
  ], label);
  if (step.stepId !== expected.id || step.order !== expected.order) fail(`${label} is out of order`);
  if (!['passed', 'failed'].includes(step.result)) fail(`${label}.result is invalid`);
  fresh(step.observedAt, now, freshnessHours, `${label}.observedAt`);
  const normalized = {
    stepId: step.stepId,
    order: step.order,
    result: step.result,
    observedAt: step.observedAt,
    evidenceRef: evidenceRef(step.evidenceRef, runId, runAttempt, targetId, step.stepId, `${label}.evidenceRef`),
    versionBefore: nullableVersion(step.versionBefore, `${label}.versionBefore`),
    versionAfter: nullableVersion(step.versionAfter, `${label}.versionAfter`),
    identityFingerprintBefore: nullableSha(step.identityFingerprintBefore, `${label}.identityFingerprintBefore`),
    identityFingerprintAfter: nullableSha(step.identityFingerprintAfter, `${label}.identityFingerprintAfter`),
    grantSetDigestBefore: nullableSha(step.grantSetDigestBefore, `${label}.grantSetDigestBefore`),
    grantSetDigestAfter: nullableSha(step.grantSetDigestAfter, `${label}.grantSetDigestAfter`),
    rollbackMode: step.rollbackMode,
    concurrentMcpVerified: step.concurrentMcpVerified,
    repairVerified: step.repairVerified,
    downgradeRejected: step.downgradeRejected,
    purgeVerified: step.purgeVerified,
  };
  if (normalized.rollbackMode !== null && normalized.rollbackMode !== 'forward-rebuild') fail(`${label}.rollbackMode is invalid`);
  for (const field of ['concurrentMcpVerified', 'repairVerified', 'downgradeRejected', 'purgeVerified']) {
    if (typeof normalized[field] !== 'boolean') fail(`${label}.${field} must be boolean`);
  }
  if (previous !== undefined) {
    if (timestamp(normalized.observedAt, `${label}.observedAt`) < timestamp(previous.observedAt, `${label}.previous.observedAt`)) {
      fail(`${label}.observedAt is not monotonic`);
    }
    if (normalized.versionBefore !== previous.versionAfter
      || normalized.identityFingerprintBefore !== previous.identityFingerprintAfter
      || normalized.grantSetDigestBefore !== previous.grantSetDigestAfter) {
      fail(`${label} does not continue the previous lifecycle state`);
    }
  }
  const noFlags = () => !normalized.concurrentMcpVerified && !normalized.repairVerified
    && !normalized.downgradeRejected && !normalized.purgeVerified;
  const sameState = () => {
    if (!normalized.identityFingerprintBefore || normalized.identityFingerprintBefore !== normalized.identityFingerprintAfter
      || !normalized.grantSetDigestBefore || normalized.grantSetDigestBefore !== normalized.grantSetDigestAfter) {
      fail(`${label} did not preserve Agent identity and active grants`);
    }
  };
  if (step.stepId === 'install') {
    if (normalized.versionBefore !== null || normalized.versionAfter !== versions.baseline
      || normalized.identityFingerprintBefore !== null || normalized.identityFingerprintAfter !== null
      || normalized.grantSetDigestBefore !== null || normalized.grantSetDigestAfter !== null
      || normalized.rollbackMode !== null || !noFlags()) fail(`${label} install state is invalid`);
  } else if (step.stepId === 'enroll') {
    if (normalized.versionAfter !== versions.baseline
      || normalized.identityFingerprintBefore !== null || normalized.identityFingerprintAfter === null
      || normalized.grantSetDigestBefore !== null || normalized.grantSetDigestAfter !== null
      || normalized.rollbackMode !== null || !noFlags()) fail(`${label} enroll state is invalid`);
  } else if (step.stepId === 'mcp') {
    if (normalized.versionAfter !== versions.baseline
      || normalized.identityFingerprintBefore === null
      || normalized.identityFingerprintAfter !== normalized.identityFingerprintBefore
      || normalized.grantSetDigestBefore !== null || normalized.grantSetDigestAfter === null
      || normalized.rollbackMode !== null || !noFlags()) fail(`${label} MCP state is invalid`);
  } else if (step.stepId === 'update') {
    if (normalized.versionBefore !== versions.baseline || normalized.versionAfter !== versions.candidate
      || normalized.rollbackMode !== null || !noFlags()) fail(`${label} update transition is invalid`);
    sameState();
  } else if (step.stepId === 'concurrent-mcp') {
    if (normalized.versionAfter !== versions.candidate || normalized.rollbackMode !== null
      || !normalized.concurrentMcpVerified || normalized.repairVerified
      || normalized.downgradeRejected || normalized.purgeVerified) fail(`${label} concurrent MCP state is invalid`);
    sameState();
  } else if (step.stepId === 'repair') {
    if (normalized.versionAfter !== versions.candidate || normalized.rollbackMode !== null
      || normalized.concurrentMcpVerified || !normalized.repairVerified
      || normalized.downgradeRejected || normalized.purgeVerified) fail(`${label} repair state is invalid`);
    sameState();
  } else if (step.stepId === 'downgrade-rejected') {
    if (normalized.versionAfter !== versions.candidate || normalized.rollbackMode !== null
      || normalized.concurrentMcpVerified || normalized.repairVerified
      || !normalized.downgradeRejected || normalized.purgeVerified) fail(`${label} downgrade rejection state is invalid`);
    sameState();
  } else if (step.stepId === 'rollback') {
    if (normalized.versionBefore !== versions.candidate || normalized.versionAfter !== versions.rollback
      || normalized.rollbackMode !== 'forward-rebuild' || !noFlags()) fail(`${label} rollback must be an increasing-version forward rebuild`);
    sameState();
  } else if (step.stepId === 'reinstall') {
    if (normalized.versionAfter !== versions.rollback || normalized.rollbackMode !== null || !noFlags()) {
      fail(`${label} reinstall state is invalid`);
    }
    sameState();
  } else if (step.stepId === 'purge') {
    if (normalized.versionAfter !== versions.rollback
      || normalized.identityFingerprintAfter !== null || normalized.grantSetDigestAfter !== null
      || normalized.rollbackMode !== null || normalized.concurrentMcpVerified || normalized.repairVerified
      || normalized.downgradeRejected || !normalized.purgeVerified) fail(`${label} purge state is invalid`);
  } else if (step.stepId === 'uninstall') {
    if (normalized.versionBefore !== versions.rollback || normalized.versionAfter !== null
      || normalized.identityFingerprintBefore !== null || normalized.identityFingerprintAfter !== null
      || normalized.grantSetDigestBefore !== null || normalized.grantSetDigestAfter !== null
      || normalized.rollbackMode !== null || !noFlags()) fail(`${label} uninstall state is invalid`);
  }
  return normalized;
}

function normalizeEvidence(manifest, input, sourceSha, now) {
  const evidence = record(input, 'evidence');
  exactKeys(evidence, ['schemaVersion', 'sourceSha', 'manifestSha256', 'runId', 'runAttempt', 'targets'], 'evidence');
  if (evidence.schemaVersion !== 1 || evidence.sourceSha !== sourceSha
    || evidence.manifestSha256 !== canonicalSha256(manifest)) fail('evidence binding is stale');
  const runId = string(evidence.runId, 'evidence.runId');
  if (!/^[1-9][0-9]*$/.test(runId)) fail('evidence.runId is invalid');
  const runAttempt = integer(evidence.runAttempt, 'evidence.runAttempt');
  if (runAttempt < 1) fail('evidence.runAttempt is invalid');
  const targetById = new Map(manifest.targets.map((target) => [target.id, target]));
  const seen = new Set();
  const targets = array(evidence.targets, 'evidence.targets').map((run, index) => {
    const label = `evidence.targets[${index}]`;
    exactKeys(run, ['targetId', 'artifacts', 'steps'], label);
    const target = targetById.get(run.targetId);
    if (!target || seen.has(run.targetId)) fail(`${label}.targetId is unknown or duplicate`);
    seen.add(run.targetId);
    const normalizedArtifacts = normalizeArtifacts(
      run.artifacts, target, manifest.artifactPhases, sourceSha, `${label}.artifacts`,
    );
    const steps = array(run.steps, `${label}.steps`);
    if (steps.length !== manifest.steps.length) fail(`${label}.steps is incomplete`);
    const normalizedSteps = [];
    for (let stepIndex = 0; stepIndex < manifest.steps.length; stepIndex += 1) {
      normalizedSteps.push(normalizeStep(
        steps[stepIndex], runId, runAttempt, run.targetId, manifest.steps[stepIndex],
        normalizedSteps[stepIndex - 1], normalizedArtifacts.versions,
        now, manifest.evidenceFreshnessHours, `${label}.steps[${stepIndex}]`,
      ));
    }
    return {
      targetId: run.targetId,
      os: target.os,
      arch: target.arch,
      distribution: target.distribution,
      libc: target.libc,
      artifacts: normalizedArtifacts.artifacts,
      steps: normalizedSteps,
    };
  });
  if (seen.size !== manifest.targets.length) fail('evidence is missing a required target');
  noSecrets(evidence, 'evidence');
  return {
    runId,
    runAttempt,
    targets: manifest.targets.map((target) => targets.find((run) => run.targetId === target.id)),
  };
}

function summarize(targets) {
  const steps = targets.flatMap((target) => target.steps);
  return {
    targetCount: targets.length,
    stepCount: steps.length,
    passed: steps.filter((step) => step.result === 'passed').length,
    failed: steps.filter((step) => step.result === 'failed').length,
  };
}
function withoutDigest(report) { const { contentSha256: _, ...content } = report; return content; }

export function generateReport({ manifest: manifestInput, evidence, expectedSourceSha, now = new Date() }) {
  const manifest = validateManifest(manifestInput);
  const sourceSha = sha(expectedSourceSha, SOURCE_SHA, 'expectedSourceSha');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail('now must be valid');
  const normalizedEvidence = normalizeEvidence(manifest, evidence, sourceSha, now);
  const { runId, runAttempt, targets } = normalizedEvidence;
  const blockers = targets.flatMap((target) => target.steps
    .filter((step) => step.result !== 'passed')
    .map((step) => `LIFECYCLE_FAILED:${target.targetId}:${step.stepId}`)).sort();
  const report = {
    schemaVersion: manifest.reportSchemaVersion,
    sourceSha,
    manifestSha256: canonicalSha256(manifest),
    generatedAt: now.toISOString(),
    evidenceFreshnessHours: manifest.evidenceFreshnessHours,
    runId,
    runAttempt,
    releaseDecision: blockers.length === 0 ? 'eligible' : 'blocked',
    blockers,
    summary: summarize(targets),
    targets,
  };
  noSecrets(report, 'report');
  return { ...report, contentSha256: canonicalSha256(report) };
}

export function renderMarkdown(report) {
  noSecrets(report, 'report');
  const lines = [
    '# Palladin platform lifecycle report', '',
    `- Source SHA: \`${report.sourceSha}\``,
    `- Report SHA-256: \`${report.contentSha256}\``,
    `- Generated at: ${report.generatedAt}`,
    `- Physical workflow run: ${report.runId} (attempt ${report.runAttempt})`,
    `- Release decision: **${report.releaseDecision.toUpperCase()}**`, '',
    '| Target | Platform | Install | Enroll | MCP | Update | Concurrent MCP | Repair | Downgrade rejected | Forward rollback | Reinstall | Purge | Uninstall |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
  ];
  for (const target of report.targets) {
    const result = Object.fromEntries(target.steps.map((step) => [step.stepId, step.result]));
    lines.push(`| ${target.targetId} | ${target.distribution}/${target.arch} | ${result.install} | ${result.enroll} | ${result.mcp} | ${result.update} | ${result['concurrent-mcp']} | ${result.repair} | ${result['downgrade-rejected']} | ${result.rollback} | ${result.reinstall} | ${result.purge} | ${result.uninstall} |`);
  }
  lines.push('', '## Release blockers', '');
  if (report.blockers.length === 0) lines.push('None.');
  else report.blockers.forEach((blocker) => lines.push(`- \`${blocker}\``));
  return `${lines.join('\n')}\n`;
}

function inspectReport(manifestInput, reportInput, expectedSourceSha, now, markdown) {
  const manifest = validateManifest(manifestInput);
  const report = record(reportInput, 'report');
  exactKeys(report, ['schemaVersion', 'sourceSha', 'manifestSha256', 'generatedAt', 'evidenceFreshnessHours', 'runId', 'runAttempt', 'releaseDecision', 'blockers', 'summary', 'targets', 'contentSha256'], 'report');
  if (report.schemaVersion !== manifest.reportSchemaVersion || report.sourceSha !== sha(expectedSourceSha, SOURCE_SHA, 'expectedSourceSha')
    || report.manifestSha256 !== canonicalSha256(manifest) || report.evidenceFreshnessHours !== manifest.evidenceFreshnessHours
    || report.contentSha256 !== canonicalSha256(withoutDigest(report))) fail('report binding is stale or invalid');
  timestamp(report.generatedAt, 'report.generatedAt');
  const evidence = {
    schemaVersion: 1,
    sourceSha: report.sourceSha,
    manifestSha256: report.manifestSha256,
    runId: report.runId,
    runAttempt: report.runAttempt,
    targets: array(report.targets, 'report.targets').map((target) => ({
      targetId: target.targetId,
      artifacts: target.artifacts,
      steps: target.steps,
    })),
  };
  const normalizedEvidence = normalizeEvidence(manifest, evidence, report.sourceSha, now);
  const { targets } = normalizedEvidence;
  if (report.runId !== normalizedEvidence.runId || report.runAttempt !== normalizedEvidence.runAttempt) {
    fail('report physical workflow binding is invalid');
  }
  const blockers = targets.flatMap((target) => target.steps
    .filter((step) => step.result !== 'passed')
    .map((step) => `LIFECYCLE_FAILED:${target.targetId}:${step.stepId}`)).sort();
  if (canonicalJson(report.targets) !== canonicalJson(targets)
    || canonicalJson(report.summary) !== canonicalJson(summarize(targets))
    || canonicalJson(report.blockers) !== canonicalJson(blockers)
    || report.releaseDecision !== (blockers.length === 0 ? 'eligible' : 'blocked')) fail('report derived content is invalid');
  if (markdown !== undefined && markdown !== renderMarkdown(report)) fail('Markdown report does not match JSON');
  noSecrets(report, 'report');
  return blockers;
}

export function validateReport({ manifest, report, expectedSourceSha, now = new Date(), markdown }) {
  const blockers = inspectReport(manifest, report, expectedSourceSha, now, markdown);
  if (blockers.length > 0) fail(`release gate blocked: ${blockers.join(', ')}`);
  return true;
}

function readJson(path, label) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { fail(`${label} must be valid JSON`); }
}
function writeAtomic(path, content) {
  const absolute = resolve(path);
  mkdirSync(dirname(absolute), { recursive: true });
  const temporary = join(dirname(absolute), `.${basename(absolute)}.${randomUUID()}.tmp`);
  try {
    writeFileSync(temporary, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    renameSync(temporary, absolute);
  } finally { rmSync(temporary, { force: true }); }
}
function parse(argv) {
  const [command, ...rest] = argv;
  if (!['generate', 'validate'].includes(command)) fail('usage: report.mjs <generate|validate> [options]');
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index]; const value = rest[index + 1];
    if (!flag?.startsWith('--') || value === undefined || options[flag.slice(2)] !== undefined) fail('invalid arguments');
    options[flag.slice(2)] = value;
  }
  const allowed = new Set(['manifest', 'evidence', 'source-sha', 'json', 'markdown', 'now']);
  Object.keys(options).forEach((key) => { if (!allowed.has(key)) fail(`unknown option: --${key}`); });
  for (const key of command === 'generate' ? ['evidence', 'source-sha', 'json', 'markdown'] : ['source-sha', 'json', 'markdown']) {
    if (!options[key]) fail(`--${key} is required`);
  }
  return { command, options };
}
function cli(argv) {
  const { command, options } = parse(argv);
  const manifest = loadManifest(options.manifest ? resolve(options.manifest) : DEFAULT_MANIFEST_PATH);
  const now = options.now ? new Date(options.now) : new Date();
  if (command === 'generate') {
    const report = generateReport({ manifest, evidence: readJson(resolve(options.evidence), 'evidence'), expectedSourceSha: options['source-sha'], now });
    const markdown = renderMarkdown(report);
    writeAtomic(options.json, `${JSON.stringify(report, null, 2)}\n`);
    writeAtomic(options.markdown, markdown);
    validateReport({ manifest, report, expectedSourceSha: options['source-sha'], now, markdown });
  } else {
    validateReport({
      manifest,
      report: readJson(resolve(options.json), 'report'),
      expectedSourceSha: options['source-sha'],
      now,
      markdown: readFileSync(resolve(options.markdown), 'utf8'),
    });
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { cli(process.argv.slice(2)); } catch (error) {
    process.stderr.write(`lifecycle report failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  }
}
