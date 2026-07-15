import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_MANIFEST_PATH = resolve(HERE, 'coverage-manifest.json');

const SHA_PATTERN = /^[a-f0-9]{40}$/;
const ARTIFACT_SHA_PATTERN = /^[a-f0-9]{64}$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
const FINDING_STATUSES = ['unresolved', 'accepted', 'resolved'];
const EVIDENCE_RESULTS = ['passed', 'expected-residual', 'failed'];
const SECRET_VALUE_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
  /\bBearer\s+\S+/i,
  /\b(?:pl|sk|ghp|npm)_[A-Za-z0-9_-]{8,}\b/i,
  /\b(?:api[_ -]?key|password|access[_ -]?token|private[_ -]?key|mnemonic)\s*[:=]\s*\S+/i,
];
const SECRET_FIELD_PATTERN = /^(?:secret(?:Value)?|password|apiKey|privateKey|accessToken|authorization|cookie|mnemonic)$/i;

function fail(message) {
  throw new Error(message);
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function record(value, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  return value;
}

function array(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  return value;
}

function string(value, label) {
  if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a non-empty string`);
  return value;
}

function integer(value, label) {
  if (!Number.isSafeInteger(value)) fail(`${label} must be an integer`);
  return value;
}

function exactKeys(value, allowed, label) {
  const actual = Object.keys(record(value, label)).sort();
  const expected = [...allowed].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} must contain exactly: ${expected.join(', ')}`);
  }
}

function allowedKeys(value, required, optional, label) {
  const object = record(value, label);
  for (const key of required) if (!(key in object)) fail(`${label}.${key} is required`);
  const permitted = new Set([...required, ...optional]);
  for (const key of Object.keys(object)) if (!permitted.has(key)) fail(`${label}.${key} is not allowed`);
}

function uniqueIds(items, label) {
  const seen = new Set();
  for (const item of items) {
    const id = string(record(item, `${label} item`).id, `${label} item.id`);
    if (!ID_PATTERN.test(id)) fail(`${label} contains an invalid id`);
    if (seen.has(id)) fail(`${label} contains a duplicate id`);
    seen.add(id);
  }
  return seen;
}

function assertKnownIds(values, known, label) {
  const seen = new Set();
  for (const value of array(values, label)) {
    const id = string(value, `${label} item`);
    if (!known.has(id)) fail(`${label} contains an unknown id`);
    if (seen.has(id)) fail(`${label} contains a duplicate id`);
    seen.add(id);
  }
  return [...seen];
}

function parseTime(value, label) {
  const text = string(value, label);
  const timestamp = Date.parse(text);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== text) {
    fail(`${label} must be an ISO-8601 UTC timestamp`);
  }
  return timestamp;
}

function assertFresh(observedAt, now, freshnessHours, label) {
  const observed = parseTime(observedAt, label);
  const current = now.getTime();
  if (observed > current + 5 * 60 * 1000) fail(`${label} is in the future`);
  if (current - observed > freshnessHours * 60 * 60 * 1000) fail(`${label} is stale`);
}

function assertSourceSha(value, label) {
  const sha = string(value, label);
  if (!SHA_PATTERN.test(sha)) fail(`${label} must be a lowercase 40-character Git SHA`);
  return sha;
}

function assertArtifactSha(value, label) {
  const sha = string(value, label);
  if (!ARTIFACT_SHA_PATTERN.test(sha)) fail(`${label} must be a lowercase 64-character SHA-256 digest`);
  return sha;
}

function assertReviewDate(value, label) {
  const date = string(value, label);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)
    || new Date(`${date}T00:00:00.000Z`).toISOString().slice(0, 10) !== date) {
    fail(`${label} must be a real ISO calendar date`);
  }
  return date;
}

function assertResidualReviewsCurrent(manifest, now) {
  for (const [index, risk] of manifest.residualRisks.entries()) {
    const deadline = Date.parse(`${risk.reviewDate}T23:59:59.999Z`);
    if (now.getTime() > deadline) fail(`manifest.residualRisks[${index}].reviewDate is overdue`);
  }
}

function assertEvidenceRef(value, targetTierId, attackId, label, manualRequired = false) {
  const reference = string(value, label);
  const artifact = /^artifact:\/\/github-actions\/([1-9][0-9]{0,19})\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/.exec(reference);
  const manual = /^manual:\/\/operator-attestation\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)\/([0-9]{8}T[0-9]{6}Z)$/.exec(reference);
  const artifactMatches = artifact?.[2] === targetTierId && artifact[3] === attackId;
  const manualMatches = manual?.[1] === targetTierId && manual[2] === attackId;
  if (manualRequired && !manualMatches) {
    fail(`${label} requires a manual operator attestation`);
  }
  if (!artifactMatches && !manualMatches) {
    fail(`${label} must identify only a GitHub Actions run or operator attestation`);
  }
  return reference;
}

function assertNoSecretMaterial(value, path = 'report') {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoSecretMaterial(item, `${path}[${index}]`));
    return;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_FIELD_PATTERN.test(key)) fail(`${path}.${key} is a secret-bearing field`);
      assertNoSecretMaterial(item, `${path}.${key}`);
    }
    return;
  }
  if (typeof value !== 'string') return;
  for (const pattern of SECRET_VALUE_PATTERNS) {
    if (pattern.test(value)) fail(`${path} contains secret-shaped material`);
  }
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function canonicalSha256(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

export function loadManifest(path = DEFAULT_MANIFEST_PATH) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function validateManifest(input) {
  const manifest = record(input, 'manifest');
  exactKeys(manifest, [
    'schemaVersion',
    'reportSchemaVersion',
    'evidenceFreshnessHours',
    'coverage',
    'adrs',
    'attacks',
    'residualRisks',
    'targetTiers',
  ], 'manifest');
  if (integer(manifest.schemaVersion, 'manifest.schemaVersion') !== 1) fail('unsupported manifest schemaVersion');
  if (integer(manifest.reportSchemaVersion, 'manifest.reportSchemaVersion') !== 1) fail('unsupported report schemaVersion');
  const freshness = integer(manifest.evidenceFreshnessHours, 'manifest.evidenceFreshnessHours');
  if (freshness < 1 || freshness > 720) fail('manifest.evidenceFreshnessHours must be between 1 and 720');

  exactKeys(manifest.coverage, ['mode', 'evidenceRequiredDisposition', 'unsupportedDisposition'], 'manifest.coverage');
  if (manifest.coverage.mode !== 'cartesian-product') fail('manifest.coverage.mode must be cartesian-product');
  if (manifest.coverage.evidenceRequiredDisposition !== 'evidence-required') fail('invalid evidence disposition');
  if (manifest.coverage.unsupportedDisposition !== 'not-applicable') fail('invalid unsupported disposition');

  const adrs = array(manifest.adrs, 'manifest.adrs');
  const adrIds = uniqueIds(adrs, 'manifest.adrs');
  for (const [index, item] of adrs.entries()) {
    exactKeys(item, ['id', 'href'], `manifest.adrs[${index}]`);
    const href = string(item.href, `manifest.adrs[${index}].href`);
    if (!/^runtime\/docs\/adr\/[0-9]{4}-[a-z0-9-]+\.md(?:#[a-z0-9-]+)?$/.test(href)) fail(`invalid ADR href: ${href}`);
  }

  const attacks = array(manifest.attacks, 'manifest.attacks');
  const attackIds = uniqueIds(attacks, 'manifest.attacks');
  for (const [index, item] of attacks.entries()) {
    exactKeys(item, ['id', 'name'], `manifest.attacks[${index}]`);
    string(item.name, `manifest.attacks[${index}].name`);
  }

  const risks = array(manifest.residualRisks, 'manifest.residualRisks');
  const riskIds = uniqueIds(risks, 'manifest.residualRisks');
  for (const [index, item] of risks.entries()) {
    exactKeys(item, ['id', 'title', 'statement', 'owner', 'reviewDate', 'adrRefs'], `manifest.residualRisks[${index}]`);
    string(item.title, `manifest.residualRisks[${index}].title`);
    string(item.statement, `manifest.residualRisks[${index}].statement`);
    const owner = string(item.owner, `manifest.residualRisks[${index}].owner`);
    if (!/^[a-z0-9](?:[a-z0-9-]{0,38})$/.test(owner)) fail(`manifest.residualRisks[${index}].owner is invalid`);
    assertReviewDate(item.reviewDate, `manifest.residualRisks[${index}].reviewDate`);
    const refs = assertKnownIds(item.adrRefs, adrIds, `manifest.residualRisks[${index}].adrRefs`);
    if (refs.length === 0) fail(`manifest.residualRisks[${index}] requires an ADR reference`);
  }

  const targetTiers = array(manifest.targetTiers, 'manifest.targetTiers');
  uniqueIds(targetTiers, 'manifest.targetTiers');
  for (const [index, item] of targetTiers.entries()) {
    const label = `manifest.targetTiers[${index}]`;
    allowedKeys(item,
      ['id', 'os', 'arch', 'libc', 'tier', 'channel', 'disposition', 'expectedResidualAttacks', 'expectedResidualRiskIds', 'manualRequiredAttacks', 'residualRiskIds'],
      ['adrRefs', 'rationale'],
      label,
    );
    if (!['macos', 'windows', 'linux'].includes(item.os)) fail(`${label}.os is invalid`);
    if (!['arm64', 'x64'].includes(item.arch)) fail(`${label}.arch is invalid`);
    if (!['none', 'gnu', 'musl'].includes(item.libc)) fail(`${label}.libc is invalid`);
    if (!['Convenience', 'Hardened'].includes(item.tier)) fail(`${label}.tier is invalid`);
    string(item.channel, `${label}.channel`);
    const disposition = string(item.disposition, `${label}.disposition`);
    if (!['evidence-required', 'not-applicable'].includes(disposition)) fail(`${label}.disposition is invalid`);
    const expectedResidualAttacks = assertKnownIds(item.expectedResidualAttacks, attackIds, `${label}.expectedResidualAttacks`);
    const expectedResidualRiskIds = assertKnownIds(item.expectedResidualRiskIds, riskIds, `${label}.expectedResidualRiskIds`);
    const manualRequiredAttacks = assertKnownIds(item.manualRequiredAttacks, attackIds, `${label}.manualRequiredAttacks`);
    const targetRisks = assertKnownIds(item.residualRiskIds, riskIds, `${label}.residualRiskIds`);
    if (targetRisks.length === 0) fail(`${label} must declare residual risks`);
    if ((expectedResidualAttacks.length === 0) !== (expectedResidualRiskIds.length === 0)) {
      fail(`${label} must bind every expected residual policy to residual risk ids`);
    }
    for (const riskId of expectedResidualRiskIds) {
      if (!targetRisks.includes(riskId)) fail(`${label}.expectedResidualRiskIds must be included in residualRiskIds`);
    }
    if (disposition === 'not-applicable') {
      if (manualRequiredAttacks.length !== 0) fail(`${label} cannot require manual evidence when not applicable`);
      if (item.tier !== 'Hardened' || item.os !== 'linux' || item.libc !== 'musl') {
        fail(`${label} may be not-applicable only for Linux musl Hardened`);
      }
      const refs = assertKnownIds(item.adrRefs, adrIds, `${label}.adrRefs`);
      if (refs.length === 0) fail(`${label} requires an ADR reference`);
      string(item.rationale, `${label}.rationale`);
    } else if ('adrRefs' in item || 'rationale' in item) {
      fail(`${label} may include rationale only when not applicable`);
    }
  }
  assertNoSecretMaterial(manifest, 'manifest');
  return manifest;
}

function normalizedFindings(input, targetTierIds, attackIds, adrIds) {
  const findings = array(input, 'evidenceBundle.findings');
  uniqueIds(findings, 'evidenceBundle.findings');
  return findings.map((item, index) => {
    const label = `evidenceBundle.findings[${index}]`;
    exactKeys(item, ['id', 'severity', 'status', 'targetTierIds', 'attackIds', 'adrRefs'], label);
    if (!SEVERITIES.includes(item.severity)) fail(`${label}.severity is invalid`);
    if (!FINDING_STATUSES.includes(item.status)) fail(`${label}.status is invalid`);
    const targets = assertKnownIds(item.targetTierIds, targetTierIds, `${label}.targetTierIds`);
    const attacks = assertKnownIds(item.attackIds, attackIds, `${label}.attackIds`);
    const adrs = assertKnownIds(item.adrRefs, adrIds, `${label}.adrRefs`);
    if (targets.length === 0 || attacks.length === 0) fail(`${label} must identify affected coverage`);
    if (item.status === 'accepted' && adrs.length === 0) fail(`${label} accepted finding requires an ADR reference`);
    return {
      id: item.id,
      severity: item.severity,
      status: item.status,
      targetTierIds: [...targets].sort(),
      attackIds: [...attacks].sort(),
      adrRefs: [...adrs].sort(),
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
}

function evidenceCellKey(targetTierId, attackId) {
  return `${targetTierId}\u0000${attackId}`;
}

function exactMappingKeys(input, expectedKeys, label) {
  const mapping = record(input, label);
  const actual = Object.keys(mapping).sort();
  const expected = [...expectedKeys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`${label} must contain exactly: ${expected.join(', ')}`);
  }
  return mapping;
}

export function createEvidenceShard({
  manifest: manifestInput,
  sourceSha: sourceShaInput,
  targetTierIds: targetTierIdsInput,
  artifactSha256ByTarget,
  observedAt,
  outcomes,
  evidenceRefs,
  findings,
}) {
  const manifest = validateManifest(manifestInput);
  const sourceSha = assertSourceSha(sourceShaInput, 'sourceSha');
  parseTime(observedAt, 'observedAt');
  const requested = array(targetTierIdsInput, 'targetTierIds').map((id, index) =>
    string(id, `targetTierIds[${index}]`));
  if (requested.length === 0 || new Set(requested).size !== requested.length) {
    fail('targetTierIds must be a non-empty unique list');
  }
  const targetById = new Map(manifest.targetTiers.map((target) => [target.id, target]));
  for (const id of requested) {
    const target = targetById.get(id);
    if (!target || target.disposition !== 'evidence-required') {
      fail('targetTierIds contains an unknown or non-executable target');
    }
  }
  const hashes = exactMappingKeys(artifactSha256ByTarget, requested, 'artifactSha256ByTarget');
  const outcomeTargets = exactMappingKeys(outcomes, requested, 'outcomes');
  const referenceTargets = exactMappingKeys(evidenceRefs, requested, 'evidenceRefs');
  const attackIds = manifest.attacks.map(({ id }) => id);
  const evidence = [];
  for (const targetTierId of requested) {
    const target = targetById.get(targetTierId);
    if (!target) fail(`internal error: missing target ${targetTierId}`);
    const artifactSha256 = assertArtifactSha(hashes[targetTierId], `artifactSha256ByTarget.${targetTierId}`);
    const targetOutcomes = exactMappingKeys(outcomeTargets[targetTierId], attackIds, `outcomes.${targetTierId}`);
    const targetRefs = exactMappingKeys(referenceTargets[targetTierId], attackIds, `evidenceRefs.${targetTierId}`);
    for (const attackId of attackIds) {
      const result = targetOutcomes[attackId];
      if (!EVIDENCE_RESULTS.includes(result)) fail(`outcomes.${targetTierId}.${attackId} is invalid`);
      const expectedResidual = target.expectedResidualAttacks.includes(attackId);
      if (expectedResidual && result !== 'expected-residual') {
        fail(`outcomes.${targetTierId}.${attackId} must explicitly be expected-residual`);
      }
      if (!expectedResidual && result === 'expected-residual') {
        fail(`outcomes.${targetTierId}.${attackId} cannot weaken a required denial`);
      }
      evidence.push({
        targetTierId,
        attackId,
        result,
        observedAt,
        evidenceRef: assertEvidenceRef(
          targetRefs[attackId],
          targetTierId,
          attackId,
          `evidenceRefs.${targetTierId}.${attackId}`,
          target.manualRequiredAttacks.includes(attackId),
        ),
        artifactSha256,
        residualRiskIds: expectedResidual ? [...target.expectedResidualRiskIds].sort() : [],
      });
    }
  }
  const normalizedShardFindings = normalizedFindings(
    findings,
    new Set(requested),
    new Set(attackIds),
    new Set(manifest.adrs.map(({ id }) => id)),
  );
  for (const cell of evidence) {
    if (cell.result !== 'failed') continue;
    const mapped = normalizedShardFindings.some((finding) =>
      finding.targetTierIds.includes(cell.targetTierId) && finding.attackIds.includes(cell.attackId));
    if (!mapped) fail(`failed evidence ${cell.targetTierId} x ${cell.attackId} requires a finding`);
  }
  const shard = {
    schemaVersion: 1,
    sourceSha,
    manifestSha256: canonicalSha256(manifest),
    evidence,
    findings: normalizedShardFindings,
  };
  assertNoSecretMaterial(shard, 'evidenceShard');
  return shard;
}

function normalizeEvidenceBundle(manifest, input, expectedSourceSha, now) {
  const bundle = record(input, 'evidenceBundle');
  exactKeys(bundle, ['schemaVersion', 'sourceSha', 'manifestSha256', 'evidence', 'findings'], 'evidenceBundle');
  if (integer(bundle.schemaVersion, 'evidenceBundle.schemaVersion') !== 1) fail('unsupported evidence schemaVersion');
  const sourceSha = assertSourceSha(bundle.sourceSha, 'evidenceBundle.sourceSha');
  if (sourceSha !== expectedSourceSha) fail('evidenceBundle.sourceSha is stale or belongs to a different source SHA');
  const digest = canonicalSha256(manifest);
  if (bundle.manifestSha256 !== digest) fail('evidenceBundle.manifestSha256 is stale');

  const targetTierIds = new Set(manifest.targetTiers.map(({ id }) => id));
  const executableTargetIds = new Set(manifest.targetTiers
    .filter(({ disposition }) => disposition === 'evidence-required')
    .map(({ id }) => id));
  const targetById = new Map(manifest.targetTiers.map((target) => [target.id, target]));
  const attackIds = new Set(manifest.attacks.map(({ id }) => id));
  const adrIds = new Set(manifest.adrs.map(({ id }) => id));
  const riskIds = new Set(manifest.residualRisks.map(({ id }) => id));
  const cells = new Map();

  for (const [index, item] of array(bundle.evidence, 'evidenceBundle.evidence').entries()) {
    const label = `evidenceBundle.evidence[${index}]`;
    exactKeys(item, ['targetTierId', 'attackId', 'result', 'observedAt', 'evidenceRef', 'artifactSha256', 'residualRiskIds'], label);
    const targetTierId = string(item.targetTierId, `${label}.targetTierId`);
    if (!executableTargetIds.has(targetTierId)) fail(`${label}.targetTierId is unknown or does not require evidence`);
    const attackId = string(item.attackId, `${label}.attackId`);
    if (!attackIds.has(attackId)) fail(`${label}.attackId is unknown`);
    if (!EVIDENCE_RESULTS.includes(item.result)) fail(`${label}.result is invalid`);
    assertFresh(item.observedAt, now, manifest.evidenceFreshnessHours, `${label}.observedAt`);
    const evidenceRef = assertEvidenceRef(
      item.evidenceRef,
      targetTierId,
      attackId,
      `${label}.evidenceRef`,
      targetById.get(targetTierId)?.manualRequiredAttacks.includes(attackId) ?? false,
    );
    const artifactSha256 = assertArtifactSha(item.artifactSha256, `${label}.artifactSha256`);
    const residualRiskIds = assertKnownIds(item.residualRiskIds, riskIds, `${label}.residualRiskIds`);
    const target = targetById.get(targetTierId);
    const expectedResidual = target.expectedResidualAttacks.includes(attackId);
    if (expectedResidual) {
      if (item.result !== 'expected-residual') fail(`${label}.result must be expected-residual for the manifest-declared boundary`);
      if (canonicalJson([...residualRiskIds].sort()) !== canonicalJson([...target.expectedResidualRiskIds].sort())) {
        fail(`${label} must reference the manifest's expected residual risks`);
      }
    } else {
      if (item.result === 'expected-residual') fail(`${label}.result cannot weaken a required denial to expected-residual`);
      if (residualRiskIds.length !== 0) fail(`${label}.residualRiskIds must be empty for a non-residual result`);
    }
    const key = evidenceCellKey(targetTierId, attackId);
    if (cells.has(key)) fail(`${label} duplicates ${targetTierId} x ${attackId}`);
    cells.set(key, {
      targetTierId,
      attackId,
      result: item.result,
      observedAt: item.observedAt,
      evidenceRef,
      artifactSha256,
      residualRiskIds: [...residualRiskIds].sort(),
    });
  }

  for (const target of manifest.targetTiers) {
    if (target.disposition !== 'evidence-required') continue;
    for (const attack of manifest.attacks) {
      const key = evidenceCellKey(target.id, attack.id);
      if (!cells.has(key)) fail(`missing evidence for ${target.id} x ${attack.id}`);
    }
  }
  const requiredCount = executableTargetIds.size * attackIds.size;
  if (cells.size !== requiredCount) fail(`evidence count must be exactly ${requiredCount}`);

  const findings = normalizedFindings(bundle.findings, targetTierIds, attackIds, adrIds);
  for (const cell of cells.values()) {
    if (cell.result !== 'failed') continue;
    const mapped = findings.some((finding) =>
      finding.targetTierIds.includes(cell.targetTierId) && finding.attackIds.includes(cell.attackId));
    if (!mapped) fail(`failed evidence ${cell.targetTierId} x ${cell.attackId} requires a finding`);
  }
  assertNoSecretMaterial(bundle, 'evidenceBundle');
  return { sourceSha, cells, findings };
}

function computeGate(coverage, findings) {
  const blockers = [];
  for (const cell of coverage) {
    if (cell.result === 'failed') blockers.push(`ATTACK_FAILED:${cell.targetTierId}:${cell.attackId}`);
  }
  for (const finding of findings) {
    if (['Critical', 'High'].includes(finding.severity) && finding.status !== 'resolved') {
      blockers.push(`FINDING_BLOCKS_RELEASE:${finding.id}:${finding.severity}:${finding.status}`);
    }
  }
  blockers.sort();
  return {
    releaseDecision: blockers.length === 0 ? 'eligible' : 'blocked',
    blockers,
  };
}

function summarize(coverage, findings) {
  const resultCounts = {
    passed: 0,
    expectedResidual: 0,
    notApplicable: 0,
    failed: 0,
  };
  for (const cell of coverage) {
    if (cell.result === 'passed') resultCounts.passed += 1;
    else if (cell.result === 'expected-residual') resultCounts.expectedResidual += 1;
    else if (cell.result === 'not-applicable') resultCounts.notApplicable += 1;
    else if (cell.result === 'failed') resultCounts.failed += 1;
  }
  return {
    targetTierCount: new Set(coverage.map(({ targetTierId }) => targetTierId)).size,
    attackCount: new Set(coverage.map(({ attackId }) => attackId)).size,
    coverageCellCount: coverage.length,
    findingCount: findings.length,
    resultCounts,
  };
}

function reportWithoutDigest(report) {
  const { contentSha256: _contentSha256, ...content } = report;
  return content;
}

export function generateReport({ manifest: manifestInput, evidenceBundle, expectedSourceSha, now = new Date() }) {
  const manifest = validateManifest(manifestInput);
  const sourceSha = assertSourceSha(expectedSourceSha, 'expectedSourceSha');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail('now must be a valid Date');
  assertResidualReviewsCurrent(manifest, now);
  const normalized = normalizeEvidenceBundle(manifest, evidenceBundle, sourceSha, now);
  const evidenceByCell = normalized.cells;
  const coverage = [];
  for (const target of manifest.targetTiers) {
    for (const attack of manifest.attacks) {
      if (target.disposition === 'not-applicable') {
        coverage.push({
          targetTierId: target.id,
          os: target.os,
          arch: target.arch,
          libc: target.libc,
          tier: target.tier,
          channel: target.channel,
          attackId: attack.id,
          evidenceRequirement: 'not-applicable',
          result: 'not-applicable',
          adrRefs: [...target.adrRefs].sort(),
          residualRiskIds: [...target.residualRiskIds].sort(),
        });
        continue;
      }
      const evidence = evidenceByCell.get(evidenceCellKey(target.id, attack.id));
      if (!evidence) fail(`internal error: missing normalized evidence for ${target.id} x ${attack.id}`);
      coverage.push({
        targetTierId: target.id,
        os: target.os,
        arch: target.arch,
        libc: target.libc,
        tier: target.tier,
        channel: target.channel,
        attackId: attack.id,
        evidenceRequirement: target.manualRequiredAttacks.includes(attack.id) ? 'manual-required' : 'automated',
        result: evidence.result,
        observedAt: evidence.observedAt,
        evidenceRef: evidence.evidenceRef,
        artifactSha256: evidence.artifactSha256,
        residualRiskIds: evidence.residualRiskIds,
      });
    }
  }
  const gate = computeGate(coverage, normalized.findings);
  const report = {
    schemaVersion: manifest.reportSchemaVersion,
    sourceSha,
    manifestSha256: canonicalSha256(manifest),
    generatedAt: now.toISOString(),
    evidenceFreshnessHours: manifest.evidenceFreshnessHours,
    releaseDecision: gate.releaseDecision,
    blockers: gate.blockers,
    summary: summarize(coverage, normalized.findings),
    adrs: manifest.adrs,
    residualRisks: manifest.residualRisks,
    findings: normalized.findings,
    coverage,
  };
  assertNoSecretMaterial(report);
  return { ...report, contentSha256: canonicalSha256(report) };
}

function compareCanonical(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) fail(`${label} does not match canonical content`);
}

function inspectReport({ manifest: manifestInput, report: input, expectedSourceSha, now = new Date(), markdown }) {
  const manifest = validateManifest(manifestInput);
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail('now must be a valid Date');
  assertResidualReviewsCurrent(manifest, now);
  const report = record(input, 'report');
  exactKeys(report, [
    'schemaVersion',
    'sourceSha',
    'manifestSha256',
    'generatedAt',
    'evidenceFreshnessHours',
    'releaseDecision',
    'blockers',
    'summary',
    'adrs',
    'residualRisks',
    'findings',
    'coverage',
    'contentSha256',
  ], 'report');
  if (report.schemaVersion !== manifest.reportSchemaVersion) fail('report.schemaVersion is stale');
  const sourceSha = assertSourceSha(report.sourceSha, 'report.sourceSha');
  if (sourceSha !== assertSourceSha(expectedSourceSha, 'expectedSourceSha')) fail('report.sourceSha is stale or belongs to a different source SHA');
  if (report.manifestSha256 !== canonicalSha256(manifest)) fail('report.manifestSha256 is stale');
  if (report.evidenceFreshnessHours !== manifest.evidenceFreshnessHours) fail('report evidence freshness policy is stale');
  parseTime(report.generatedAt, 'report.generatedAt');
  if (Date.parse(report.generatedAt) > now.getTime() + 5 * 60 * 1000) fail('report.generatedAt is in the future');
  if (report.contentSha256 !== canonicalSha256(reportWithoutDigest(report))) fail('report.contentSha256 does not match report content');
  compareCanonical(report.adrs, manifest.adrs, 'report.adrs');
  compareCanonical(report.residualRisks, manifest.residualRisks, 'report.residualRisks');

  const targetById = new Map(manifest.targetTiers.map((target) => [target.id, target]));
  const attackIds = new Set(manifest.attacks.map(({ id }) => id));
  const expectedKeys = new Set();
  for (const target of manifest.targetTiers) for (const attack of manifest.attacks) expectedKeys.add(evidenceCellKey(target.id, attack.id));
  const seen = new Set();
  for (const [index, cell] of array(report.coverage, 'report.coverage').entries()) {
    const label = `report.coverage[${index}]`;
    const target = targetById.get(cell.targetTierId);
    if (!target || !attackIds.has(cell.attackId)) fail(`${label} identifies unknown coverage`);
    const key = evidenceCellKey(cell.targetTierId, cell.attackId);
    if (seen.has(key)) fail(`${label} is duplicate coverage`);
    seen.add(key);
    for (const field of ['os', 'arch', 'libc', 'tier', 'channel']) {
      if (cell[field] !== target[field]) fail(`${label}.${field} does not match the manifest`);
    }
    if (target.disposition === 'not-applicable') {
      exactKeys(cell, ['targetTierId', 'os', 'arch', 'libc', 'tier', 'channel', 'attackId', 'evidenceRequirement', 'result', 'adrRefs', 'residualRiskIds'], label);
      if (cell.evidenceRequirement !== 'not-applicable') fail(`${label}.evidenceRequirement must be not-applicable`);
      if (cell.result !== 'not-applicable') fail(`${label}.result must be not-applicable`);
      compareCanonical(cell.adrRefs, [...target.adrRefs].sort(), `${label}.adrRefs`);
      compareCanonical(cell.residualRiskIds, [...target.residualRiskIds].sort(), `${label}.residualRiskIds`);
    } else {
      exactKeys(cell, ['targetTierId', 'os', 'arch', 'libc', 'tier', 'channel', 'attackId', 'evidenceRequirement', 'result', 'observedAt', 'evidenceRef', 'artifactSha256', 'residualRiskIds'], label);
      const expectedRequirement = target.manualRequiredAttacks.includes(cell.attackId) ? 'manual-required' : 'automated';
      if (cell.evidenceRequirement !== expectedRequirement) fail(`${label}.evidenceRequirement does not match the manifest`);
      if (!EVIDENCE_RESULTS.includes(cell.result)) fail(`${label}.result is invalid`);
      assertFresh(cell.observedAt, now, manifest.evidenceFreshnessHours, `${label}.observedAt`);
      assertEvidenceRef(
        cell.evidenceRef,
        cell.targetTierId,
        cell.attackId,
        `${label}.evidenceRef`,
        expectedRequirement === 'manual-required',
      );
      assertArtifactSha(cell.artifactSha256, `${label}.artifactSha256`);
      const expectedResidual = target.expectedResidualAttacks.includes(cell.attackId);
      if (expectedResidual && cell.result !== 'expected-residual') fail(`${label} hides an expected Convenience residual`);
      if (!expectedResidual && cell.result === 'expected-residual') fail(`${label} weakens a required denial`);
      if (expectedResidual) compareCanonical(cell.residualRiskIds, [...target.expectedResidualRiskIds].sort(), `${label}.residualRiskIds`);
      else compareCanonical(cell.residualRiskIds, [], `${label}.residualRiskIds`);
    }
  }
  if (seen.size !== expectedKeys.size || [...expectedKeys].some((key) => !seen.has(key))) fail('report.coverage is incomplete');

  const findings = normalizedFindings(
    report.findings,
    new Set(manifest.targetTiers.map(({ id }) => id)),
    attackIds,
    new Set(manifest.adrs.map(({ id }) => id)),
  );
  compareCanonical(report.findings, findings, 'report.findings');
  const gate = computeGate(report.coverage, findings);
  if (report.releaseDecision !== gate.releaseDecision) fail('report.releaseDecision is incorrect');
  compareCanonical(report.blockers, gate.blockers, 'report.blockers');
  compareCanonical(report.summary, summarize(report.coverage, findings), 'report.summary');
  assertNoSecretMaterial(report);
  if (markdown !== undefined && markdown !== renderMarkdown(report)) fail('Markdown report is stale or does not match JSON report');
  return gate;
}

export function validateReport(options) {
  const gate = inspectReport(options);
  if (gate.blockers.length > 0) fail(`release gate blocked: ${gate.blockers.join(', ')}`);
  return true;
}

function markdownCell(value) {
  return String(value).replaceAll('|', '\\|').replaceAll('\n', ' ');
}

export function renderMarkdown(report) {
  assertNoSecretMaterial(report);
  const lines = [
    '# Palladin adversarial security report',
    '',
    `- Source SHA: \`${report.sourceSha}\``,
    `- Manifest SHA-256: \`${report.manifestSha256}\``,
    `- Report SHA-256: \`${report.contentSha256}\``,
    `- Generated at: ${report.generatedAt}`,
    `- Evidence freshness: ${report.evidenceFreshnessHours} hours`,
    `- Release decision: **${report.releaseDecision.toUpperCase()}**`,
    '',
    '## Summary',
    '',
    '| Target tiers | Attacks | Coverage cells | Passed | Expected residual | N/A | Failed | Findings |',
    '| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
    `| ${report.summary.targetTierCount} | ${report.summary.attackCount} | ${report.summary.coverageCellCount} | ${report.summary.resultCounts.passed} | ${report.summary.resultCounts.expectedResidual} | ${report.summary.resultCounts.notApplicable} | ${report.summary.resultCounts.failed} | ${report.summary.findingCount} |`,
    '',
    '## Release blockers',
    '',
  ];
  if (report.blockers.length === 0) lines.push('None.');
  else for (const blocker of report.blockers) lines.push(`- \`${blocker}\``);
  lines.push('', '## Target x tier x attack coverage', '');
  lines.push('| Target tier | OS | Arch | libc | Tier | Channel | Attack | Evidence requirement | Result | Artifact SHA-256 | Evidence | Residual risks / ADRs |');
  lines.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |');
  for (const cell of report.coverage) {
    const evidence = cell.evidenceRef ?? '-';
    const refs = [...(cell.residualRiskIds ?? []), ...(cell.adrRefs ?? [])].join(', ') || '-';
    lines.push(`| ${markdownCell(cell.targetTierId)} | ${cell.os} | ${cell.arch} | ${cell.libc} | ${cell.tier} | ${cell.channel} | ${markdownCell(cell.attackId)} | ${cell.evidenceRequirement} | ${cell.result} | ${cell.artifactSha256 ?? '-'} | ${markdownCell(evidence)} | ${markdownCell(refs)} |`);
  }
  lines.push('', '## Findings', '');
  if (report.findings.length === 0) lines.push('None.');
  else {
    lines.push('| ID | Severity | Status | Targets | Attacks | ADRs |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const finding of report.findings) {
      lines.push(`| ${markdownCell(finding.id)} | ${finding.severity} | ${finding.status} | ${markdownCell(finding.targetTierIds.join(', '))} | ${markdownCell(finding.attackIds.join(', '))} | ${markdownCell(finding.adrRefs.join(', ') || '-')} |`);
    }
  }
  lines.push('', '## Residual risks', '');
  const adrById = new Map(report.adrs.map((adr) => [adr.id, adr.href]));
  for (const risk of report.residualRisks) {
    lines.push(`### ${risk.id}: ${risk.title}`, '', risk.statement, '');
    lines.push(`Owner: \`${risk.owner}\``, `Review date: ${risk.reviewDate}`, `ADR: ${risk.adrRefs.map((id) => `[${id}](${adrById.get(id)})`).join(', ')}`, '');
  }
  return `${lines.join('\n')}\n`;
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!['evidence', 'generate', 'validate'].includes(command)) fail('usage: report.mjs <evidence|generate|validate> [options]');
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (!flag?.startsWith('--') || value === undefined) fail(`invalid argument: ${flag ?? ''}`);
    options[flag.slice(2)] = value;
  }
  const allowed = command === 'generate'
    ? new Set(['manifest', 'evidence', 'source-sha', 'json', 'markdown', 'now'])
    : command === 'evidence'
      ? new Set(['manifest', 'source-sha', 'targets', 'artifact-hashes', 'observed-at', 'outcomes', 'evidence-refs', 'findings', 'json'])
      : new Set(['manifest', 'source-sha', 'json', 'markdown', 'now']);
  for (const key of Object.keys(options)) if (!allowed.has(key)) fail(`unknown option: --${key}`);
  const required = command === 'generate'
    ? ['evidence', 'source-sha', 'json', 'markdown']
    : command === 'evidence'
      ? ['source-sha', 'targets', 'artifact-hashes', 'observed-at', 'outcomes', 'evidence-refs', 'findings', 'json']
      : ['source-sha', 'json', 'markdown'];
  for (const key of required) {
    if (!options[key]) fail(`--${key} is required`);
  }
  return { command, options };
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

function writeAtomic(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  try {
    writeFileSync(temporary, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function cli(argv) {
  const { command, options } = parseArgs(argv);
  const manifest = loadManifest(options.manifest ? resolve(options.manifest) : DEFAULT_MANIFEST_PATH);
  if (command === 'evidence') {
    const targets = options.targets.split(',').map((value) => value.trim()).filter(Boolean);
    const shard = createEvidenceShard({
      manifest,
      sourceSha: options['source-sha'],
      targetTierIds: targets,
      artifactSha256ByTarget: readJson(resolve(options['artifact-hashes']), 'artifact hashes'),
      observedAt: options['observed-at'],
      outcomes: readJson(resolve(options.outcomes), 'outcomes'),
      evidenceRefs: readJson(resolve(options['evidence-refs']), 'evidence references'),
      findings: readJson(resolve(options.findings), 'findings'),
    });
    writeAtomic(resolve(options.json), `${JSON.stringify(shard, null, 2)}\n`);
    return;
  }
  const now = options.now ? new Date(options.now) : new Date();
  if (command === 'generate') {
    const report = generateReport({
      manifest,
      evidenceBundle: readJson(resolve(options.evidence), 'evidence'),
      expectedSourceSha: options['source-sha'],
      now,
    });
    const markdown = renderMarkdown(report);
    writeAtomic(resolve(options.json), `${JSON.stringify(report, null, 2)}\n`);
    writeAtomic(resolve(options.markdown), markdown);
    const gate = inspectReport({ manifest, report, expectedSourceSha: options['source-sha'], now, markdown });
    if (gate.blockers.length > 0) fail(`release gate blocked: ${gate.blockers.join(', ')}`);
    return;
  }
  const report = readJson(resolve(options.json), 'report');
  const markdown = readFileSync(resolve(options.markdown), 'utf8');
  validateReport({ manifest, report, expectedSourceSha: options['source-sha'], now, markdown });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    cli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`adversarial report failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  }
}
