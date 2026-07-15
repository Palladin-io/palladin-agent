import { createHash, createPublicKey, randomUUID, verify as verifySignature } from 'node:crypto';
import {
  closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync,
  renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { canonicalJson, loadManifest, validateReport } from './report.mjs';

const SOURCE_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const OPERATOR = /^[a-z0-9](?:[a-z0-9-]{0,38})$/;
const KIND = 'palladin-lifecycle-operator-approval';
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function fail(message) { throw new Error(message); }
function isRecord(value) { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function exactKeys(value, keys, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has an invalid shape`);
}
function timestamp(value, label) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail(`${label} must be an ISO-8601 UTC timestamp`);
  }
  return Date.parse(value);
}
function readRegularFile(path, label, encoding) {
  const absolute = resolve(path);
  const descriptor = openSync(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor); const linked = lstatSync(absolute);
    if (!opened.isFile() || linked.isSymbolicLink() || opened.dev !== linked.dev || opened.ino !== linked.ino) {
      fail(`${label} changed while it was opened`);
    }
    return readFileSync(descriptor, encoding);
  } finally { closeSync(descriptor); }
}
function readJson(path, label) {
  try { return JSON.parse(readRegularFile(path, label, 'utf8')); }
  catch (error) { fail(`${label} must be valid JSON: ${error instanceof Error ? error.message : 'unknown error'}`); }
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
function physicalEvidence(report) {
  if (!Array.isArray(report.targets)) fail('report targets are invalid');
  const targets = report.targets.map((target) => {
    if (typeof target.targetId !== 'string' || !Array.isArray(target.steps) || !Array.isArray(target.artifacts)) {
      fail('report target evidence is invalid');
    }
    const cells = target.steps.map((step) => ({
      stepId: step.stepId,
      result: step.result,
      observedAt: step.observedAt,
      evidenceRef: step.evidenceRef,
    }));
    if (cells.length === 0) fail('report has no lifecycle evidence');
    return {
      targetId: target.targetId,
      cellCount: cells.length,
      cellsSha256: createHash('sha256').update(canonicalJson(cells), 'utf8').digest('hex'),
      artifactSha256: [...new Set(target.artifacts.map((artifact) => artifact.sha256))].sort(),
    };
  }).sort((left, right) => left.targetId.localeCompare(right.targetId));
  if (targets.length === 0) fail('report has no lifecycle evidence');
  return targets;
}

export function createOperatorApprovalPayload({ report, operator, approvedAt }) {
  if (!isRecord(report) || !SOURCE_SHA.test(report.sourceSha)
    || !SHA256.test(report.contentSha256) || report.releaseDecision !== 'eligible') {
    fail('report is not eligible for operator approval');
  }
  if (typeof operator !== 'string' || !OPERATOR.test(operator)) fail('operator is invalid');
  timestamp(approvedAt, 'approvedAt');
  return {
    schemaVersion: 1,
    kind: KIND,
    operator,
    approvedAt,
    sourceSha: report.sourceSha,
    reportContentSha256: report.contentSha256,
    physicalEvidence: physicalEvidence(report),
  };
}
function publicKey(value) {
  const text = String(value).trim();
  if (text.startsWith('-----BEGIN PUBLIC KEY-----')) return createPublicKey(text);
  const raw = Buffer.from(text, 'base64');
  if (raw.length !== 32 || raw.toString('base64') !== text) fail('operator approval public key is invalid');
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}
function signature(value) {
  if (typeof value !== 'string') fail('operator approval signature is missing');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== value) fail('operator approval signature is invalid');
  return bytes;
}
export function verifyOperatorApproval({ report, approval, publicKeyPem, expectedOperator, expectedSourceSha, now = new Date() }) {
  exactKeys(approval, ['signature', 'signed'], 'operator approval');
  exactKeys(approval.signed, ['schemaVersion', 'kind', 'operator', 'approvedAt', 'sourceSha', 'reportContentSha256', 'physicalEvidence'], 'operator approval payload');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime()) || !SOURCE_SHA.test(expectedSourceSha)
    || !OPERATOR.test(expectedOperator)) fail('operator approval verification context is invalid');
  const expected = createOperatorApprovalPayload({
    report,
    operator: expectedOperator,
    approvedAt: approval.signed.approvedAt,
  });
  if (canonicalJson(approval.signed) !== canonicalJson(expected)
    || approval.signed.schemaVersion !== 1 || approval.signed.kind !== KIND
    || approval.signed.sourceSha !== expectedSourceSha) fail('operator approval does not match the exact lifecycle report');
  const approvedAt = timestamp(approval.signed.approvedAt, 'operator approval approvedAt');
  const generatedAt = timestamp(report.generatedAt, 'report generatedAt');
  if (approvedAt < generatedAt || approvedAt > now.getTime() + 5 * 60 * 1000
    || now.getTime() - approvedAt > report.evidenceFreshnessHours * 60 * 60 * 1000) {
    fail('operator approval is stale or has an invalid timestamp');
  }
  let key;
  try { key = publicKey(publicKeyPem); } catch { fail('operator approval public key is invalid'); }
  if (key.asymmetricKeyType !== 'ed25519') fail('operator approval key must be Ed25519');
  if (!verifySignature(null, Buffer.from(canonicalJson(approval.signed), 'utf8'), key, signature(approval.signature))) {
    fail('operator approval signature is invalid');
  }
  return true;
}
function parse(argv) {
  const [command, ...rest] = argv;
  if (!['payload', 'assemble', 'verify'].includes(command)) fail('usage: operator-approval.mjs <payload|assemble|verify> [options]');
  const options = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index]; const value = rest[index + 1];
    if (!flag?.startsWith('--') || value === undefined || options.has(flag)) fail('invalid arguments');
    options.set(flag, value);
  }
  const common = ['--report', '--markdown', '--source-sha', '--operator'];
  const required = command === 'payload'
    ? [...common, '--approved-at', '--output']
    : command === 'assemble'
      ? [...common, '--payload', '--signature', '--public-key', '--output']
      : [...common, '--approval', '--public-key'];
  const allowed = new Set([...required, '--manifest', '--now']);
  for (const flag of options.keys()) if (!allowed.has(flag)) fail(`unknown option: ${flag}`);
  for (const flag of required) if (!options.has(flag)) fail(`${flag} is required`);
  return { command, options };
}
function context(options) {
  const report = readJson(options.get('--report'), 'lifecycle report');
  const markdown = readRegularFile(options.get('--markdown'), 'lifecycle Markdown', 'utf8');
  const manifest = options.has('--manifest') ? readJson(options.get('--manifest'), 'lifecycle manifest') : loadManifest();
  const now = options.has('--now') ? new Date(options.get('--now')) : new Date();
  validateReport({ manifest, report, expectedSourceSha: options.get('--source-sha'), now, markdown });
  return { report, now };
}
function cli(argv) {
  const { command, options } = parse(argv);
  const { report, now } = context(options);
  if (command === 'payload') {
    writeAtomic(options.get('--output'), canonicalJson(createOperatorApprovalPayload({
      report, operator: options.get('--operator'), approvedAt: options.get('--approved-at'),
    })));
    return;
  }
  const publicKeyPem = readRegularFile(options.get('--public-key'), 'public key', 'utf8');
  if (command === 'assemble') {
    const approval = {
      signed: readJson(options.get('--payload'), 'approval payload'),
      signature: readRegularFile(options.get('--signature'), 'signature', 'utf8').trim(),
    };
    verifyOperatorApproval({ report, approval, publicKeyPem, expectedOperator: options.get('--operator'), expectedSourceSha: options.get('--source-sha'), now });
    writeAtomic(options.get('--output'), `${canonicalJson(approval)}\n`);
  } else {
    verifyOperatorApproval({
      report,
      approval: readJson(options.get('--approval'), 'operator approval'),
      publicKeyPem,
      expectedOperator: options.get('--operator'),
      expectedSourceSha: options.get('--source-sha'),
      now,
    });
  }
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { cli(process.argv.slice(2)); } catch (error) {
    process.stderr.write(`lifecycle operator approval failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  }
}
