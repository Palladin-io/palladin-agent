import {
  createPublicKey,
  randomUUID,
  verify as verifySignature,
} from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  canonicalJson,
  loadManifest,
  validateReport,
} from './report.mjs';

const SOURCE_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const OPERATOR = /^[a-z0-9](?:[a-z0-9-]{0,38})$/;
const KIND = 'palladin-adversarial-operator-approval';
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function fail(message) {
  throw new Error(message);
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value, expected, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    fail(`${label} has an invalid shape`);
  }
}

function timestamp(value, label) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))
    || new Date(value).toISOString() !== value) fail(`${label} must be an ISO-8601 UTC timestamp`);
  return Date.parse(value);
}

function readRegularFile(path, label, encoding) {
  const absolute = resolve(path);
  const descriptor = openSync(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor);
    const linked = lstatSync(absolute);
    if (!opened.isFile() || linked.isSymbolicLink()
      || opened.dev !== linked.dev || opened.ino !== linked.ino) {
      fail(`${label} changed while it was opened`);
    }
    return readFileSync(descriptor, encoding);
  } finally {
    closeSync(descriptor);
  }
}

function readJson(path, label) {
  try {
    return JSON.parse(readRegularFile(path, label, 'utf8'));
  } catch (error) {
    fail(`${label} must be valid JSON: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

function writeAtomic(path, content) {
  const absolute = resolve(path);
  mkdirSync(dirname(absolute), { recursive: true });
  const temporary = join(dirname(absolute), `.${basename(absolute)}.${randomUUID()}.tmp`);
  try {
    writeFileSync(temporary, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    renameSync(temporary, absolute);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function manualEvidence(report) {
  const cells = report.coverage
    .filter((cell) => cell.evidenceRequirement === 'manual-required')
    .map((cell) => ({
      targetTierId: cell.targetTierId,
      attackId: cell.attackId,
      result: cell.result,
      observedAt: cell.observedAt,
      evidenceRef: cell.evidenceRef,
      artifactSha256: cell.artifactSha256,
    }))
    .sort((left, right) => `${left.targetTierId}\0${left.attackId}`
      .localeCompare(`${right.targetTierId}\0${right.attackId}`));
  if (cells.length === 0) fail('report has no manual evidence to approve');
  return cells;
}

export function createOperatorApprovalPayload({ report, operator, approvedAt }) {
  if (!isRecord(report) || !SOURCE_SHA.test(report.sourceSha)
    || !SHA256.test(report.contentSha256) || !Array.isArray(report.coverage)) {
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
    manualEvidence: manualEvidence(report),
  };
}

function decodeSignature(value) {
  if (typeof value !== 'string' || value.length === 0) fail('operator approval signature is missing');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== value) {
    fail('operator approval signature is not canonical Ed25519 base64');
  }
  return bytes;
}

function operatorPublicKey(value) {
  const text = String(value).trim();
  if (text.startsWith('-----BEGIN PUBLIC KEY-----')) return createPublicKey(text);
  const raw = Buffer.from(text, 'base64');
  if (raw.length !== 32 || raw.toString('base64') !== text) {
    fail('operator approval public key is invalid');
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

export function verifyOperatorApproval({
  report,
  approval,
  publicKeyPem,
  expectedOperator,
  expectedSourceSha,
  now = new Date(),
}) {
  exactKeys(approval, ['signature', 'signed'], 'operator approval');
  exactKeys(approval.signed, [
    'schemaVersion',
    'kind',
    'operator',
    'approvedAt',
    'sourceSha',
    'reportContentSha256',
    'manualEvidence',
  ], 'operator approval payload');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail('now must be a valid Date');
  if (!SOURCE_SHA.test(expectedSourceSha)) fail('expected source SHA is invalid');
  if (!OPERATOR.test(expectedOperator)) fail('expected operator is invalid');
  const expected = createOperatorApprovalPayload({
    report,
    operator: expectedOperator,
    approvedAt: approval.signed.approvedAt,
  });
  if (canonicalJson(approval.signed) !== canonicalJson(expected)) {
    fail('operator approval does not match the exact report and manual evidence');
  }
  if (approval.signed.schemaVersion !== 1 || approval.signed.kind !== KIND
    || approval.signed.sourceSha !== expectedSourceSha) fail('operator approval policy is invalid');
  const approvedAt = timestamp(approval.signed.approvedAt, 'operator approval approvedAt');
  const generatedAt = timestamp(report.generatedAt, 'report generatedAt');
  if (approvedAt < generatedAt) fail('operator approval predates the report');
  if (approvedAt > now.getTime() + 5 * 60 * 1000) fail('operator approval is in the future');
  if (now.getTime() - approvedAt > report.evidenceFreshnessHours * 60 * 60 * 1000) {
    fail('operator approval is stale');
  }
  let publicKey;
  try {
    publicKey = operatorPublicKey(publicKeyPem);
  } catch {
    fail('operator approval public key is invalid');
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') fail('operator approval key must be Ed25519');
  const valid = verifySignature(
    null,
    Buffer.from(canonicalJson(approval.signed), 'utf8'),
    publicKey,
    decodeSignature(approval.signature),
  );
  if (!valid) fail('operator approval signature is invalid');
  return true;
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!['payload', 'assemble', 'verify'].includes(command)) {
    fail('usage: operator-approval.mjs <payload|assemble|verify> [options]');
  }
  const options = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
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

function reportContext(options) {
  const report = readJson(options.get('--report'), 'report');
  const markdown = readRegularFile(options.get('--markdown'), 'Markdown report', 'utf8');
  const manifest = options.has('--manifest')
    ? readJson(options.get('--manifest'), 'coverage manifest')
    : loadManifest();
  const now = options.has('--now') ? new Date(options.get('--now')) : new Date();
  validateReport({
    manifest,
    report,
    expectedSourceSha: options.get('--source-sha'),
    now,
    markdown,
  });
  return { report, now };
}

function cli(argv) {
  const { command, options } = parseArgs(argv);
  const { report, now } = reportContext(options);
  if (command === 'payload') {
    const payload = createOperatorApprovalPayload({
      report,
      operator: options.get('--operator'),
      approvedAt: options.get('--approved-at'),
    });
    writeAtomic(options.get('--output'), canonicalJson(payload));
    return;
  }
  const publicKeyPem = readRegularFile(options.get('--public-key'), 'public key', 'utf8');
  if (command === 'assemble') {
    const signed = readJson(options.get('--payload'), 'approval payload');
    const signature = readRegularFile(options.get('--signature'), 'signature', 'utf8').trim();
    const approval = { signature, signed };
    verifyOperatorApproval({
      report,
      approval,
      publicKeyPem,
      expectedOperator: options.get('--operator'),
      expectedSourceSha: options.get('--source-sha'),
      now,
    });
    writeAtomic(options.get('--output'), `${canonicalJson(approval)}\n`);
    return;
  }
  verifyOperatorApproval({
    report,
    approval: readJson(options.get('--approval'), 'operator approval'),
    publicKeyPem,
    expectedOperator: options.get('--operator'),
    expectedSourceSha: options.get('--source-sha'),
    now,
  });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    cli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`adversarial operator approval failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  }
}
