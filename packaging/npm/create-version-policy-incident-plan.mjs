import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  canonicalizeVersionPolicyPayload,
  parseAndVerifyHistoricalVersionPolicy,
} from '../../dist/runtime/version-policy.js';

const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith('--') || value === undefined || values.has(key.slice(2))) fail();
  values.set(key.slice(2), value);
}
const allowed = ['current', 'block-version', 'safe-version', 'output-dir', 'public-key', 'issued-at'];
if ([...values.keys()].some((key) => !allowed.includes(key))) fail();
const current = values.get('current');
const blocked = values.get('block-version');
const safe = values.get('safe-version');
const output = values.get('output-dir');
const publicKey = values.get('public-key');
const issuedAt = values.get('issued-at');
if ([current, blocked, safe, output, publicKey, issuedAt].some((value) => value === undefined)
  || !exactVersion(blocked) || !exactVersion(safe) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(issuedAt)) fail();
const issued = new Date(issuedAt);
if (!Number.isFinite(issued.getTime()) || issued.toISOString() !== issuedAt.replace('Z', '.000Z')) fail();
const envelope = parseAndVerifyHistoricalVersionPolicy(readFileSync(resolve(current)), {
  publicKeyBase64: publicKey,
  source: 'https://releases.palladin.io/agent/version-policy.json',
});
if (blocked === safe || !envelope.signed.artifacts.some((artifact) => artifact.version === safe)) fail();
const expires = new Date(issued.getTime() + 30 * 24 * 60 * 60 * 1000)
  .toISOString().replace('.000Z', 'Z');
const payload = {
  ...envelope.signed,
  sequence: envelope.signed.sequence + 1,
  issuedAt,
  expiresAt: expires,
  recommendedVersion: safe,
  blockedVersions: [...new Set([...envelope.signed.blockedVersions, blocked])].sort(),
};
const canonical = canonicalizeVersionPolicyPayload(payload);
mkdirSync(resolve(output), { recursive: false, mode: 0o700 });
writeFileSync(resolve(output, 'version-policy-unsigned.json'), canonical, { mode: 0o600 });

const packages = ['@palladin/agent', ...[...new Set(payload.artifacts.map((artifact) => artifact.packageName))].sort()];
const reason = 'This release is blocked by Palladin signed security policy. Install the latest safe version.';
const commands = [
  '# REVIEW ONLY - this file is never executed by Palladin tooling.',
  '# Run manually as the npm owner with interactive 2FA after the signed policy is published.',
  ...packages.map((name) => `npm deprecate ${shell(name)}@${shell(blocked)} ${shell(reason)}`),
  `npm dist-tag add ${shell('@palladin/agent')}@${shell(safe)} latest`,
  '',
];
writeFileSync(resolve(output, 'npm-incident-plan.txt'), commands.join('\n'), { mode: 0o600 });
process.stdout.write(`Unsigned canonical policy and manual npm plan written to ${resolve(output)}\n`);

function exactVersion(value) {
  return typeof value === 'string' && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value)
    && value.split('.').every((part) => Number.isSafeInteger(Number(part)));
}

function shell(value) {
  if (!/^[A-Za-z0-9@/._ -]+$/.test(value)) fail();
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function fail() {
  process.stderr.write('incident plan inputs are missing, unsafe, or inconsistent\n');
  process.exit(1);
}
