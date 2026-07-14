import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { canonicalizeVersionPolicyPayload, parseAndVerifyHistoricalVersionPolicy } from '../../dist/runtime/version-policy.js';

const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith('--') || value === undefined || values.has(key.slice(2))) fail();
  values.set(key.slice(2), value);
}
if ([...values.keys()].some((key) => !['current', 'public-key', 'issued-at', 'output'].includes(key))) fail();
const issuedAt = required('issued-at');
const issued = new Date(issuedAt);
if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(issuedAt)
  || issued.toISOString() !== issuedAt.replace('Z', '.000Z')) fail();
const current = parseAndVerifyHistoricalVersionPolicy(readFileSync(resolve(required('current'))), {
  publicKeyBase64: required('public-key'),
  source: 'https://releases.palladin.io/agent/version-policy.json',
}).signed;
const payload = {
  ...current,
  sequence: current.sequence + 1,
  issuedAt,
  expiresAt: new Date(issued.getTime() + 30 * 24 * 60 * 60 * 1000)
    .toISOString().replace('.000Z', 'Z'),
};
writeFileSync(resolve(required('output')), canonicalizeVersionPolicyPayload(payload), { mode: 0o600 });
function required(name) { const value = values.get(name); if (value === undefined) fail(); return value; }
function fail() { process.stderr.write('renewal inputs are missing or current policy is invalid/expired\n'); process.exit(1); }
