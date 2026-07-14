import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  canonicalizeVersionPolicyEnvelope,
  canonicalizeVersionPolicyPayload,
  parseAndVerifyVersionPolicy,
} from '../../dist/runtime/version-policy.js';

const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith('--') || value === undefined || values.has(key.slice(2))) fail();
  values.set(key.slice(2), value);
}
if ([...values.keys()].some((key) => !['payload', 'signature', 'public-key', 'output'].includes(key))) fail();
const payloadBytes = readFileSync(resolve(required('payload')));
const payload = JSON.parse(payloadBytes.toString('utf8'));
if (canonicalizeVersionPolicyPayload(payload) !== payloadBytes.toString('utf8')) fail();
const signature = readFileSync(resolve(required('signature')), 'utf8').trim();
const envelope = { signature, signed: payload };
const canonical = canonicalizeVersionPolicyEnvelope(envelope);
parseAndVerifyVersionPolicy(Buffer.from(canonical), {
  publicKeyBase64: required('public-key'),
  source: 'https://releases.palladin.io/agent/version-policy.json',
});
writeFileSync(resolve(required('output')), canonical, { mode: 0o600 });

function required(name) { const value = values.get(name); if (value === undefined) fail(); return value; }
function fail() { process.stderr.write('KMS signature or canonical policy envelope is invalid\n'); process.exit(1); }
