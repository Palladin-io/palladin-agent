import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { parseAndVerifyVersionPolicy } from '../../dist/runtime/version-policy.js';

const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith('--') || value === undefined || values.has(key.slice(2))) fail();
  values.set(key.slice(2), value);
}
if ([...values.keys()].some((key) => !['bundle', 'public-key'].includes(key))) fail();
const bundle = values.get('bundle');
const publicKey = values.get('public-key');
if (bundle === undefined || publicKey === undefined) fail();
const bytes = readFileSync(resolve(bundle));
if (bytes.length === 0 || bytes.length > 64 * 1024) fail();
const envelope = parseAndVerifyVersionPolicy(bytes, {
  publicKeyBase64: publicKey,
  source: 'https://releases.palladin.io/agent/version-policy.json',
});
const digest = createHash('sha256').update(bytes).digest('hex');
process.stdout.write(`${envelope.signed.sequence}-${digest}.json`);

function fail() {
  process.stderr.write('signed version-policy object identity is invalid\n');
  process.exit(1);
}
