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
if ([...values.keys()].some((key) => !['public-key', 'source-sha', 'bundle', 'version'].includes(key))) fail();
const publicKey = values.get('public-key');
const sourceSha = values.get('source-sha');
const bundle = values.get('bundle');
const version = values.get('version');
if (publicKey === undefined || sourceSha === undefined || bundle === undefined || version === undefined) fail();

const envelope = parseAndVerifyVersionPolicy(readFileSync(resolve(bundle)), {
  publicKeyBase64: publicKey,
  source: 'https://releases.palladin.io/agent/version-policy.json',
});
const expected = [
  '@palladin/runtime-darwin-arm64',
  '@palladin/runtime-darwin-x64',
  '@palladin/runtime-linux-arm64-gnu',
  '@palladin/runtime-linux-arm64-musl',
  '@palladin/runtime-linux-x64-gnu',
  '@palladin/runtime-linux-x64-musl',
  '@palladin/runtime-win32-arm64',
  '@palladin/runtime-win32-x64',
];
const actual = envelope.signed.artifacts
  .filter((artifact) => artifact.version === version && artifact.sourceSha === sourceSha)
  .map((artifact) => artifact.packageName)
  .sort();
if (JSON.stringify(actual) !== JSON.stringify(expected)) fail();

function fail() {
  process.stderr.write('configured version-policy bundle does not bind the exact release set\n');
  process.exit(1);
}
