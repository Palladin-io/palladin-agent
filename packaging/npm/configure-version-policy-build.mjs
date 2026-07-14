import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith('--') || value === undefined || values.has(key.slice(2))) fail();
  values.set(key.slice(2), value);
}
if ([...values.keys()].some((key) => !['public-key', 'source-sha', 'bundle'].includes(key))) fail();
const publicKey = values.get('public-key');
const sourceSha = values.get('source-sha');
const bundlePath = values.get('bundle');
if (publicKey === undefined || sourceSha === undefined || bundlePath === undefined) fail();

const keyBytes = Buffer.from(publicKey, 'base64');
if (keyBytes.length !== 32 || keyBytes.toString('base64') !== publicKey
  || keyBytes.every((byte) => byte === 0)) fail();
if (!/^[0-9a-f]{40}$/.test(sourceSha) || /^0{40}$/.test(sourceSha)) fail();
const bundle = readFileSync(resolve(bundlePath));
if (bundle.length === 0 || bundle.length > 64 * 1024) fail();
try {
  JSON.parse(bundle.toString('utf8'));
} catch {
  fail();
}

const source = `// Generated from public, owner-approved release inputs. Never place a private key here.
export const VERSION_POLICY_SOURCE = 'https://releases.palladin.io/agent/version-policy.json';
export const VERSION_POLICY_PUBLIC_KEY_BASE64 = ${JSON.stringify(publicKey)};
export const RUNTIME_SOURCE_SHA = ${JSON.stringify(sourceSha)};
export const VERSION_POLICY_BUNDLE_BASE64 = ${JSON.stringify(bundle.toString('base64'))};
`;
writeFileSync(resolve('src/runtime/version-policy-build.ts'), source, { encoding: 'utf8', mode: 0o644 });

function fail() {
  process.stderr.write('version-policy release inputs are missing or invalid\n');
  process.exit(1);
}
