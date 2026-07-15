import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith('--') || value === undefined || values.has(key.slice(2))
    || !['output-private-key', 'output-public-key'].includes(key.slice(2))) fail();
  values.set(key.slice(2), value);
}
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
writeFileSync(resolve(required('output-private-key')), privateKey.export({
  format: 'pem', type: 'pkcs8',
}), { flag: 'wx', mode: 0o600 });
writeFileSync(resolve(required('output-public-key')), publicKey.export({
  format: 'der', type: 'spki',
}).subarray(-32).toString('base64'), { encoding: 'utf8', flag: 'wx', mode: 0o600 });

function required(name) {
  const value = values.get(name);
  if (value === undefined) fail();
  return value;
}

function fail() {
  process.stderr.write('CI version-policy key outputs are invalid\n');
  process.exit(1);
}
