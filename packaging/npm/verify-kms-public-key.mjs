import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const pemIndex = process.argv.indexOf('--pem');
const expectedIndex = process.argv.indexOf('--expected');
if (process.argv.length !== 6 || pemIndex < 0 || expectedIndex < 0) fail();
try {
  const key = createPublicKey(readFileSync(resolve(process.argv[pemIndex + 1])));
  const der = key.export({ format: 'der', type: 'spki' });
  const raw = der.subarray(-32).toString('base64');
  if (der.length !== 44 || raw !== process.argv[expectedIndex + 1]) fail();
} catch {
  fail();
}
function fail() { process.stderr.write('KMS Ed25519 public key does not match the pinned build key\n'); process.exit(1); }
