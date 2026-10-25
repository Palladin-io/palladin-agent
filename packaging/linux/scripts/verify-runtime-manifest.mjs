import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { verifyArtifactIntegrityBinding } from '../../../dist/runtime/version-policy.js';

try {
  const required = ['manifest', 'public-key', 'version', 'source-sha', 'architecture', 'binaries'];
  const values = new Map();
  for (let index = 2; index < process.argv.length; index += 2) {
    const key = process.argv[index]?.replace(/^--/, '');
    const value = process.argv[index + 1];
    if (!process.argv[index].startsWith('--') || !required.includes(key)
      || !value || values.has(key)) throw new Error();
    values.set(key, value);
  }
  if (values.size !== required.length || !['x64', 'arm64'].includes(values.get('architecture'))) throw new Error();
  const binaries = resolve(values.get('binaries'));
  const digest = (name) => createHash('sha256').update(readRegular(join(binaries, name), 256 * 1024 * 1024)).digest('hex');
  const binding = verifyArtifactIntegrityBinding(readRegular(resolve(values.get('manifest')), 64 * 1024), {
    packageName: `@palladin/runtime-linux-${values.get('architecture')}-gnu`,
    version: values.get('version'),
    sourceSha: values.get('source-sha'),
    executableSha256: digest('palladin-linux-client'),
  }, { publicKeyBase64: values.get('public-key') });
  if (binding.workerExecutableSha256 !== digest('palladin-worker')) throw new Error();
} catch {
  process.stderr.write('Linux system package requires a valid release signature binding the exact version, source, architecture, client and worker\n');
  process.exitCode = 1;
}

function readRegular(path, maximum) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maximum) throw new Error();
    const bytes = readFileSync(descriptor);
    if (bytes.length !== metadata.size) throw new Error();
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}
