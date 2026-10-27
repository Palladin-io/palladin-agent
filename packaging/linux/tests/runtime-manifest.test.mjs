import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { canonicalizeVersionPolicyEnvelope, canonicalizeVersionPolicyPayload } from '../../../dist/runtime/version-policy.js';

const script = resolve('packaging/linux/scripts/verify-runtime-manifest.mjs');
const source = '1234567890abcdef1234567890abcdef12345678';
function fixture(t, architecture = 'x64') {
  const root = mkdtempSync(join(tmpdir(), 'palladin-linux-manifest-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
  writeFileSync(join(root, 'palladin-linux-client'), 'test client');
  writeFileSync(join(root, 'palladin-worker'), 'test worker');
  const digest = (name) => createHash('sha256').update(readFileSync(join(root, name))).digest('hex');
  const signed = { schemaVersion: 2, artifacts: [{
    packageName: `@palladin/runtime-linux-${architecture}-gnu`, version: '1.2.3', sourceSha: source,
    executableSha256: digest('palladin-linux-client'), workerExecutableSha256: digest('palladin-worker'),
  }] };
  const manifest = join(root, 'release-signature.json');
  const signature = sign(null, Buffer.from(canonicalizeVersionPolicyPayload(signed)), keys.privateKey).toString('base64');
  writeFileSync(manifest, canonicalizeVersionPolicyEnvelope({ signed, signature }));
  const run = (overrides = {}) => {
    const options = { manifest, 'public-key': publicKey, version: '1.2.3', 'source-sha': source, architecture, binaries: root, ...overrides };
    return spawnSync(process.execPath, [script, ...Object.entries(options).flatMap(([key, value]) => [`--${key}`, value])], { encoding: 'utf8' });
  };
  return { root, manifest, publicKey, run };
}

test('accepts the signed exact client and worker pair', (t) => {
  const f = fixture(t);
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
});
for (const binary of ['palladin-linux-client', 'palladin-worker']) {
  test(`rejects modified ${binary} bytes`, (t) => {
    const f = fixture(t);
    writeFileSync(join(f.root, binary), 'modified');
    assert.notEqual(f.run().status, 0);
  });
}
for (const [key, value] of [['version', '1.2.4'], ['architecture', 'arm64'], ['source-sha', 'a'.repeat(40)]]) {
  test(`rejects a valid signature for another ${key}`, (t) => {
    const f = fixture(t);
    assert.notEqual(f.run({ [key]: value }).status, 0);
  });
}
test('rejects absent manifest and invalid signature', (t) => {
  const f = fixture(t);
  const envelope = JSON.parse(readFileSync(f.manifest, 'utf8'));
  envelope.signature = Buffer.alloc(64).toString('base64');
  writeFileSync(f.manifest, canonicalizeVersionPolicyEnvelope(envelope));
  assert.notEqual(f.run().status, 0);
  rmSync(f.manifest);
  assert.notEqual(f.run().status, 0);
});

for (const [format, development] of [['deb', false], ['rpm', false], ['deb', true], ['rpm', true]]) {
  test(`${format}${development ? " development" : ""} contains the verified runtime manifest with root ownership`, { skip: process.platform !== 'linux' || process.env.PALLADIN_TEST_SYSTEM_PACKAGES !== '1' }, (t) => {
    const architecture = process.arch === 'arm64' ? 'arm64' : 'x64';
    const f = fixture(t, architecture);
    for (const name of ['palladin-linux-service', 'palladin-linux-executor', 'palladin-linux-admin-purge']) {
      writeFileSync(join(f.root, name), 'test executable');
    }
    const output = join(f.root, 'output');
    const packageVersion = development ? '1.2.3.dev1' : '1.2.3';
    const result = spawnSync('bash', [resolve(`packaging/linux/${format}/build-${format}.sh`),
      '--version', packageVersion, '--architecture', architecture, '--binaries', f.root, '--output', output,
      '--release-manifest', f.manifest, '--public-key', f.publicKey, '--source-sha', source,
      ...(development ? ['--development-loopback'] : []),
    ], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    if (format === 'deb') {
      const file = join(output, `palladin-runtime_${packageVersion}-1_${architecture === 'arm64' ? 'arm64' : 'amd64'}.deb`);
      const listing = spawnSync('dpkg-deb', ['--contents', file], { encoding: 'utf8' });
      assert.equal(listing.status, 0, listing.stderr);
      assert.match(listing.stdout, /-rw-r--r-- root\/root .*\.\/usr\/lib\/palladin\/runtime\/release-signature\.json/);
      const extracted = join(f.root, 'extracted');
      assert.equal(spawnSync('dpkg-deb', ['--extract', file, extracted]).status, 0);
      assert.equal(readFileSync(join(extracted, 'usr/lib/palladin/runtime/release-signature.json'), 'utf8'), readFileSync(f.manifest, 'utf8'));
    } else {
      const file = join(output, `palladin-runtime-${packageVersion}-1.${architecture === 'arm64' ? 'aarch64' : 'x86_64'}.rpm`);
      const listing = spawnSync('rpm', ['-qp', '--qf', '[%{FILENAMES} %{FILEUSERNAME} %{FILEGROUPNAME} %{FILEMODES:perms} %{FILEDIGESTS}\n]', file], { encoding: 'utf8' });
      assert.equal(listing.status, 0, listing.stderr);
      const digest = createHash('sha256').update(readFileSync(f.manifest)).digest('hex');
      assert.ok(listing.stdout.includes(`/usr/lib/palladin/runtime/release-signature.json root root -rw-r--r-- ${digest}`));
    }
  });
}
