import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { PLATFORM_PACKAGE_NAMES, PUBLIC_PACKAGE_NAMES } from './release-policy.mjs';

const scripts = resolve('packaging/npm');
const sha = '0123456789abcdef0123456789abcdef01234567';

function run(script, args, options = {}) {
  return execFileSync(process.execPath, [join(scripts, script), ...args], { encoding: 'utf8', ...options });
}

function failing(script, args) {
  return spawnSync(process.execPath, [join(scripts, script), ...args], { encoding: 'utf8' });
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function fixture() {
  return mkdtempSync(join(tmpdir(), 'palladin-release-script-'));
}

function metaManifest(overrides = {}) {
  return {
    name: '@palladin/agent',
    version: '1.2.3',
    description: 'fixture',
    private: true,
    license: 'Apache-2.0',
    repository: { type: 'git', url: 'https://example.test/source.git' },
    homepage: 'https://example.test',
    bugs: { url: 'https://example.test/issues' },
    files: ['dist/bin/', 'dist/runtime/', 'README.md', 'LICENSE', 'SECURITY.md'],
    workspaces: ['packages/*'],
    publishConfig: { access: 'public', provenance: true },
    type: 'module',
    bin: { palladin: './dist/bin/palladin.js' },
    scripts: { build: 'tsc', test: 'vitest run' },
    devDependencies: { typescript: '1.0.0' },
    engines: { node: '>=20.5.0' },
    optionalDependencies: Object.fromEntries(PLATFORM_PACKAGE_NAMES.map((name) => [name, '1.2.3'])),
    ...overrides,
  };
}

function createMetaSource(root, manifest = metaManifest()) {
  mkdirSync(join(root, 'dist/bin'), { recursive: true });
  mkdirSync(join(root, 'dist/runtime'), { recursive: true });
  writeFileSync(join(root, 'dist/bin/palladin.js'), 'fixture');
  writeFileSync(join(root, 'dist/runtime/native-dispatch.js'), 'fixture');
  for (const file of ['README.md', 'LICENSE', 'SECURITY.md']) writeFileSync(join(root, file), file);
  writeJson(join(root, 'package.json'), manifest);
}

test('stages only the publishable meta package and preserves the private source', () => {
  const root = fixture();
  try {
    const source = join(root, 'source');
    const output = join(root, 'stage');
    mkdirSync(source);
    createMetaSource(source);
    const before = readFileSync(join(source, 'package.json'), 'utf8');
    run('stage-meta-package.mjs', ['--source', source, '--output-dir', output, '--version', '1.2.3']);
    const staged = JSON.parse(readFileSync(join(output, 'package.json'), 'utf8'));
    assert.equal(staged.private, undefined);
    assert.equal(staged.scripts, undefined);
    assert.equal(staged.devDependencies, undefined);
    assert.deepEqual(staged.optionalDependencies, metaManifest().optionalDependencies);
    assert.equal(readFileSync(join(source, 'package.json'), 'utf8'), before);
    assert.deepEqual(readdirSync(output).sort(), ['LICENSE', 'README.md', 'SECURITY.md', 'dist', 'package.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('meta staging rejects lifecycle scripts, version ranges, and symlinked publish files', () => {
  const root = fixture();
  try {
    const lifecycle = join(root, 'lifecycle');
    mkdirSync(lifecycle);
    createMetaSource(lifecycle, metaManifest({ scripts: { install: 'steal-secrets' } }));
    let result = failing('stage-meta-package.mjs', ['--source', lifecycle, '--output-dir', join(root, 'out-1'), '--version', '1.2.3']);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /forbidden lifecycle script/);

    const ranged = join(root, 'ranged');
    mkdirSync(ranged);
    createMetaSource(ranged, metaManifest({
      optionalDependencies: { ...metaManifest().optionalDependencies, [PLATFORM_PACKAGE_NAMES[0]]: '^1.2.3' },
    }));
    result = failing('stage-meta-package.mjs', ['--source', ranged, '--output-dir', join(root, 'out-2'), '--version', '1.2.3']);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /exact version/);

    const linked = join(root, 'linked');
    mkdirSync(linked);
    createMetaSource(linked);
    rmSync(join(linked, 'SECURITY.md'));
    symlinkSync(join(linked, 'README.md'), join(linked, 'SECURITY.md'));
    result = failing('stage-meta-package.mjs', ['--source', linked, '--output-dir', join(root, 'out-3'), '--version', '1.2.3']);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /symbolic link/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('creates exactly nine inert bootstrap packages without mutating source files', () => {
  const root = fixture();
  try {
    const output = join(root, 'bootstrap');
    const sourceBefore = readFileSync('package.json', 'utf8');
    run('stage-bootstrap-packages.mjs', ['--output-dir', output]);
    assert.deepEqual(readdirSync(output).sort(), PUBLIC_PACKAGE_NAMES.map((name) => name.slice('@palladin/'.length)).sort());
    for (const name of PUBLIC_PACKAGE_NAMES) {
      const directory = join(output, name.slice('@palladin/'.length));
      assert.deepEqual(readdirSync(directory), ['package.json']);
      const manifest = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
      assert.equal(manifest.name, name);
      assert.equal(manifest.version, '0.0.0-bootstrap');
      for (const forbidden of ['private', 'bin', 'scripts', 'dependencies', 'optionalDependencies', 'devDependencies']) {
        assert.equal(manifest[forbidden], undefined);
      }
      assert.deepEqual(manifest.files, []);
    }
    assert.equal(readFileSync('package.json', 'utf8'), sourceBefore);
    const duplicate = failing('stage-bootstrap-packages.mjs', ['--output-dir', output]);
    assert.notEqual(duplicate.status, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('generates and verifies deterministic release metadata, then detects tampering', () => {
  const root = fixture();
  try {
    const artifact = join(root, 'agent-1.2.3.tgz');
    const sbom = join(root, 'release.spdx.json');
    const manifest = join(root, 'release-manifest.json');
    const checksums = join(root, 'SHA256SUMS');
    writeFileSync(artifact, 'signed artifact bytes');
    writeJson(sbom, { spdxVersion: 'SPDX-2.3', SPDXID: 'SPDXRef-DOCUMENT' });
    const args = ['--artifacts', root, '--version', '1.2.3', '--source-sha', sha, '--sbom', sbom, '--manifest', manifest, '--checksums', checksums];
    run('generate-release-manifest.mjs', args);
    run('verify-release-manifest.mjs', args);
    const release = JSON.parse(readFileSync(manifest, 'utf8'));
    assert.deepEqual(release, {
      schemaVersion: 1,
      version: '1.2.3',
      sourceSha: sha,
      artifacts: [{
        filename: 'agent-1.2.3.tgz',
        size: 21,
        sha256: createHash('sha256').update('signed artifact bytes').digest('hex'),
        sbom: {
          filename: 'release.spdx.json',
          sha256: createHash('sha256').update(readFileSync(sbom)).digest('hex'),
        },
      }],
    });
    writeFileSync(artifact, 'tampered');
    const tampered = failing('verify-release-manifest.mjs', args);
    assert.notEqual(tampered.status, 0);
    assert.match(tampered.stderr, /does not exactly match/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function tarHeader(path, size) {
  const header = Buffer.alloc(512);
  header.write(path, 0, 100, 'utf8');
  header.write('0000644\0', 100, 8, 'ascii');
  header.write('0000000\0', 108, 8, 'ascii');
  header.write('0000000\0', 116, 8, 'ascii');
  header.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii');
  header.write('00000000000\0', 136, 12, 'ascii');
  header.fill(32, 148, 156);
  header[156] = 48;
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return header;
}

function writePackageArchive(path, manifest) {
  const body = Buffer.from(JSON.stringify(manifest));
  const padding = Buffer.alloc(Math.ceil(body.length / 512) * 512 - body.length);
  writeFileSync(path, gzipSync(Buffer.concat([tarHeader('package/package.json', body.length), body, padding, Buffer.alloc(1024)])));
}

test('accepts only one exact, inert tarball for every supported platform package', () => {
  const root = fixture();
  try {
    for (const name of PLATFORM_PACKAGE_NAMES) {
      const filename = `${name.slice('@palladin/'.length)}-1.2.3.tgz`;
      writePackageArchive(join(root, filename), { name, version: '1.2.3' });
    }
    writeFileSync(join(root, 'palladin-runtime-setup-x64-1.2.3.zip'), 'signed ancillary installer');
    run('verify-platform-release-set.mjs', ['--directory', root, '--version', '1.2.3']);

    const first = PLATFORM_PACKAGE_NAMES[0];
    writePackageArchive(join(root, `${first.slice('@palladin/'.length)}-1.2.3.tgz`), {
      name: first,
      version: '1.2.3',
      scripts: { postinstall: 'steal-secrets' },
    });
    const lifecycle = failing('verify-platform-release-set.mjs', ['--directory', root, '--version', '1.2.3']);
    assert.notEqual(lifecycle.status, 0);
    assert.match(lifecycle.stderr, /forbidden lifecycle script/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('release workflows pin actions and isolate the one-time npm token exception', () => {
  const workflowDirectory = resolve('.github/workflows');
  const workflows = readdirSync(workflowDirectory)
    .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'));
  const directPublishes = [];
  const tokenConsumers = [];

  for (const workflow of workflows) {
    const contents = readFileSync(join(workflowDirectory, workflow), 'utf8');
    for (const match of contents.matchAll(/uses:\s+([^\s#]+)/g)) {
      const action = match[1];
      if (!action.startsWith('./')) {
        assert.match(action, /@[0-9a-f]{40}$/, `${workflow} contains an unpinned action: ${action}`);
      }
    }
    if (/\bnpm publish\b/.test(contents)) directPublishes.push(workflow);
    if (/NODE_AUTH_TOKEN|NPM_TOKEN/.test(contents)) tokenConsumers.push(workflow);
  }

  assert.deepEqual(directPublishes, ['npm-bootstrap.yml']);
  assert.deepEqual(tokenConsumers, ['npm-bootstrap.yml']);
  const platformRelease = readFileSync(join(workflowDirectory, 'release-platforms.yml'), 'utf8');
  const metaRelease = readFileSync(join(workflowDirectory, 'release-meta.yml'), 'utf8');
  const finalRelease = readFileSync(join(workflowDirectory, 'release-finalize.yml'), 'utf8');
  assert.doesNotMatch(platformRelease, /secrets:\s+inherit/);
  assert.match(platformRelease, /npm stage publish "\$package" --tag candidate/);
  assert.match(metaRelease, /npm stage publish "\$package" --tag latest/);
  for (const contents of [platformRelease, metaRelease, finalRelease]) {
    assert.match(contents, /github\.actor == 'patryk-roguszewski'/);
    assert.match(contents, /test "\$GITHUB_REF" = "refs\/tags\/\$RELEASE_TAG"/);
    assert.match(contents, /git merge-base --is-ancestor/);
  }
});
