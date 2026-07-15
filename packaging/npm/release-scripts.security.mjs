import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import {
  canonicalizeVersionPolicyEnvelope,
  canonicalizeVersionPolicyPayload,
  parseAndVerifyVersionPolicy,
} from '../../dist/runtime/version-policy.js';
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

function signedPolicyFixture() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const issued = new Date(Math.floor(Date.now() / 1000) * 1000);
  const payload = {
    artifacts: [{
      executableSha256: '11'.repeat(32),
      packageName: '@palladin/runtime-linux-x64-gnu',
      sourceSha: sha,
      version: '1.2.2',
      workerExecutableSha256: '22'.repeat(32),
    }],
    blockedVersions: [],
    expiresAt: new Date(issued.getTime() + 24 * 60 * 60 * 1000).toISOString().replace('.000Z', 'Z'),
    issuedAt: issued.toISOString().replace('.000Z', 'Z'),
    minimumVersion: '1.2.2',
    recommendedVersion: '1.2.2',
    schemaVersion: 1,
    sequence: 7,
    source: 'https://releases.palladin.io/agent/version-policy.json',
  };
  const signature = sign(
    null,
    Buffer.from(canonicalizeVersionPolicyPayload(payload)),
    privateKey,
  ).toString('base64');
  const envelope = canonicalizeVersionPolicyEnvelope({ signed: payload, signature });
  return {
    envelope,
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64'),
  };
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
      writePackageArchive(join(root, filename), {
        name,
        version: '1.2.3',
        ...(name.includes('/runtime-win32-') ? {
          palladinRuntime: { workerExecutableSha256: '33'.repeat(32) },
        } : {}),
      });
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
    assert.match(contents, /group: palladin-npm-release/);
  }
});

test('release finalization requires the exact fresh adversarial report before publication', () => {
  const workflow = readFileSync(resolve('.github/workflows/release-finalize.yml'), 'utf8');
  assert.match(workflow, /if: github\.actor == 'patryk-roguszewski'/);
  assert.match(workflow, /needs: \[authorize, compatibility, smoke-native, smoke-musl\]/);
  assert.ok(workflow.includes('[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]]'));
  assert.match(workflow, /test -f "\$assets\/adversarial-report\.json"/);
  assert.match(workflow, /test -f "\$assets\/adversarial-report\.md"/);
  assert.match(workflow, /test -f "\$assets\/adversarial-approval\.json"/);
  assert.match(workflow, /--directory "\$platform_packages" --version "\$VERSION"/);
  assert.match(workflow, /expected-release-assets\.txt/);
  assert.match(workflow, /actual-release-assets\.txt/);
  assert.match(workflow, /cmp --silent "\$RUNNER_TEMP\/expected-release-assets\.txt"/);
  assert.match(workflow, /node security\/adversarial\/report\.mjs validate/);
  assert.match(workflow, /--source-sha "\$SOURCE_SHA"/);
  assert.match(workflow, /--json "\$assets\/adversarial-report\.json"/);
  assert.match(workflow, /--markdown "\$assets\/adversarial-report\.md"/);
  assert.match(workflow, /node security\/adversarial\/verify-release-artifacts\.mjs/);
  assert.match(workflow, /--platform-manifest "\$assets\/release-manifest\.json"/);
  assert.match(workflow, /--agent-manifest "\$assets\/release-manifest-agent\.json"/);
  assert.match(workflow, /node security\/adversarial\/operator-approval\.mjs verify/);
  assert.match(workflow, /--approval "\$assets\/adversarial-approval\.json"/);
  assert.match(workflow, /adversarial-report\.json\|adversarial-report\.md\|adversarial-approval\.json\) continue/);
  assert.doesNotMatch(workflow, /report\.mjs validate[^]*\|\| true/);
  assert.ok(
    workflow.indexOf('node security/adversarial/report.mjs validate')
      < workflow.indexOf('gh release edit "${{ inputs.release_tag }}"'),
  );
});

test('meta-package staging is blocked by the exact adversarial release report', () => {
  const workflow = readFileSync(resolve('.github/workflows/release-meta.yml'), 'utf8');
  const reportValidations = [...workflow.matchAll(/node security\/adversarial\/report\.mjs validate/g)];
  const artifactValidations = [
    ...workflow.matchAll(/node security\/adversarial\/verify-release-artifacts\.mjs/g),
  ];
  const stageOffset = workflow.indexOf('npm stage publish "$package" --tag latest');

  assert.equal(reportValidations.length, 3);
  assert.equal(artifactValidations.length, 3);
  assert.ok(stageOffset > 0);
  assert.ok(reportValidations.every((match) => match.index < stageOffset));
  assert.ok(artifactValidations.every((match) => match.index < stageOffset));
  assert.match(workflow, /test -f "\$assets\/adversarial-report\.json"/);
  assert.match(workflow, /test -f "\$assets\/adversarial-report\.md"/);
  assert.match(workflow, /name: Revalidate the adversarial release gate before staging/);
  assert.match(workflow, /--platform-manifest "\$gate\/release-manifest\.json"/);
  assert.match(workflow, /name: KMS-sign the owner-approved adversarial evidence/);
  assert.match(workflow, /gcloud kms asymmetric-sign/);
  assert.match(workflow, /operator-approval\.mjs assemble/);
  assert.match(workflow, /operator-approval\.mjs verify/);
  assert.match(workflow, /--approval "\$gate\/adversarial-approval\.json"/);
  assert.match(workflow, /needs: \[authorize, compatibility, smoke-native, smoke-musl, publish-policy, approve-adversarial\]/);
  assert.doesNotMatch(workflow, /adversarial\/report\.mjs validate[^]*\|\| true/);
});

test('signed version policy release is owner-only, KMS-backed, and published after smoke', () => {
  const workflowDirectory = resolve('.github/workflows');
  const platform = readFileSync(join(workflowDirectory, 'release-platforms.yml'), 'utf8');
  const meta = readFileSync(join(workflowDirectory, 'release-meta.yml'), 'utf8');
  const maintenance = readFileSync(
    join(workflowDirectory, 'version-policy-maintenance.yml'),
    'utf8',
  );
  const verify = readFileSync(join(workflowDirectory, 'version-policy-verify.yml'), 'utf8');

  for (const workflow of [platform, meta, maintenance]) {
    assert.match(workflow, /environment: version-policy-signing/);
    assert.match(workflow, /google-github-actions\/auth@[0-9a-f]{40}/);
    assert.match(workflow, /google-github-actions\/setup-gcloud@[0-9a-f]{40}/);
    assert.match(workflow, /version: 561\.0\.0/);
    assert.match(workflow, /PALLADIN_VERSION_POLICY_PUBLIC_KEY/);
    assert.doesNotMatch(workflow, /credentials_json|PALLADIN_VERSION_POLICY_PRIVATE|NPM_TOKEN/);
  }

  assert.match(platform, /PALLADIN_PRODUCTION_BUILD: "1"/);
  assert.match(platform, /verify-kms-public-key\.mjs/);
  assert.match(meta, /bootstrap_policy:/);
  assert.match(meta, /npm install --prefix "\$root" --force --ignore-scripts --save-exact/);
  assert.match(meta, /npm audit signatures --prefix "\$root"/);
  assert.match(meta, /gh attestation verify "\$asset"/);
  assert.match(meta, /cmp --silent "\$asset" "\$registry_tarball"/);
  assert.match(meta, /verify-release-policy --policy/);
  assert.ok(meta.indexOf('verify-release-policy --policy') < meta.indexOf('name: Publish the policy only after all native smokes pass'));
  assert.match(meta, /Exercise the live dynamic policy before the meta-package can be staged/);
  assert.doesNotMatch(meta, /tar --extract|curl[^\n]*\|\|/);
  assert.match(meta, /needs: \[authorize, smoke-native, smoke-musl\]/);
  assert.match(meta, /name: Publish the policy only after all native smokes pass/);
  assert.match(meta, /group: palladin-npm-release/);
  assert.match(maintenance, /github\.actor == 'patryk-roguszewski'/);
  assert.match(maintenance, /github\.ref == 'refs\/heads\/main'/);
  assert.match(maintenance, /inputs\.confirmation == 'SIGN POLICY'/);
  assert.match(maintenance, /group: palladin-npm-release/);
  for (const workflow of [meta, maintenance]) {
    assert.match(workflow, /--if-generation-match=0/);
    assert.match(workflow, /version-policy\/\$object/);
    assert.match(workflow, /--if-generation-match="\$(?:OBSERVED_GENERATION|observed_generation)"/);
  }
  assert.doesNotMatch(maintenance, /npm deprecate|npm dist-tag add/);
  assert.match(verify, /schedule:/);
  assert.doesNotMatch(verify, /claude|anthropic|id-token: write/);
});

test('signed policy object names are immutable and incident latest moves only the meta-package', () => {
  const root = fixture();
  try {
    const { envelope, publicKey } = signedPolicyFixture();
    const current = join(root, 'current.json');
    writeFileSync(current, envelope);
    const digest = createHash('sha256').update(envelope).digest('hex');
    assert.equal(run('version-policy-object-name.mjs', [
      '--bundle', current,
      '--public-key', publicKey,
    ]), `7-${digest}.json`);

    const output = join(root, 'incident');
    run('create-version-policy-incident-plan.mjs', [
      '--current', current,
      '--block-version', '1.2.3',
      '--safe-version', '1.2.2',
      '--output-dir', output,
      '--public-key', publicKey,
      '--issued-at', new Date(Math.floor(Date.now() / 1000) * 1000)
        .toISOString().replace('.000Z', 'Z'),
    ]);
    const plan = readFileSync(join(output, 'npm-incident-plan.txt'), 'utf8');
    assert.match(plan, /npm deprecate '@palladin\/agent'@'1\.2\.3'/);
    assert.match(plan, /npm deprecate '@palladin\/runtime-linux-x64-gnu'@'1\.2\.3'/);
    assert.equal((plan.match(/npm dist-tag add/g) ?? []).length, 1);
    assert.match(plan, /npm dist-tag add '@palladin\/agent'@'1\.2\.2' latest/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('CI policy fixture signs exact staged Linux bytes with an ephemeral matching key', () => {
  const root = fixture();
  try {
    const packages = ['@palladin/runtime-linux-x64-gnu', '@palladin/runtime-linux-x64-musl'];
    const packageRoots = packages.map((name) => {
      const packageRoot = join(root, name.split('/').at(-1));
      mkdirSync(join(packageRoot, 'bin'), { recursive: true });
      writeJson(join(packageRoot, 'package.json'), { name, version: '1.2.3' });
      writeFileSync(join(packageRoot, 'bin/palladin-linux-client'), `client: ${name}`);
      writeFileSync(join(packageRoot, 'bin/palladin-worker'), `worker: ${name}`);
      return packageRoot;
    });
    const bundle = join(root, 'policy.json');
    const privateKey = join(root, 'policy-private.pem');
    const publicKey = join(root, 'policy.pub');
    run('generate-version-policy-ci-key.mjs', [
      '--output-private-key', privateKey,
      '--output-public-key', publicKey,
    ]);
    run('generate-version-policy-ci-fixture.mjs', [
      '--package-root', packageRoots[0],
      '--package-root', packageRoots[1],
      '--version', '1.2.3',
      '--source-sha', sha,
      '--private-key', privateKey,
      '--public-key', publicKey,
      '--output-bundle', bundle,
    ]);
    rmSync(privateKey);
    const policy = parseAndVerifyVersionPolicy(readFileSync(bundle), {
      publicKeyBase64: readFileSync(publicKey, 'utf8'),
      source: 'https://releases.palladin.io/agent/version-policy.json',
    }).signed;
    assert.deepEqual(policy.artifacts.map((artifact) => artifact.packageName), packages);
    for (const artifact of policy.artifacts) {
      const packageRoot = packageRoots[packages.indexOf(artifact.packageName)];
      assert.equal(
        artifact.executableSha256,
        createHash('sha256').update(readFileSync(join(packageRoot, 'bin/palladin-linux-client')))
          .digest('hex'),
      );
      assert.equal(
        artifact.workerExecutableSha256,
        createHash('sha256').update(readFileSync(join(packageRoot, 'bin/palladin-worker')))
          .digest('hex'),
      );
    }
    assert.deepEqual(readdirSync(root).sort(), [
      'policy.json', 'policy.pub', 'runtime-linux-x64-gnu', 'runtime-linux-x64-musl',
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('configured policy constants stay typed as strings for production compilation', () => {
  const root = fixture();
  try {
    const { envelope, publicKey } = signedPolicyFixture();
    const bundle = join(root, 'policy.json');
    mkdirSync(join(root, 'src/runtime'), { recursive: true });
    writeFileSync(bundle, envelope);
    run('configure-version-policy-build.mjs', [
      '--public-key', publicKey,
      '--source-sha', sha,
      '--bundle', bundle,
    ], { cwd: root });
    const generated = readFileSync(join(root, 'src/runtime/version-policy-build.ts'), 'utf8');
    for (const name of [
      'VERSION_POLICY_SOURCE', 'VERSION_POLICY_PUBLIC_KEY_BASE64',
      'RUNTIME_SOURCE_SHA', 'VERSION_POLICY_BUNDLE_BASE64',
    ]) {
      assert.match(generated, new RegExp(`export const ${name}: string =`));
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('release policy generator binds all exact executables and rejects a symlink', () => {
  const root = fixture();
  try {
    const policyKeys = generateKeyPairSync('ed25519');
    const policyPublicKey = policyKeys.publicKey.export({ format: 'der', type: 'spki' })
      .subarray(-32).toString('base64');
    const modules = join(root, 'node_modules');
    const current = join(root, 'current.json');
    const output = join(root, 'payload.json');
    writeFileSync(current, '');
    const executables = new Map([
      ['@palladin/runtime-darwin-arm64', 'PalladinRuntime.app/Contents/MacOS/palladin'],
      ['@palladin/runtime-darwin-x64', 'PalladinRuntime.app/Contents/MacOS/palladin'],
      ['@palladin/runtime-linux-arm64-gnu', 'bin/palladin-linux-client'],
      ['@palladin/runtime-linux-arm64-musl', 'bin/palladin-linux-client'],
      ['@palladin/runtime-linux-x64-gnu', 'bin/palladin-linux-client'],
      ['@palladin/runtime-linux-x64-musl', 'bin/palladin-linux-client'],
      ['@palladin/runtime-win32-arm64', 'bin/palladin-client.exe'],
      ['@palladin/runtime-win32-x64', 'bin/palladin-client.exe'],
    ]);
    for (const [name, executable] of executables) {
      const packageRoot = join(modules, ...name.split('/'));
      mkdirSync(join(packageRoot, executable, '..'), { recursive: true });
      writeJson(join(packageRoot, 'package.json'), {
        name,
        version: '1.2.3',
        ...(name.includes('/runtime-win32-') ? {
          palladinRuntime: { workerExecutableSha256: '33'.repeat(32) },
        } : {}),
      });
      writeFileSync(join(packageRoot, executable), `signed fixture: ${name}`);
      if (name.includes('/runtime-linux-')) {
        writeFileSync(join(packageRoot, 'bin/palladin-worker'), `signed worker fixture: ${name}`);
      }
    }
    const args = [
      '--node-modules', modules,
      '--version', '1.2.3',
      '--source-sha', sha,
      '--current', current,
      '--public-key', policyPublicKey,
      '--issued-at', '2026-07-14T12:00:00Z',
      '--windows-publisher', 'CN=Palladin Test',
      '--windows-thumbprint', 'A'.repeat(40),
      '--output', output,
    ];
    run('generate-version-policy-release.mjs', args);
    const payload = JSON.parse(readFileSync(output, 'utf8'));
    assert.equal(payload.sequence, 1);
    assert.equal(payload.minimumVersion, '1.2.3');
    assert.equal(payload.recommendedVersion, '1.2.3');
    assert.equal(payload.expiresAt, '2026-08-13T12:00:00Z');
    assert.equal(payload.artifacts.length, 8);
    assert.ok(payload.artifacts.every((artifact) => /^[0-9a-f]{64}$/.test(
      artifact.workerExecutableSha256,
    )));

    const currentSignature = sign(
      null,
      Buffer.from(canonicalizeVersionPolicyPayload(payload)),
      policyKeys.privateKey,
    ).toString('base64');
    writeFileSync(current, canonicalizeVersionPolicyEnvelope({
      signed: payload,
      signature: currentSignature,
    }));
    const retryOutput = join(root, 'retry-payload.json');
    const retryArgs = [...args];
    retryArgs[retryArgs.indexOf('--issued-at') + 1] = '2026-07-15T12:00:00Z';
    retryArgs[retryArgs.indexOf('--output') + 1] = retryOutput;
    run('generate-version-policy-release.mjs', retryArgs);
    assert.deepEqual(JSON.parse(readFileSync(retryOutput, 'utf8')), payload);

    const linked = join(
      modules,
      '@palladin/runtime-linux-x64-gnu/bin/palladin-linux-client',
    );
    unlinkSync(linked);
    symlinkSync(join(modules, '@palladin/runtime-linux-x64-musl/bin/palladin-linux-client'), linked);
    const rejected = failing('generate-version-policy-release.mjs', args);
    assert.notEqual(rejected.status, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
