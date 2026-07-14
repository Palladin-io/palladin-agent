import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

interface ContractManifest {
  syntheticOnly: boolean;
  consumers: string[];
  fixtures: string[];
}

interface RootPackage {
  optionalDependencies: Record<string, string>;
}

const read = (path: string): string => readFileSync(path, 'utf8').replace(/\r\n/g, '\n');

function filesUnder(root: string, suffixes: string[]): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) files.push(...filesUnder(path, suffixes));
    else if (suffixes.some((suffix) => path.endsWith(suffix))) files.push(path);
  }
  return files;
}

describe('cross-platform CI gates', () => {
  it('runs portable and native gates on every pull request, including stacked branches', () => {
    const portable = read('.github/workflows/test.yml');
    const native = read('.github/workflows/rust-runtime.yml');

    for (const workflow of [portable, native]) {
      expect(workflow).toContain('  pull_request:\n');
      expect(workflow).toContain('  merge_group:\n');
      expect(workflow).not.toContain('pull_request_target');
      expect(workflow).not.toContain('    branches:');
      expect(workflow).not.toContain('    paths:');
      expect(workflow).toContain('permissions:\n  contents: read');
    }

    expect(portable).toContain('name: CI Gate');
    expect(portable).toContain('needs: [test, minimum-npm-platform-selection, contracts]');
    expect(native).toContain('name: Native Platform Gate');
    expect(native).toContain('needs: [apple, windows, linux]');
  });

  it('builds and tests every declared npm OS, CPU, and libc target natively', () => {
    const native = read('.github/workflows/rust-runtime.yml');
    const rootPackage = JSON.parse(read('package.json')) as RootPackage;
    const supported = [
      { packageName: '@palladin/runtime-darwin-arm64', target: 'aarch64-apple-darwin', runner: 'macos-15' },
      { packageName: '@palladin/runtime-darwin-x64', target: 'x86_64-apple-darwin', runner: 'macos-15-intel' },
      { packageName: '@palladin/runtime-win32-arm64', target: 'aarch64-pc-windows-msvc', runner: 'windows-11-arm' },
      { packageName: '@palladin/runtime-win32-x64', target: 'x86_64-pc-windows-msvc', runner: 'windows-2025' },
      { packageName: '@palladin/runtime-linux-arm64-gnu', target: 'aarch64-unknown-linux-gnu', runner: 'ubuntu-24.04-arm' },
      { packageName: '@palladin/runtime-linux-x64-gnu', target: 'x86_64-unknown-linux-gnu', runner: 'ubuntu-24.04' },
      { packageName: '@palladin/runtime-linux-arm64-musl', target: 'aarch64-unknown-linux-musl', runner: 'ubuntu-24.04-arm' },
      { packageName: '@palladin/runtime-linux-x64-musl', target: 'x86_64-unknown-linux-musl', runner: 'ubuntu-24.04' },
    ];

    expect(Object.keys(rootPackage.optionalDependencies).sort()).toEqual(
      supported.map(({ packageName }) => packageName).sort(),
    );
    for (const { packageName, target, runner } of supported) {
      expect(native, target).toContain(target);
      expect(native, runner).toContain(`runner: ${runner}`);
      const sourceManifest = JSON.parse(read(`packages/${packageName.replace('@palladin/', '')}/package.json`)) as { name: string };
      expect(sourceManifest.name).toBe(packageName);
    }
    expect(native).toContain('cargo test --workspace --locked --target ${{ matrix.target }}');
    expect(native).toContain('cargo test --workspace --locked --target ${{ matrix.gnu_target }}');
    expect(native).toContain('cargo test --workspace --locked --target ${{ matrix.musl_target }}');
    expect(native).toContain('cargo clippy --workspace --all-targets --locked --target ${{ matrix.target }}');
    expect(native).toContain('cargo clippy --workspace --all-targets --locked --target ${{ matrix.gnu_target }}');
    expect(native).toContain('cargo clippy --workspace --all-targets --locked --target ${{ matrix.musl_target }}');
    expect(native).toContain('--exclude palladin-linux-broker --exclude palladin-linux-executor');
    expect(native).toContain('--exclude palladin-windows-broker --exclude palladin-windows-executor');
    expect(native).toContain('runner: macos-15-intel');
    expect(native).toContain('runner: windows-11-arm');
    expect(native).toContain('runner: ubuntu-24.04-arm');
    expect(native).toContain('Build and run the native musl npm package on Alpine');
  });

  it('uses all three semantic contract consumers and verifies frozen digests', () => {
    const workflow = read('.github/workflows/test.yml');
    const manifest = JSON.parse(read('runtime/contracts/v1/source-manifest.json')) as ContractManifest;

    expect(manifest.syntheticOnly).toBe(true);
    expect(manifest.consumers).toEqual(['typescript', 'rust', 'dotnet']);
    expect(manifest.fixtures.length).toBeGreaterThan(0);
    expect(workflow).toContain('sha256sum --check SOURCE.sha256');
    expect(workflow).toContain('dotnet restore --locked-mode');
    expect(workflow).toContain('Palladin.ContractGate.csproj');
    expect(workflow).toContain('cargo fmt --all -- --check');
    expect(workflow).toContain('cargo clippy --workspace --all-targets --locked -- -D warnings');
    expect(workflow).toContain('cargo test --workspace --locked');
    expect(workflow).toContain('vitest run tests/contracts');
  });

  it('keeps CI logs and artifacts free of secret material and private fixtures', () => {
    const workflows = filesUnder('.github/workflows', ['.yml', '.yaml'])
      .map(read)
      .join('\n');
    const typescriptTests = filesUnder('tests', ['.ts'])
      .filter((path) => path !== 'tests/runtime/ci-matrix.test.ts');
    const rustSources = filesUnder('runtime/crates', ['.rs']);
    const packagingSources = filesUnder('packaging', ['.sh', '.ps1', '.psm1', '.mjs']);

    for (const forbidden of [
      'printenv',
      'set -x',
      'toJSON(secrets)',
      'ACTIONS_STEP_DEBUG',
      'runtime/contracts/v1/**',
    ]) {
      expect(workflows, forbidden).not.toContain(forbidden);
    }

    const unsafeTypeScript = [
      /expect\([^\n;]*\.password\b[^\n;]*\)\.(?:toBe|toEqual|toContain|toMatch|toMatchObject|toHaveLength)/,
      /expect\([^\n;]*(?:X-Api-Key|FAKE_KEY|TOTP_SECRET|page\.filled|result\.stdout|secretValues)[^\n;]*\)\.(?:toBe|toEqual|toContain|toMatch|toMatchObject|toHaveLength)/,
      /expect\([^\n;]*\.privateKey[^\n;]*\)\.toHaveLength/,
      /expect\((?:fetchSpy|getProfile|fetch)\)\.not\.toHaveBeenCalled/,
      /expect\([^\n;]*\)\.not\.toHaveProperty\(['"](?:stdout|stderr)['"]\)/,
    ];
    for (const path of typescriptTests) {
      const source = read(path);
      for (const pattern of unsafeTypeScript) {
        expect(!pattern.test(source), `${path}: unsafe sensitive Vitest matcher`).toBe(true);
      }
    }

    const unsafeRust = [
      /assert_(?:eq|ne)!\([^;]{0,300}expose_(?:secret|for_authorized_operation)/,
      /assert!\(\s*!?[^,;]{0,180}contains\("[^"]*(?:secret|password|api[_-]?key|token)[^"]*"\)\s*\);/i,
      /(?:println|eprintln|dbg)!\([^;]{0,300}expose_(?:secret|for_authorized_operation)/,
    ];
    for (const path of rustSources) {
      const source = read(path);
      for (const pattern of unsafeRust) {
        expect(!pattern.test(source), `${path}: unsafe sensitive Rust output`).toBe(true);
      }
    }

    for (const path of packagingSources) {
      const source = read(path);
      expect(!/(?:set\s+-x|\bprintenv\b|toJSON\(secrets\))/i.test(source), `${path}: unsafe CI logging`).toBe(true);
    }
  });

  it('keeps secret-bearing signing jobs owner-dispatched and outside pull requests', () => {
    for (const path of [
      '.github/workflows/macos-signed-runtime.yml',
      '.github/workflows/windows-signed-runtime.yml',
    ]) {
      const workflow = read(path);
      expect(workflow).toContain('  workflow_dispatch:');
      expect(workflow).not.toContain('pull_request:');
      expect(workflow).not.toContain('pull_request_target:');
      expect(workflow).toContain("if: github.actor == 'patryk-roguszewski'");
      expect(workflow).toContain('persist-credentials: false');
    }

    const macos = read('.github/workflows/macos-signed-runtime.yml');
    expect(macos).toContain('name: macOS Signed Release Gate');
    expect(macos).toContain('runner: macos-15-intel');
    expect(macos).toContain('platform: macos/x86_64');
    const windows = read('.github/workflows/windows-signed-runtime.yml');
    expect(windows).toContain('name: Windows Signed Release Gate');
    expect(windows).toContain('runner: windows-11-arm');
    expect(windows).toContain('Signed install smoke - ${{ matrix.architecture }}');

    const fix = read('.github/workflows/fix-pr.yml');
    expect(fix).toContain('ref: ${{ steps.pr.outputs.sha }}');
    expect(fix).toContain('persist-credentials: false');
    expect(fix).toContain('npm ci --ignore-scripts --workspaces=false');
    expect(fix).toContain('push --force-with-lease="refs/heads/${HEAD_BRANCH}:${ORIGINAL_SHA}"');
    const claudeFixStep = fix
      .split('      - name: Run Claude Code fix\n')[1]
      ?.split('\n      - name: Validate the fix without credentials')[0];
    expect(claudeFixStep).toBeDefined();
    expect(claudeFixStep).not.toContain('GH_TOKEN:');
    expect(claudeFixStep).not.toContain('npm ');
    expect(claudeFixStep).not.toContain('Bash(gh ');
    expect(claudeFixStep).not.toContain('Bash(git push:');
  });
});
