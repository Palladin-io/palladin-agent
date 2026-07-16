import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

interface PackageManifest {
  name: string;
  version: string;
  private?: boolean;
  files?: string[];
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  os?: string[];
  cpu?: string[];
  libc?: string[];
  publishConfig?: { access?: string; provenance?: boolean };
  engines?: { node?: string; npm?: string };
  palladinRuntime?: { workerExecutableSha256: string };
}

function manifest(path: string): PackageManifest {
  return JSON.parse(readFileSync(resolve(path), 'utf8')) as PackageManifest;
}

describe('public npm package boundary', () => {
  it('publishes only the native dispatcher and an exact platform dependency', () => {
    const root = manifest('package.json');
    const dispatcher = readFileSync('src/runtime/native-dispatch.ts', 'utf8');
    expect(root.files).toContain('dist/bin/');
    expect(root.files).toContain('dist/runtime/');
    expect(root.files).not.toContain('dist/');
    expect(root.dependencies).toBeUndefined();
    expect(root.engines).toEqual({ node: '>=20.5.0', npm: '>=9.7.1' });
    expect(dispatcher).toContain(`const NATIVE_RUNTIME_VERSION = '${root.version}'`);
    expect(root.optionalDependencies).toEqual({
      '@palladin/runtime-darwin-arm64': root.version,
      '@palladin/runtime-darwin-x64': root.version,
      '@palladin/runtime-linux-arm64-gnu': root.version,
      '@palladin/runtime-linux-arm64-musl': root.version,
      '@palladin/runtime-linux-x64-gnu': root.version,
      '@palladin/runtime-linux-x64-musl': root.version,
      '@palladin/runtime-win32-arm64': root.version,
      '@palladin/runtime-win32-x64': root.version,
    });
    for (const lifecycle of [
      'preinstall', 'install', 'postinstall', 'preprepare', 'prepare', 'postprepare',
    ]) {
      expect(root.scripts?.[lifecycle]).toBeUndefined();
    }
  });

  it('keeps root development installs cross-platform while platform packages stay OS-scoped', () => {
    expect(readFileSync('.npmrc', 'utf8').trim()).toBe('workspaces=false');
  });

  it('documents the supported global, local, exact-version npx, omit, and offline policies', () => {
    const readme = readFileSync('README.md', 'utf8');
    expect(readme).toContain('npm install --global @palladin/agent@<exact-version>');
    expect(readme).toContain('npm exec -- palladin doctor');
    expect(readme).toContain('npx --yes @palladin/agent@<exact-version> -- doctor');
    expect(readme).toContain('`--omit=optional` is unsupported');
    expect(readme).toContain('npm cache or proxy');
  });

  it('excludes every legacy TypeScript implementation from the launcher tarball', () => {
    const npmCli = process.env.npm_execpath;
    if (!npmCli) throw new Error('npm_execpath is unavailable');
    const output = execFileSync(process.execPath, [npmCli, 'pack', '--dry-run', '--json'], {
      encoding: 'utf8',
      env: { ...process.env, npm_config_loglevel: 'silent' },
    });
    const packs = JSON.parse(output) as Array<{ files: Array<{ path: string }> }>;
    const paths = packs[0]?.files.map((file) => file.path).sort();
    expect(paths).toEqual([
      'LICENSE',
      'README.md',
      'SECURITY.md',
      'dist/bin/palladin.d.ts',
      'dist/bin/palladin.d.ts.map',
      'dist/bin/palladin.js',
      'dist/bin/palladin.js.map',
      'dist/runtime/native-dispatch.d.ts',
      'dist/runtime/native-dispatch.d.ts.map',
      'dist/runtime/native-dispatch.js',
      'dist/runtime/native-dispatch.js.map',
      'dist/runtime/version-policy-build.d.ts',
      'dist/runtime/version-policy-build.d.ts.map',
      'dist/runtime/version-policy-build.js',
      'dist/runtime/version-policy-build.js.map',
      'dist/runtime/version-policy.d.ts',
      'dist/runtime/version-policy.d.ts.map',
      'dist/runtime/version-policy.js',
      'dist/runtime/version-policy.js.map',
      'dist/runtime/windows-runtime-cache.d.ts',
      'dist/runtime/windows-runtime-cache.d.ts.map',
      'dist/runtime/windows-runtime-cache.js',
      'dist/runtime/windows-runtime-cache.js.map',
      'package.json',
    ]);
  }, 30_000);

  it.each(['arm64', 'x64'])('keeps the darwin/%s development workspace private and platform-neutral', (architecture) => {
    const runtime = manifest(`packages/runtime-darwin-${architecture}/package.json`);
    expect(runtime.name).toBe(`@palladin/runtime-darwin-${architecture}`);
    expect(runtime.private).toBe(true);
    expect(runtime.os).toBeUndefined();
    expect(runtime.cpu).toBeUndefined();
    expect(runtime.files).toContain('PalladinRuntime.app/');
    expect(runtime.scripts).toBeUndefined();
    expect(runtime.dependencies).toBeUndefined();
    expect(runtime.optionalDependencies).toBeUndefined();
    expect(runtime.publishConfig).toEqual({ access: 'public', provenance: true });
  });

  it.each([
    ['x64', '@palladin/runtime-win32-x64'],
    ['arm64', '@palladin/runtime-win32-arm64'],
  ])('keeps the Windows %s workspace private, inert, and architecture-neutral', (architecture, name) => {
    const runtime = manifest(`packages/runtime-win32-${architecture}/package.json`);
    expect(runtime.name).toBe(name);
    expect(runtime.private).toBe(true);
    expect(runtime.os).toBeUndefined();
    expect(runtime.cpu).toBeUndefined();
    expect(runtime.files).toEqual(['bin/palladin-client.exe', 'README.md', 'LICENSE']);
    expect(runtime.scripts).toBeUndefined();
    expect(runtime.dependencies).toBeUndefined();
    expect(runtime.optionalDependencies).toBeUndefined();
    expect(runtime.publishConfig).toEqual({ access: 'public', provenance: true });
  });

  it.each([
    ['x64', 'gnu', '@palladin/runtime-linux-x64-gnu'],
    ['arm64', 'gnu', '@palladin/runtime-linux-arm64-gnu'],
    ['x64', 'musl', '@palladin/runtime-linux-x64-musl'],
    ['arm64', 'musl', '@palladin/runtime-linux-arm64-musl'],
  ])('keeps the Linux %s/%s workspace private and inert', (architecture, libc, name) => {
    const runtime = manifest(`packages/runtime-linux-${architecture}-${libc}/package.json`);
    expect(runtime.name).toBe(name);
    expect(runtime.private).toBe(true);
    expect(runtime.os).toBeUndefined();
    expect(runtime.cpu).toBeUndefined();
    expect(runtime.files).toEqual([
      'bin/palladin-linux-client',
      'bin/palladin-worker',
      'README.md',
    ]);
    expect(runtime.scripts).toBeUndefined();
    expect(runtime.dependencies).toBeUndefined();
    expect(runtime.optionalDependencies).toBeUndefined();
    expect(runtime.publishConfig).toEqual({ access: 'public', provenance: true });
  });

  it.each([
    ['darwin', 'arm64', 'none', '@palladin/runtime-darwin-arm64', ['PalladinRuntime.app/', 'README.md', 'LICENSE']],
    ['darwin', 'x64', 'none', '@palladin/runtime-darwin-x64', ['PalladinRuntime.app/', 'README.md', 'LICENSE']],
    ['win32', 'arm64', 'none', '@palladin/runtime-win32-arm64', ['bin/palladin-client.exe', 'README.md', 'LICENSE']],
    ['win32', 'x64', 'none', '@palladin/runtime-win32-x64', ['bin/palladin-client.exe', 'README.md', 'LICENSE']],
    ['linux', 'arm64', 'glibc', '@palladin/runtime-linux-arm64-gnu', ['bin/palladin-linux-client', 'bin/palladin-worker', 'README.md', 'LICENSE']],
    ['linux', 'arm64', 'musl', '@palladin/runtime-linux-arm64-musl', ['bin/palladin-linux-client', 'bin/palladin-worker', 'README.md', 'LICENSE']],
    ['linux', 'x64', 'glibc', '@palladin/runtime-linux-x64-gnu', ['bin/palladin-linux-client', 'bin/palladin-worker', 'README.md', 'LICENSE']],
    ['linux', 'x64', 'musl', '@palladin/runtime-linux-x64-musl', ['bin/palladin-linux-client', 'bin/palladin-worker', 'README.md', 'LICENSE']],
  ])('verifies the staged public %s/%s/%s manifest', (os, cpu, libc, name, files) => {
    const temporary = mkdtempSync(join(tmpdir(), 'palladin-platform-manifest-'));
    try {
      const packageDirectory = join(temporary, 'package');
      mkdirSync(packageDirectory);
      const root = manifest('package.json');
      writeFileSync(join(packageDirectory, 'package.json'), `${JSON.stringify({
        name,
        version: root.version,
        license: 'Apache-2.0',
        files,
        os: [os],
        cpu: [cpu],
        ...(libc === 'none' ? {} : { libc: [libc] }),
        ...(os === 'win32' ? {
          palladinRuntime: { workerExecutableSha256: 'ab'.repeat(32) },
        } : {}),
        publishConfig: { access: 'public', provenance: true },
      }, null, 2)}\n`);
      execFileSync(process.execPath, [
        'packaging/npm/verify-platform-package.mjs',
        '--package', packageDirectory,
        '--name', name,
        '--os', os,
        '--cpu', cpu,
        '--libc', libc,
        '--files', JSON.stringify(files),
      ]);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
});
