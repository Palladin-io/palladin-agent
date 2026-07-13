import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
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
  publishConfig?: { access?: string; provenance?: boolean };
}

function manifest(path: string): PackageManifest {
  return JSON.parse(readFileSync(resolve(path), 'utf8')) as PackageManifest;
}

describe('public npm package boundary', () => {
  it('publishes only the native dispatcher and an exact platform dependency', () => {
    const root = manifest('package.json');
    expect(root.files).toContain('dist/bin/');
    expect(root.files).toContain('dist/runtime/');
    expect(root.files).not.toContain('dist/');
    expect(root.dependencies).toBeUndefined();
    expect(root.optionalDependencies).toEqual({
      '@palladin/runtime-darwin-universal': root.version,
      '@palladin/runtime-win32-arm64': root.version,
      '@palladin/runtime-win32-x64': root.version,
    });
    for (const lifecycle of ['preinstall', 'install', 'postinstall', 'prepare']) {
      expect(root.scripts?.[lifecycle]).toBeUndefined();
    }
  });

  it('keeps root development installs cross-platform while platform packages stay OS-scoped', () => {
    expect(readFileSync('.npmrc', 'utf8').trim()).toBe('workspaces=false');
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
      'package.json',
    ]);
  });

  it('keeps the development workspace private and platform-neutral', () => {
    const runtime = manifest('packages/runtime-darwin-universal/package.json');
    expect(runtime.name).toBe('@palladin/runtime-darwin-universal');
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
});
