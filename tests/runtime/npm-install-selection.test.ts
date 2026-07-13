import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

interface TargetPackage {
  name: string;
  os: 'darwin' | 'linux' | 'win32';
  cpu: 'arm64' | 'x64';
  libc?: 'glibc' | 'musl';
}

const targets: TargetPackage[] = [
  { name: '@palladin/runtime-darwin-arm64', os: 'darwin', cpu: 'arm64' },
  { name: '@palladin/runtime-darwin-x64', os: 'darwin', cpu: 'x64' },
  { name: '@palladin/runtime-win32-arm64', os: 'win32', cpu: 'arm64' },
  { name: '@palladin/runtime-win32-x64', os: 'win32', cpu: 'x64' },
  { name: '@palladin/runtime-linux-arm64-gnu', os: 'linux', cpu: 'arm64', libc: 'glibc' },
  { name: '@palladin/runtime-linux-arm64-musl', os: 'linux', cpu: 'arm64', libc: 'musl' },
  { name: '@palladin/runtime-linux-x64-gnu', os: 'linux', cpu: 'x64', libc: 'glibc' },
  { name: '@palladin/runtime-linux-x64-musl', os: 'linux', cpu: 'x64', libc: 'musl' },
];

const testedTargets = process.env.PALLADIN_NPM_SELECTION_NATIVE_ONLY === '1'
  ? targets.filter((target) => (
      target.os === process.platform
      && target.cpu === process.arch
      && (target.os !== 'linux' || target.libc === 'glibc')
    ))
  : targets;
const nativeTarget = targets.find((target) => (
  target.os === process.platform
  && target.cpu === process.arch
  && (target.os !== 'linux' || target.libc === 'glibc')
));

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

describe('npm platform selection', () => {
  it.each(testedTargets)('installs only $name for $os/$cpu/$libc', (selected) => {
    const npmCli = process.env.npm_execpath;
    if (!npmCli) throw new Error('npm_execpath is unavailable');
    const fixture = mkdtempSync(join(tmpdir(), 'palladin-npm-selection-'));
    try {
      const optionalDependencies: Record<string, string> = {};
      for (const target of targets) {
        const directoryName = target.name.slice('@palladin/'.length);
        const directory = join(fixture, 'packages', directoryName);
        mkdirSync(directory, { recursive: true });
        writeJson(join(directory, 'package.json'), {
          name: target.name,
          version: '0.1.0',
          os: [target.os],
          cpu: [target.cpu],
          ...(target.libc === undefined ? {} : { libc: [target.libc] }),
          files: ['README.md'],
        });
        writeFileSync(join(directory, 'README.md'), `${target.name}\n`, { mode: 0o600 });
        optionalDependencies[target.name] = pathToFileURL(directory).href;
      }
      writeJson(join(fixture, 'package.json'), {
        name: 'palladin-install-selection-fixture',
        version: '0.0.0',
        private: true,
        optionalDependencies,
      });

      const args = [
        npmCli,
        'install',
        '--ignore-scripts',
        '--no-package-lock',
        '--no-audit',
        '--no-fund',
        `--os=${selected.os}`,
        `--cpu=${selected.cpu}`,
      ];
      if (selected.libc !== undefined) args.push(`--libc=${selected.libc}`);
      execFileSync(process.execPath, args, {
        cwd: fixture,
        stdio: 'pipe',
        env: {
          ...process.env,
          npm_config_cache: join(fixture, '.npm-cache'),
          npm_config_loglevel: 'error',
        },
      });

      const installed = readdirSync(join(fixture, 'node_modules', '@palladin')).sort();
      expect(installed).toEqual([selected.name.slice('@palladin/'.length)]);
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  }, 30_000);

  it.runIf(nativeTarget !== undefined)('proves that --omit=optional removes the required runtime', () => {
    const npmCli = process.env.npm_execpath;
    if (!npmCli || nativeTarget === undefined) throw new Error('native npm fixture is unavailable');
    const fixture = mkdtempSync(join(tmpdir(), 'palladin-npm-omit-'));
    try {
      const directoryName = nativeTarget.name.slice('@palladin/'.length);
      const packageDirectory = join(fixture, 'packages', directoryName);
      mkdirSync(packageDirectory, { recursive: true });
      writeJson(join(packageDirectory, 'package.json'), {
        name: nativeTarget.name,
        version: '0.1.0',
        os: [nativeTarget.os],
        cpu: [nativeTarget.cpu],
        ...(nativeTarget.libc === undefined ? {} : { libc: [nativeTarget.libc] }),
      });
      writeJson(join(fixture, 'package.json'), {
        name: 'palladin-omit-fixture',
        version: '0.0.0',
        private: true,
        optionalDependencies: {
          [nativeTarget.name]: `file:packages/${directoryName}`,
        },
      });
      execFileSync(process.execPath, [
        npmCli,
        'install',
        '--ignore-scripts',
        '--omit=optional',
        '--no-package-lock',
        '--no-audit',
        '--no-fund',
      ], {
        cwd: fixture,
        stdio: 'pipe',
        env: { ...process.env, npm_config_cache: join(fixture, '.npm-cache') },
      });
      expect(existsSync(join(fixture, 'node_modules', '@palladin', directoryName))).toBe(false);
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  }, 30_000);

});
