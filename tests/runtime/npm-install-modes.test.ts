import { execFile, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { readFileSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

const run = promisify(execFile);

interface RegistryPackage {
  manifest: Record<string, unknown>;
  tarball: Buffer;
  tarballPath: string;
}

const platformPackages = [
  ['@palladin/runtime-darwin-arm64', 'darwin', 'arm64', undefined],
  ['@palladin/runtime-darwin-x64', 'darwin', 'x64', undefined],
  ['@palladin/runtime-win32-arm64', 'win32', 'arm64', undefined],
  ['@palladin/runtime-win32-x64', 'win32', 'x64', undefined],
  ['@palladin/runtime-linux-arm64-gnu', 'linux', 'arm64', 'glibc'],
  ['@palladin/runtime-linux-arm64-musl', 'linux', 'arm64', 'musl'],
  ['@palladin/runtime-linux-x64-gnu', 'linux', 'x64', 'glibc'],
  ['@palladin/runtime-linux-x64-musl', 'linux', 'x64', 'musl'],
] as const;

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function pack(npmCli: string, directory: string, destination: string): Buffer {
  const output = execFileSync(process.execPath, [
    npmCli,
    'pack',
    directory,
    '--pack-destination', destination,
    '--json',
  ], { encoding: 'utf8', env: { ...process.env, npm_config_loglevel: 'silent' } });
  const result = JSON.parse(output) as Array<{ filename: string }>;
  const filename = result[0]?.filename;
  if (!filename) throw new Error('npm pack did not return a tarball');
  return readFileSync(join(destination, filename));
}

function installedPackageNames(directory: string): string[] {
  const names: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      names.push(...installedPackageNames(path));
    } else if (entry.isFile() && entry.name === 'package.json') {
      const manifest = JSON.parse(readFileSync(path, 'utf8')) as { name?: string };
      if (manifest.name !== undefined) names.push(manifest.name);
    }
  }
  return names;
}

describe('npm installation modes', () => {
  it('supports global and exact-version npx installs through the package registry', async () => {
    const npmCli = process.env.npm_execpath;
    if (!npmCli) throw new Error('npm_execpath is unavailable');
    const fixture = mkdtempSync(join(tmpdir(), 'palladin-npm-modes-'));
    const packages = new Map<string, RegistryPackage>();
    const server = createServer((request, response) => {
      const pathname = new URL(request.url ?? '/', 'http://registry.invalid').pathname;
      if (pathname.startsWith('/tarballs/')) {
        const record = [...packages.values()].find((candidate) => candidate.tarballPath === pathname);
        if (!record) {
          response.writeHead(404).end();
          return;
        }
        response.writeHead(200, { 'content-type': 'application/octet-stream' }).end(record.tarball);
        return;
      }
      const name = decodeURIComponent(pathname.slice(1));
      const record = packages.get(name);
      if (!record) {
        response.writeHead(404, { 'content-type': 'application/json' }).end('{}');
        return;
      }
      const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
      const manifest = {
        ...record.manifest,
        dist: { tarball: `${origin}${record.tarballPath}` },
      };
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        name,
        'dist-tags': { latest: '0.1.0' },
        versions: { '0.1.0': manifest },
      }));
    });

    try {
      const sources = join(fixture, 'sources');
      const tarballs = join(fixture, 'tarballs');
      mkdirSync(sources);
      mkdirSync(tarballs);
      const optionalDependencies: Record<string, string> = {};
      for (const [name, os, cpu, libc] of platformPackages) {
        const shortName = name.slice('@palladin/'.length);
        const directory = join(sources, shortName);
        mkdirSync(directory);
        const manifest = {
          name,
          version: '0.1.0',
          os: [os],
          cpu: [cpu],
          ...(libc === undefined ? {} : { libc: [libc] }),
          files: ['README.md'],
        };
        writeJson(join(directory, 'package.json'), manifest);
        writeFileSync(join(directory, 'README.md'), `${name}\n`);
        optionalDependencies[name] = '0.1.0';
        packages.set(name, {
          manifest,
          tarball: pack(npmCli, directory, tarballs),
          tarballPath: `/tarballs/${shortName}.tgz`,
        });
      }

      const launcherName = '@palladin/agent';
      const launcher = join(sources, 'agent');
      mkdirSync(launcher);
      const launcherManifest = {
        name: launcherName,
        version: '0.1.0',
        bin: { palladin: 'palladin.js' },
        files: ['palladin.js'],
        optionalDependencies,
      };
      writeJson(join(launcher, 'package.json'), launcherManifest);
      writeFileSync(
        join(launcher, 'palladin.js'),
        '#!/usr/bin/env node\nprocess.stdout.write("palladin fixture\\n");\n',
        { mode: 0o700 },
      );
      packages.set(launcherName, {
        manifest: launcherManifest,
        tarball: pack(npmCli, launcher, tarballs),
        tarballPath: '/tarballs/agent.tgz',
      });

      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
      const prefix = join(fixture, 'global');
      await run(process.execPath, [
        npmCli,
        'install',
        '--global',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--prefix', prefix,
        '--registry', origin,
        '@palladin/agent@0.1.0',
      ], { env: { ...process.env, npm_config_cache: join(fixture, 'global-cache') } });
      const globalRoot = (await run(process.execPath, [
        npmCli,
        'root',
        '--global',
        '--prefix', prefix,
      ])).stdout.trim();
      const installed = installedPackageNames(globalRoot)
        .filter((name) => name.startsWith('@palladin/runtime-'));
      const expectedRuntime = platformPackages.find(([, os, cpu, libc]) => (
        os === process.platform
        && cpu === process.arch
        && (os !== 'linux' || libc === 'glibc')
      ))?.[0];
      expect(expectedRuntime).toBeDefined();
      expect(installed).toEqual([expectedRuntime]);

      const npxWork = join(fixture, 'npx-work');
      mkdirSync(npxWork);
      const npx = await run(process.execPath, [
        npmCli,
        'exec',
        '--yes',
        '--ignore-scripts',
        '--registry', origin,
        '--package', '@palladin/agent@0.1.0',
        '--',
        'palladin',
      ], {
        cwd: npxWork,
        env: { ...process.env, npm_config_cache: join(fixture, 'npx-cache') },
      });
      expect(npx.stdout.trim()).toBe('palladin fixture');
    } finally {
      if (server.listening) {
        server.closeAllConnections?.();
        await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      }
      rmSync(fixture, { recursive: true, force: true });
    }
  }, 60_000);
});
