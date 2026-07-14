import { execFileSync, spawn } from 'node:child_process';
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { VerifiedArtifactBinding } from '../../src/runtime/version-policy.js';
import {
  prepareWindowsRuntimeCache,
  quoteWindowsArgument,
  sha256File,
} from '../../src/runtime/windows-runtime-cache.js';

const fixtures: string[] = [];
const packageName = '@palladin/runtime-win32-x64';
const longRunningArguments = process.platform === 'win32'
  ? ['-n', '10', '127.0.0.1']
  : ['10'];
const quickArguments = process.platform === 'win32'
  ? ['-n', '1', '127.0.0.1']
  : ['0'];

function fixture(): string {
  const path = mkdtempSync(join(tmpdir(), 'palladin-runtime-cache-'));
  fixtures.push(path);
  return path;
}

function source(root: string, version: string, contents: string): string {
  const directory = join(root, 'packages', version, 'bin');
  mkdirSync(directory, { recursive: true });
  const executable = join(directory, 'palladin-client.exe');
  writeFileSync(executable, contents, { mode: 0o700 });
  return executable;
}

function installProcessFixture(path: string): void {
  if (process.platform === 'win32') {
    copyFileSync('C:\\Windows\\System32\\ping.exe', path);
    return;
  }
  writeFileSync(path, '#!/bin/sh\nexec /bin/sleep "$1"\n', { mode: 0o700 });
}

function binding(version: string, executable: string): VerifiedArtifactBinding {
  return {
    packageName,
    version,
    executableSha256: sha256File(executable),
    workerExecutableSha256: 'c'.repeat(64),
    authenticodePublisher: 'CN=Palladin Test',
    authenticodeThumbprint: 'A'.repeat(40),
    policySequence: 7,
    policySource: 'https://releases.palladin.io/agent/version-policy.json',
    sourceSha: 'b'.repeat(40),
    envelopeBase64: 'fixture',
  };
}

function processIsAlive(processId: number): boolean {
  try {
    process.kill(processId, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitUntil(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for Windows process state');
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
  }
}

afterEach(() => {
  for (const path of fixtures.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('Windows content-addressed runtime cache', () => {
  it.each([
    ['', '""'],
    ['plain', 'plain'],
    ['two words', '"two words"'],
    ['embedded"quote', '"embedded\\"quote"'],
    ['trailing slash\\', '"trailing slash\\\\"'],
    ['slash\\"quote', '"slash\\\\\\"quote"'],
  ])('quotes a Windows argument without invoking a shell: %j', (argument, expected) => {
    expect(quoteWindowsArgument(argument)).toBe(expected);
  });

  it('rejects NUL in a Windows argument', () => {
    expect(() => quoteWindowsArgument('invalid\0argument')).toThrow('argument is invalid');
  });

  it.skipIf(process.platform !== 'win32')(
    'locks verified bytes and kills the suspended child job when its launcher exits',
    async () => {
      const root = fixture();
      const systemRoot = process.env.SystemRoot;
      if (systemRoot === undefined) throw new Error('SystemRoot is unavailable');
      const powershell = realpathSync(join(
        systemRoot,
        'System32',
        'WindowsPowerShell',
        'v1.0',
        'powershell.exe',
      ));
      const signature = JSON.parse(execFileSync(powershell, [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        "$s=Get-AuthenticodeSignature -LiteralPath $env:PALLADIN_TEST_SIGNED_PATH; [pscustomobject]@{Publisher=$s.SignerCertificate.Subject;Thumbprint=$s.SignerCertificate.Thumbprint;Timestamped=($null -ne $s.TimeStamperCertificate)} | ConvertTo-Json -Compress",
      ], {
        encoding: 'utf8',
        env: { SystemRoot: systemRoot, PALLADIN_TEST_SIGNED_PATH: powershell },
        windowsHide: true,
      })) as { Publisher: string; Thumbprint: string; Timestamped: boolean };
      expect(signature.Timestamped).toBe(true);

      const executable = source(root, '1.0.0', 'placeholder');
      copyFileSync(powershell, executable);
      const verified: VerifiedArtifactBinding = {
        ...binding('1.0.0', executable),
        authenticodePublisher: signature.Publisher,
        authenticodeThumbprint: signature.Thumbprint,
      };
      const lease = prepareWindowsRuntimeCache({
        packageName,
        version: '1.0.0',
        executable,
      }, verified, { cacheRoot: join(root, 'cache') });
      const pidPath = join(root, 'native-child.pid');
      const child = lease.spawnLocked([
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        '$PID | Set-Content -LiteralPath $env:PALLADIN_TEST_PID_PATH; Start-Sleep -Seconds 30',
      ], {
        shell: false,
        stdio: 'ignore',
        windowsHide: true,
        env: { ...process.env, PALLADIN_TEST_PID_PATH: pidPath },
      });
      await new Promise<void>((resolve, reject) => {
        child.once('spawn', resolve);
        child.once('error', reject);
      });
      lease.bindToChild(child.pid);
      await waitUntil(() => existsSync(pidPath), 15_000);
      const nativePid = Number.parseInt(readFileSync(pidPath, 'utf8').trim(), 10);
      expect(Number.isSafeInteger(nativePid) && nativePid > 0).toBe(true);
      expect(processIsAlive(nativePid)).toBe(true);
      const wrapperExited = new Promise<void>((resolve, reject) => {
        child.once('exit', () => resolve());
        child.once('error', reject);
      });
      expect(child.kill()).toBe(true);
      await wrapperExited;
      await waitUntil(() => !processIsAlive(nativePid), 10_000);
      lease.release();
    },
    30_000,
  );

  it('atomically copies and re-verifies an exact signed version/hash before use', () => {
    const root = fixture();
    const executable = source(root, '1.0.0', 'signed-runtime-v1');
    const verified = binding('1.0.0', executable);
    const verifyAuthenticode = vi.fn();
    const lease = prepareWindowsRuntimeCache({
      packageName,
      version: '1.0.0',
      executable,
    }, verified, {
      cacheRoot: join(root, 'cache'),
      processId: 100,
      processIsAlive: () => true,
      verifyAuthenticode,
    });

    expect(lease.executable).toContain(join(
      'v1',
      'win32-x64',
      '1.0.0',
      verified.executableSha256,
      'palladin-client.exe',
    ));
    expect(sha256File(lease.executable)).toBe(verified.executableSha256);
    lease.verifyBeforeSpawn();
    expect(verifyAuthenticode).toHaveBeenCalledWith(lease.executable, verified);
    expect(verifyAuthenticode).toHaveBeenCalledOnce();
    lease.release();
  });

  it('fails closed when the source or an existing cache entry does not match policy', () => {
    const root = fixture();
    const executable = source(root, '1.0.0', 'signed-runtime-v1');
    const verified = binding('1.0.0', executable);
    const options = {
      cacheRoot: join(root, 'cache'),
      processId: 100,
      processIsAlive: () => true,
      verifyAuthenticode: vi.fn(),
    };
    const lease = prepareWindowsRuntimeCache({ packageName, version: '1.0.0', executable }, verified, options);
    writeFileSync(lease.executable, 'attacker-runtime');
    expect(() => lease.verifyBeforeSpawn()).toThrow('hash verification failed');
    lease.release();
    expect(() => prepareWindowsRuntimeCache(
      { packageName, version: '1.0.0', executable },
      verified,
      options,
    )).toThrow('hash verification failed');

    writeFileSync(executable, 'changed-during-update');
    expect(() => prepareWindowsRuntimeCache(
      { packageName, version: '1.0.0', executable },
      verified,
      options,
    )).toThrow('hash verification failed');
  });

  it('retains a live N session while N+1 starts and collects only inactive old entries', () => {
    const root = fixture();
    const cacheRoot = join(root, 'cache');
    const alive = new Set<number>([200]);
    const options = {
      cacheRoot,
      processIsAlive: (processId: number) => alive.has(processId),
      verifyAuthenticode: vi.fn(),
    };
    const executableN = source(root, '1.0.0', 'signed-runtime-v1');
    const bindingN = binding('1.0.0', executableN);
    const sessionN = prepareWindowsRuntimeCache(
      { packageName, version: '1.0.0', executable: executableN },
      bindingN,
      { ...options, processId: 100 },
    );
    expect(sessionN.executable).toContain(join('1.0.0', bindingN.executableSha256));
    sessionN.bindToChild(200);

    const executableN1 = source(root, '1.1.0', 'signed-runtime-v2');
    const bindingN1 = binding('1.1.0', executableN1);
    const sessionN1 = prepareWindowsRuntimeCache(
      { packageName, version: '1.1.0', executable: executableN1 },
      bindingN1,
      { ...options, processId: 101 },
    );
    alive.add(201);
    sessionN1.bindToChild(201);
    expect(existsSync(sessionN.executable)).toBe(true);
    expect(sessionN1.executable).toContain(join('1.1.0', bindingN1.executableSha256));

    alive.delete(200);
    sessionN.release();
    const executableN2 = source(root, '1.2.0', 'signed-runtime-v3');
    const bindingN2 = binding('1.2.0', executableN2);
    const sessionN2 = prepareWindowsRuntimeCache(
      { packageName, version: '1.2.0', executable: executableN2 },
      bindingN2,
      { ...options, processId: 102 },
    );
    expect(existsSync(sessionN.executable)).toBe(false);
    expect(existsSync(sessionN1.executable)).toBe(true);
    alive.delete(201);
    sessionN1.release();
    sessionN2.release();
  });

  it('keeps an already loaded executable alive through uninstall and selects N+1 after update', async () => {
    const root = fixture();
    const cacheRoot = join(root, 'cache');
    const packageN = join(root, 'installed-N', 'bin');
    mkdirSync(packageN, { recursive: true });
    const executableN = join(packageN, 'palladin-client.exe');
    installProcessFixture(executableN);
    const bindingN = binding('1.0.0', executableN);
    const sessionN = prepareWindowsRuntimeCache(
      { packageName, version: '1.0.0', executable: executableN },
      bindingN,
      { cacheRoot, verifyAuthenticode: vi.fn() },
    );
    const childN = spawn(sessionN.executable, longRunningArguments, {
      shell: false,
      stdio: 'ignore',
      windowsHide: true,
    });
    await new Promise<void>((resolve, reject) => {
      childN.once('spawn', resolve);
      childN.once('error', reject);
    });
    sessionN.bindToChild(childN.pid);

    rmSync(join(root, 'installed-N'), { recursive: true, force: false });
    expect(childN.exitCode).toBeNull();

    const packageN1 = join(root, 'installed-N', 'bin');
    mkdirSync(packageN1, { recursive: true });
    const executableN1 = join(packageN1, 'palladin-client.exe');
    installProcessFixture(executableN1);
    const bindingN1 = binding('1.1.0', executableN1);
    const sessionN1 = prepareWindowsRuntimeCache(
      { packageName, version: '1.1.0', executable: executableN1 },
      bindingN1,
      { cacheRoot, verifyAuthenticode: vi.fn() },
    );
    expect(sessionN1.executable).not.toBe(sessionN.executable);
    expect(sessionN1.executable).toContain(join('1.1.0', bindingN1.executableSha256));
    expect(existsSync(sessionN.executable)).toBe(true);
    const childN1 = spawn(sessionN1.executable, quickArguments, {
      shell: false,
      stdio: 'ignore',
      windowsHide: true,
    });
    sessionN1.bindToChild(childN1.pid);
    const nextExit = await new Promise<number | null>((resolve, reject) => {
      childN1.once('exit', resolve);
      childN1.once('error', reject);
    });
    expect(nextExit).toBe(0);
    expect(childN.exitCode).toBeNull();

    childN.kill();
    await new Promise<void>((resolve) => childN.once('exit', () => resolve()));
    sessionN.release();
    const cachedN1 = sessionN1.executable;
    sessionN1.release();

    rmSync(join(root, 'installed-N'), { recursive: true, force: false });
    expect(existsSync(cachedN1)).toBe(true);
    mkdirSync(packageN1, { recursive: true });
    installProcessFixture(executableN1);
    const reinstalledN1 = prepareWindowsRuntimeCache(
      { packageName, version: '1.1.0', executable: executableN1 },
      bindingN1,
      { cacheRoot, verifyAuthenticode: vi.fn() },
    );
    expect(reinstalledN1.executable).toBe(cachedN1);
    reinstalledN1.verifyBeforeSpawn();
    reinstalledN1.release();
  }, 30_000);
});
