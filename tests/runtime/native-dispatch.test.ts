import { EventEmitter } from 'node:events';
import type { ChildProcess } from 'node:child_process';
import { describe, expect, it, vi } from 'vitest';
import {
  detectLinuxLibcFromElf,
  launchNativeRuntime,
  resolveNativeRuntime,
  type NativeDispatchHost,
} from '../../src/runtime/native-dispatch.js';
import type { VerifiedArtifactBinding } from '../../src/runtime/version-policy.js';
import type { WindowsRuntimeLease } from '../../src/runtime/windows-runtime-cache.js';

const packageJson = '/fixture/node_modules/@palladin/runtime-darwin-arm64/package.json';
const executable = '/fixture/node_modules/@palladin/runtime-darwin-arm64/PalladinRuntime.app/Contents/MacOS/palladin';
const windowsPackageJson = 'C:\\fixture\\node_modules\\@palladin\\runtime-win32-x64\\package.json';
const windowsExecutable = 'C:\\fixture\\node_modules\\@palladin\\runtime-win32-x64\\bin\\palladin-client.exe';
const linuxPackageJson = '/fixture/node_modules/@palladin/runtime-linux-x64-gnu/package.json';
const linuxExecutable = '/fixture/node_modules/@palladin/runtime-linux-x64-gnu/bin/palladin-linux-client';

function elfWithInterpreter(interpreter: string): Buffer {
  const bytes = Buffer.alloc(512);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(1, 56);
  bytes.writeUInt32LE(3, 64);
  bytes.writeBigUInt64LE(256n, 72);
  const encoded = Buffer.from(`${interpreter}\0`, 'utf8');
  bytes.writeBigUInt64LE(BigInt(encoded.length), 96);
  encoded.copy(bytes, 256);
  return bytes;
}

function childProcess(): ChildProcess {
  const child = new EventEmitter() as ChildProcess;
  Object.assign(child, { exitCode: null, signalCode: null, kill: vi.fn(() => true) });
  return child;
}

function host(overrides: Partial<NativeDispatchHost> = {}): NativeDispatchHost {
  const platform = overrides.platform ?? 'darwin';
  const architecture = overrides.architecture ?? 'arm64';
  const linuxLibc = overrides.linuxLibc;
  const fixture: NativeDispatchHost = {
    platform: 'darwin',
    architecture: 'arm64',
    resolvePackageJson: vi.fn(() => packageJson),
    realpath: vi.fn((path: string) => path),
    assertExecutable: vi.fn(),
    readPackageManifest: vi.fn((path: string) => ({
      name: packageNameFromPath(path),
      version: '0.1.0',
      os: [platform],
      cpu: [architecture],
      ...(platform === 'linux' ? { libc: [linuxLibc] } : {}),
    })),
    hashFile: vi.fn(() => 'a'.repeat(64)),
    loadVerifiedArtifactBinding: vi.fn(async (request) => ({
      packageName: request.packageName,
      version: request.version,
      executableSha256: request.executableSha256,
      workerExecutableSha256: 'c'.repeat(64),
      ...(request.packageName.startsWith('@palladin/runtime-win32-') ? {
        authenticodePublisher: 'CN=Palladin Test',
        authenticodeThumbprint: 'A'.repeat(40),
      } : {}),
      policySequence: 1,
      policySource: 'https://releases.palladin.io/agent/version-policy.json',
      sourceSha: request.sourceSha,
      runtimeAllowed: true,
      envelopeBase64: 'fixture',
    } satisfies VerifiedArtifactBinding)),
    loadBundledArtifactBinding: vi.fn(async (request) => ({
      packageName: request.packageName,
      version: request.version,
      executableSha256: request.executableSha256,
      workerExecutableSha256: 'c'.repeat(64),
      ...(request.packageName.startsWith('@palladin/runtime-win32-') ? {
        authenticodePublisher: 'CN=Palladin Test',
        authenticodeThumbprint: 'A'.repeat(40),
      } : {}),
      policySequence: 1,
      policySource: 'https://releases.palladin.io/agent/version-policy.json',
      sourceSha: request.sourceSha,
      runtimeAllowed: true,
      envelopeBase64: 'fixture',
    } satisfies VerifiedArtifactBinding)),
    prepareWindowsRuntime: vi.fn((source) => fakeWindowsLease(source.executable)),
    spawnRuntime: vi.fn(() => childProcess()),
    addSignalHandler: vi.fn(),
    removeSignalHandler: vi.fn(),
    ...overrides,
  };
  return fixture;
}

function packageNameFromPath(path: string): string {
  const normalized = path.replaceAll('\\', '/');
  const match = /node_modules\/(?:@palladin\/)?([^/]+)\/package\.json$/.exec(normalized);
  return match?.[1] === undefined ? '@palladin/runtime-darwin-arm64' : `@palladin/${match[1]}`;
}

function fakeWindowsLease(executablePath: string): WindowsRuntimeLease {
  const child = childProcess();
  return {
    executable: executablePath,
    verifyBeforeSpawn: vi.fn(),
    spawnLocked: vi.fn(() => child),
    bindToChild: vi.fn(),
    release: vi.fn(),
  };
}

describe('native runtime dispatcher', () => {
  it.each([
    ['arm64', '@palladin/runtime-darwin-arm64/package.json', packageJson, executable],
    [
      'x64',
      '@palladin/runtime-darwin-x64/package.json',
      '/fixture/node_modules/@palladin/runtime-darwin-x64/package.json',
      '/fixture/node_modules/@palladin/runtime-darwin-x64/PalladinRuntime.app/Contents/MacOS/palladin',
    ],
  ])('resolves the universal signed bundle from the darwin/%s package', (architecture, specifier, manifest, runtime) => {
    const fixture = host({ architecture, resolvePackageJson: vi.fn(() => manifest) });
    expect(resolveNativeRuntime(fixture)).toBe(runtime);
    expect(fixture.resolvePackageJson).toHaveBeenCalledWith(
      specifier,
    );
    expect(fixture.assertExecutable).toHaveBeenCalledWith(runtime);
  });

  it.each([
    ['x64', '@palladin/runtime-win32-x64/package.json', windowsPackageJson, windowsExecutable],
    [
      'arm64',
      '@palladin/runtime-win32-arm64/package.json',
      'C:\\fixture\\node_modules\\@palladin\\runtime-win32-arm64\\package.json',
      'C:\\fixture\\node_modules\\@palladin\\runtime-win32-arm64\\bin\\palladin-client.exe',
    ],
  ])('resolves only the fixed signed client for win32/%s', (architecture, specifier, manifest, client) => {
    const fixture = host({
      platform: 'win32',
      architecture,
      resolvePackageJson: vi.fn(() => manifest),
    });
    expect(resolveNativeRuntime(fixture)).toBe(client);
    expect(fixture.resolvePackageJson).toHaveBeenCalledWith(specifier);
    expect(fixture.assertExecutable).toHaveBeenCalledWith(client);
  });

  it('has no TypeScript, PATH, download, or unsupported-platform fallback', () => {
    const fixture = host({ platform: 'freebsd' });
    expect(() => resolveNativeRuntime(fixture)).toThrow('not installed for freebsd/arm64');
    expect(fixture.resolvePackageJson).not.toHaveBeenCalled();
    expect(fixture.spawnRuntime).not.toHaveBeenCalled();
  });

  it('explains how to recover when optional platform packages are unavailable', async () => {
    const fixture = host({ resolvePackageJson: vi.fn(() => { throw new Error('missing'); }) });
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await expect(launchNativeRuntime([], fixture)).resolves.toBe(1);
    expect(write).toHaveBeenCalledWith(expect.stringContaining('@palladin/runtime-darwin-arm64@0.1.0'));
    expect(write).toHaveBeenCalledWith(expect.stringContaining('--omit=optional'));
    expect(write).toHaveBeenCalledWith(expect.stringContaining('npm cache or registry proxy'));
    write.mockRestore();
  });

  it.each([
    ['x64', '@palladin/runtime-linux-x64-gnu/package.json', linuxPackageJson, linuxExecutable],
    [
      'arm64',
      '@palladin/runtime-linux-arm64-gnu/package.json',
      '/fixture/node_modules/@palladin/runtime-linux-arm64-gnu/package.json',
      '/fixture/node_modules/@palladin/runtime-linux-arm64-gnu/bin/palladin-linux-client',
    ],
  ])('resolves only the fixed glibc client for linux/%s', (architecture, specifier, manifest, client) => {
    const fixture = host({
      platform: 'linux',
      architecture,
      linuxLibc: 'glibc',
      resolvePackageJson: vi.fn(() => manifest),
    });
    expect(resolveNativeRuntime(fixture)).toBe(client);
    expect(fixture.resolvePackageJson).toHaveBeenCalledWith(specifier);
    expect(fixture.assertExecutable).toHaveBeenCalledWith(client);
  });

  it.each([
    [
      'x64',
      '@palladin/runtime-linux-x64-musl/package.json',
      '/fixture/node_modules/@palladin/runtime-linux-x64-musl/package.json',
      '/fixture/node_modules/@palladin/runtime-linux-x64-musl/bin/palladin-linux-client',
    ],
    [
      'arm64',
      '@palladin/runtime-linux-arm64-musl/package.json',
      '/fixture/node_modules/@palladin/runtime-linux-arm64-musl/package.json',
      '/fixture/node_modules/@palladin/runtime-linux-arm64-musl/bin/palladin-linux-client',
    ],
  ])('resolves only the fixed musl client for linux/%s', (architecture, specifier, manifest, client) => {
    const fixture = host({
      platform: 'linux',
      architecture,
      linuxLibc: 'musl',
      resolvePackageJson: vi.fn(() => manifest),
    });
    expect(resolveNativeRuntime(fixture)).toBe(client);
    expect(fixture.resolvePackageJson).toHaveBeenCalledWith(specifier);
    expect(fixture.assertExecutable).toHaveBeenCalledWith(client);
  });

  it('detects libc only from an exact ELF interpreter for the current architecture', () => {
    expect(detectLinuxLibcFromElf(elfWithInterpreter('/lib64/ld-linux-x86-64.so.2'), 'x64'))
      .toBe('glibc');
    expect(detectLinuxLibcFromElf(elfWithInterpreter('/lib/ld-musl-x86_64.so.1'), 'x64'))
      .toBe('musl');
    expect(detectLinuxLibcFromElf(elfWithInterpreter('/lib/ld-musl-aarch64.so.1'), 'arm64'))
      .toBe('musl');
    expect(detectLinuxLibcFromElf(elfWithInterpreter('/lib/ld-linux-aarch64.so.1'), 'arm64'))
      .toBe('glibc');
    expect(detectLinuxLibcFromElf(elfWithInterpreter('/tmp/ld-musl-x86_64.so.1'), 'x64'))
      .toBe('unsupported');
    expect(detectLinuxLibcFromElf(elfWithInterpreter('/tmp/ld-linux-aarch64.so.1'), 'arm64'))
      .toBe('unsupported');
    expect(detectLinuxLibcFromElf(elfWithInterpreter('/system/bin/linker64'), 'arm64'))
      .toBe('unsupported');
    expect(detectLinuxLibcFromElf(Buffer.alloc(64), 'x64')).toBe('unsupported');
    const duplicate = elfWithInterpreter('/lib/ld-musl-aarch64.so.1');
    duplicate.writeUInt16LE(2, 56);
    duplicate.writeUInt32LE(3, 120);
    duplicate.writeBigUInt64LE(256n, 128);
    duplicate.writeBigUInt64LE(duplicate.readBigUInt64LE(96), 152);
    expect(detectLinuxLibcFromElf(duplicate, 'arm64')).toBe('unsupported');
  });

  it('fails closed when the Linux libc cannot be positively identified', () => {
    const fixture = host({
      platform: 'linux',
      architecture: 'x64',
      linuxLibc: 'unsupported',
    });
    expect(() => resolveNativeRuntime(fixture)).toThrow('does not support this Linux libc');
    expect(fixture.resolvePackageJson).not.toHaveBeenCalled();
  });

  it('rejects unsupported Linux architectures before package resolution', () => {
    const fixture = host({ platform: 'linux', architecture: 'riscv64', linuxLibc: 'glibc' });
    expect(() => resolveNativeRuntime(fixture)).toThrow('does not support linux/riscv64');
    expect(fixture.resolvePackageJson).not.toHaveBeenCalled();
  });

  it('rejects unsupported Windows architectures before package resolution', () => {
    const fixture = host({ platform: 'win32', architecture: 'ia32' });
    expect(() => resolveNativeRuntime(fixture)).toThrow('does not support win32/ia32');
    expect(fixture.resolvePackageJson).not.toHaveBeenCalled();
  });

  it('rejects a Windows client resolving outside its exact platform package', () => {
    const fixture = host({
      platform: 'win32',
      architecture: 'x64',
      resolvePackageJson: vi.fn(() => windowsPackageJson),
      realpath: vi.fn((path: string) => path.endsWith('palladin-client.exe')
        ? 'C:\\attacker\\palladin-client.exe'
        : path),
    });
    expect(() => resolveNativeRuntime(fixture)).toThrow('resolved outside');
    expect(fixture.assertExecutable).not.toHaveBeenCalled();
  });

  it('rejects a symlinked executable escaping the platform package', () => {
    const fixture = host({
      realpath: vi.fn((path: string) => path.endsWith('/palladin') ? '/tmp/attacker' : path),
    });
    expect(() => resolveNativeRuntime(fixture)).toThrow('resolved outside');
    expect(fixture.assertExecutable).not.toHaveBeenCalled();
  });

  it.each([
    { name: '@palladin/runtime-darwin-arm64', version: '0.2.0', os: ['darwin'], cpu: ['arm64'] },
    {
      name: '@palladin/runtime-darwin-arm64',
      version: '0.1.0',
      os: ['darwin'],
      cpu: ['arm64'],
      scripts: { postinstall: 'attacker' },
    },
  ])('rejects a mismatched or active platform package manifest before policy/spawn', (manifest) => {
    const fixture = host({ readPackageManifest: vi.fn(() => manifest) });
    expect(() => resolveNativeRuntime(fixture)).toThrow('package manifest is invalid');
    expect(fixture.loadVerifiedArtifactBinding).not.toHaveBeenCalled();
    expect(fixture.spawnRuntime).not.toHaveBeenCalled();
  });

  it('spawns the fixed executable without a shell and preserves argv as separate values', async () => {
    const child = childProcess();
    const fixture = host({ spawnRuntime: vi.fn(() => child) });
    const result = launchNativeRuntime(['get', 'entry;$(touch attacker)'], fixture);
    await vi.waitFor(() => expect(fixture.spawnRuntime).toHaveBeenCalledOnce());
    child.emit('exit', 0, null);
    await expect(result).resolves.toBe(0);
    expect(fixture.spawnRuntime).toHaveBeenCalledWith(executable, [
      'get',
      'entry;$(touch attacker)',
    ], {
      shell: false,
      stdio: 'inherit',
      windowsHide: true,
    });
  });

  it.each(['--help', '-h', '--version', '-V', 'doctor'])(
    'keeps exact identity-free diagnostic %s available during a policy outage',
    async (diagnostic) => {
      const child = childProcess();
      const fixture = host({
        loadVerifiedArtifactBinding: vi.fn(async () => { throw new Error('offline'); }),
        spawnRuntime: vi.fn(() => child),
      });
      const result = launchNativeRuntime([diagnostic], fixture);
      await vi.waitFor(() => expect(fixture.spawnRuntime).toHaveBeenCalledOnce());
      child.emit('exit', 0, null);
      await expect(result).resolves.toBe(0);
      expect(fixture.loadVerifiedArtifactBinding).not.toHaveBeenCalled();
      expect(fixture.loadBundledArtifactBinding).toHaveBeenCalledOnce();
    },
  );

  it('runs offline Windows doctor only through the bundled binding and verified cache', async () => {
    const child = childProcess();
    const lease = fakeWindowsLease('C:\\cache\\doctor\\palladin-client.exe');
    vi.mocked(lease.spawnLocked).mockReturnValue(child);
    const fixture = host({
      platform: 'win32',
      architecture: 'x64',
      resolvePackageJson: vi.fn(() => windowsPackageJson),
      loadVerifiedArtifactBinding: vi.fn(async () => { throw new Error('offline'); }),
      prepareWindowsRuntime: vi.fn(() => lease),
      spawnRuntime: vi.fn(() => child),
    });
    const result = launchNativeRuntime(['doctor'], fixture);
    await vi.waitFor(() => expect(lease.spawnLocked).toHaveBeenCalledOnce());
    expect(fixture.loadVerifiedArtifactBinding).not.toHaveBeenCalled();
    expect(fixture.loadBundledArtifactBinding).toHaveBeenCalledOnce();
    expect(lease.verifyBeforeSpawn).toHaveBeenCalledOnce();
    expect(lease.spawnLocked).toHaveBeenCalledWith(['doctor'], {
      shell: false,
      stdio: 'inherit',
      windowsHide: true,
      env: process.env,
    });
    expect(fixture.spawnRuntime).not.toHaveBeenCalled();
    child.emit('exit', 0, null);
    await expect(result).resolves.toBe(0);
  });

  it.each([
    [[]],
    [['doctor', '--id', 'other']],
    [['--help', 'doctor']],
    [['--id', 'other', 'doctor']],
  ])('does not broaden the policy-independent diagnostic allowlist: %j', async (args) => {
    const fixture = host({
      loadVerifiedArtifactBinding: vi.fn(async () => { throw new Error('offline'); }),
    });
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await expect(launchNativeRuntime(args, fixture)).resolves.toBe(1);
    expect(fixture.loadVerifiedArtifactBinding).toHaveBeenCalledOnce();
    expect(fixture.spawnRuntime).not.toHaveBeenCalled();
    write.mockRestore();
  });

  it.each(['--help', '-h', '--version', '-V', 'doctor'])(
    'never starts tampered native code for offline diagnostic %s',
    async (diagnostic) => {
      const hashFile = vi.fn()
        .mockReturnValueOnce('a'.repeat(64))
        .mockReturnValueOnce('b'.repeat(64));
      const fixture = host({ hashFile });
      const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      await expect(launchNativeRuntime([diagnostic], fixture)).resolves.toBe(1);
      expect(fixture.loadBundledArtifactBinding).toHaveBeenCalledOnce();
      expect(fixture.spawnRuntime).not.toHaveBeenCalled();
      expect(write).toHaveBeenCalledWith(expect.stringContaining('integrity verification'));
      write.mockRestore();
    },
  );

  it('spawns Windows MCP from the verified cache and retains its lease until exit', async () => {
    const child = childProcess();
    Object.assign(child, { pid: 4321 });
    const lease = fakeWindowsLease('C:\\cache\\v1\\win32-x64\\0.1.0\\hash\\palladin-client.exe');
    vi.mocked(lease.spawnLocked).mockReturnValue(child);
    const fixture = host({
      platform: 'win32',
      architecture: 'x64',
      resolvePackageJson: vi.fn(() => windowsPackageJson),
      prepareWindowsRuntime: vi.fn(() => lease),
      spawnRuntime: vi.fn(() => child),
    });
    const result = launchNativeRuntime(['mcp', 'serve'], fixture);
    await vi.waitFor(() => expect(lease.spawnLocked).toHaveBeenCalledOnce());
    expect(lease.verifyBeforeSpawn).toHaveBeenCalledOnce();
    expect(lease.spawnLocked).toHaveBeenCalledWith(['mcp', 'serve'], {
      shell: false,
      stdio: 'inherit',
      windowsHide: true,
      env: process.env,
    });
    expect(fixture.spawnRuntime).not.toHaveBeenCalled();
    expect(lease.bindToChild).toHaveBeenCalledWith(4321);
    expect(lease.release).not.toHaveBeenCalled();
    child.emit('exit', 0, null);
    await expect(result).resolves.toBe(0);
    expect(lease.release).toHaveBeenCalledOnce();
  });

  it('fails closed if the runtime changes between signed policy verification and spawn', async () => {
    const hashFile = vi.fn()
      .mockReturnValueOnce('a'.repeat(64))
      .mockReturnValueOnce('b'.repeat(64));
    const fixture = host({ hashFile });
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await expect(launchNativeRuntime(['status'], fixture)).resolves.toBe(1);
    expect(fixture.spawnRuntime).not.toHaveBeenCalled();
    expect(write).toHaveBeenCalledWith(expect.stringContaining('integrity verification'));
    write.mockRestore();
  });

  it('blocks a signed-policy downgrade before creating a Windows cache entry or process', async () => {
    const fixture = host({
      platform: 'win32',
      architecture: 'x64',
      resolvePackageJson: vi.fn(() => windowsPackageJson),
      loadVerifiedArtifactBinding: vi.fn(async () => {
        throw new Error('version is below the signed security floor');
      }),
    });
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await expect(launchNativeRuntime(['mcp', 'serve'], fixture)).resolves.toBe(1);
    expect(fixture.prepareWindowsRuntime).not.toHaveBeenCalled();
    expect(fixture.spawnRuntime).not.toHaveBeenCalled();
    expect(write).toHaveBeenCalledWith(expect.stringContaining('signed version policy'));
    write.mockRestore();
  });

  it('honors a verified dynamic block before any identity-bearing spawn', async () => {
    const fixture = host();
    const defaultLoader = fixture.loadVerifiedArtifactBinding;
    fixture.loadVerifiedArtifactBinding = vi.fn(async (request) => ({
      ...(await defaultLoader(request)),
      runtimeAllowed: false,
    }));
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await expect(launchNativeRuntime(['status'], fixture)).resolves.toBe(1);
    expect(fixture.spawnRuntime).not.toHaveBeenCalled();
    expect(write).toHaveBeenCalledWith(expect.stringContaining('signed version policy'));
    write.mockRestore();
  });

  it('forwards termination signals to the native child and removes its handler', async () => {
    const child = childProcess();
    const handlers = new Map<NodeJS.Signals, () => void>();
    const fixture = host({
      spawnRuntime: vi.fn(() => child),
      addSignalHandler: vi.fn((signal, handler) => handlers.set(signal, handler)),
      removeSignalHandler: vi.fn((signal) => handlers.delete(signal)),
    });
    const result = launchNativeRuntime([], fixture);
    await vi.waitFor(() => expect(fixture.spawnRuntime).toHaveBeenCalledOnce());
    expect(handlers.has('SIGTERM')).toBe(true);
    handlers.get('SIGTERM')?.();
    expect(child.kill).toHaveBeenCalledWith('SIGTERM');
    child.emit('exit', 0, null);
    await expect(result).resolves.toBe(0);
    expect(handlers.has('SIGTERM')).toBe(false);
  });

  it('propagates the native exit code', async () => {
    const child = childProcess();
    const fixture = host({ spawnRuntime: vi.fn(() => child) });
    const result = launchNativeRuntime(['doctor'], fixture);
    await vi.waitFor(() => expect(fixture.spawnRuntime).toHaveBeenCalledOnce());
    child.emit('exit', 78, null);
    await expect(result).resolves.toBe(78);
  });
});
