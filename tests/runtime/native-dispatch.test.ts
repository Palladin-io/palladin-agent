import { EventEmitter } from 'node:events';
import type { ChildProcess } from 'node:child_process';
import { describe, expect, it, vi } from 'vitest';
import {
  launchNativeRuntime,
  resolveNativeRuntime,
  type NativeDispatchHost,
} from '../../src/runtime/native-dispatch.js';

const packageJson = '/fixture/node_modules/@palladin/runtime-darwin-universal/package.json';
const executable = '/fixture/node_modules/@palladin/runtime-darwin-universal/PalladinRuntime.app/Contents/MacOS/palladin';

function childProcess(): ChildProcess {
  const child = new EventEmitter() as ChildProcess;
  Object.assign(child, { exitCode: null, signalCode: null, kill: vi.fn(() => true) });
  return child;
}

function host(overrides: Partial<NativeDispatchHost> = {}): NativeDispatchHost {
  return {
    platform: 'darwin',
    architecture: 'arm64',
    resolvePackageJson: vi.fn(() => packageJson),
    realpath: vi.fn((path: string) => path),
    assertExecutable: vi.fn(),
    spawnRuntime: vi.fn(() => childProcess()),
    ...overrides,
  };
}

describe('native runtime dispatcher', () => {
  it.each(['arm64', 'x64'])('resolves the universal signed bundle for darwin/%s', (architecture) => {
    const fixture = host({ architecture });
    expect(resolveNativeRuntime(fixture)).toBe(executable);
    expect(fixture.resolvePackageJson).toHaveBeenCalledWith(
      '@palladin/runtime-darwin-universal/package.json',
    );
    expect(fixture.assertExecutable).toHaveBeenCalledWith(executable);
  });

  it('has no TypeScript, PATH, download, or unsupported-platform fallback', () => {
    const fixture = host({ platform: 'linux' });
    expect(() => resolveNativeRuntime(fixture)).toThrow('not installed for linux/arm64');
    expect(fixture.resolvePackageJson).not.toHaveBeenCalled();
    expect(fixture.spawnRuntime).not.toHaveBeenCalled();
  });

  it('rejects a symlinked executable escaping the platform package', () => {
    const fixture = host({
      realpath: vi.fn((path: string) => path.endsWith('/palladin') ? '/tmp/attacker' : path),
    });
    expect(() => resolveNativeRuntime(fixture)).toThrow('resolved outside');
    expect(fixture.assertExecutable).not.toHaveBeenCalled();
  });

  it('spawns the fixed executable without a shell and preserves argv as separate values', async () => {
    const child = childProcess();
    const fixture = host({ spawnRuntime: vi.fn(() => child) });
    const result = launchNativeRuntime(['get', 'entry;$(touch attacker)'], fixture);
    child.emit('exit', 0, null);
    await expect(result).resolves.toBe(0);
    expect(fixture.spawnRuntime).toHaveBeenCalledWith(executable, [
      'get',
      'entry;$(touch attacker)',
    ]);
  });

  it('propagates the native exit code', async () => {
    const child = childProcess();
    const fixture = host({ spawnRuntime: vi.fn(() => child) });
    const result = launchNativeRuntime(['doctor'], fixture);
    child.emit('exit', 78, null);
    await expect(result).resolves.toBe(78);
  });
});
