import { spawn, type ChildProcess } from 'node:child_process';
import { constants as fsConstants, accessSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { posix as darwinPath, win32 as windowsPath } from 'node:path';

const DARWIN_RUNTIME_PACKAGE = '@palladin/runtime-darwin-universal';
const BUNDLE_EXECUTABLE = ['PalladinRuntime.app', 'Contents', 'MacOS', 'palladin'] as const;
const WINDOWS_RUNTIME_PACKAGES = {
  arm64: '@palladin/runtime-win32-arm64',
  x64: '@palladin/runtime-win32-x64',
} as const;
const WINDOWS_CLIENT_EXECUTABLE = ['bin', 'palladin-client.exe'] as const;
const FORWARDED_SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'] as const;

export interface NativeDispatchHost {
  platform: NodeJS.Platform;
  architecture: string;
  resolvePackageJson(specifier: string): string;
  realpath(path: string): string;
  assertExecutable(path: string): void;
  spawnRuntime(path: string, args: readonly string[]): ChildProcess;
}

export function resolveNativeRuntime(host: NativeDispatchHost): string {
  if (host.platform === 'darwin') {
    if (host.architecture !== 'arm64' && host.architecture !== 'x64') {
      throw new Error(`Palladin native runtime does not support darwin/${host.architecture}`);
    }

    return resolvePackageExecutable(
      host,
      DARWIN_RUNTIME_PACKAGE,
      BUNDLE_EXECUTABLE,
      darwinPath,
    );
  }

  if (host.platform === 'win32') {
    if (host.architecture !== 'arm64' && host.architecture !== 'x64') {
      throw new Error(`Palladin native runtime does not support win32/${host.architecture}`);
    }

    return resolvePackageExecutable(
      host,
      WINDOWS_RUNTIME_PACKAGES[host.architecture],
      WINDOWS_CLIENT_EXECUTABLE,
      windowsPath,
    );
  }

  throw new Error(`Palladin native runtime is not installed for ${host.platform}/${host.architecture}`);
}

function resolvePackageExecutable(
  host: NativeDispatchHost,
  packageName: string,
  executableSegments: readonly string[],
  pathApi: typeof darwinPath,
): string {
  const packageJson = host.realpath(host.resolvePackageJson(`${packageName}/package.json`));
  const packageRoot = pathApi.dirname(packageJson);
  const executable = host.realpath(pathApi.join(packageRoot, ...executableSegments));
  const pathFromPackage = pathApi.relative(packageRoot, executable);
  if (
    pathFromPackage === ''
    || pathFromPackage === '..'
    || pathFromPackage.startsWith(`..${pathApi.sep}`)
    || pathApi.isAbsolute(pathFromPackage)
  ) {
    throw new Error('Palladin native runtime resolved outside its platform package');
  }
  host.assertExecutable(executable);
  return executable;
}

export async function launchNativeRuntime(
  args: readonly string[],
  host: NativeDispatchHost = systemHost(),
): Promise<number> {
  let executable: string;
  try {
    executable = resolveNativeRuntime(host);
  } catch (error) {
    process.stderr.write(`Error: ${safeError(error)}\n`);
    return 1;
  }

  let child: ChildProcess;
  try {
    child = host.spawnRuntime(executable, args);
  } catch {
    process.stderr.write('Error: Palladin native runtime could not be started\n');
    return 1;
  }

  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signal of FORWARDED_SIGNALS) {
    const handler = (): void => {
      if (child.exitCode === null && child.signalCode === null) child.kill(signal);
    };
    handlers.set(signal, handler);
    process.on(signal, handler);
  }

  return await new Promise<number>((resolve) => {
    const cleanup = (): void => {
      for (const [signal, handler] of handlers) process.off(signal, handler);
    };
    child.once('error', () => {
      cleanup();
      process.stderr.write('Error: Palladin native runtime terminated before startup\n');
      resolve(1);
    });
    child.once('exit', (code, signal) => {
      cleanup();
      if (signal !== null) {
        process.stderr.write(`Error: Palladin native runtime terminated by ${signal}\n`);
        resolve(1);
        return;
      }
      resolve(code ?? 1);
    });
  });
}

function systemHost(): NativeDispatchHost {
  const require = createRequire(import.meta.url);
  return {
    platform: process.platform,
    architecture: process.arch,
    resolvePackageJson: (specifier) => require.resolve(specifier),
    realpath: realpathSync,
    assertExecutable: (path) => accessSync(path, fsConstants.X_OK),
    spawnRuntime: (path, args) => spawn(path, [...args], {
      shell: false,
      stdio: 'inherit',
      windowsHide: true,
    }),
  };
}

function safeError(error: unknown): string {
  if (!(error instanceof Error)) return 'Palladin native runtime is unavailable';
  if (error.message.startsWith('Palladin native runtime')) return error.message;
  return 'Palladin native runtime package is missing or invalid; reinstall @palladin/agent';
}
