import { spawn, type ChildProcess } from 'node:child_process';
import {
  constants as fsConstants,
  accessSync,
  closeSync,
  openSync,
  readSync,
  realpathSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { posix as darwinPath, win32 as windowsPath } from 'node:path';

const DARWIN_RUNTIME_PACKAGE = '@palladin/runtime-darwin-universal';
const BUNDLE_EXECUTABLE = ['PalladinRuntime.app', 'Contents', 'MacOS', 'palladin'] as const;
const WINDOWS_RUNTIME_PACKAGES = {
  arm64: '@palladin/runtime-win32-arm64',
  x64: '@palladin/runtime-win32-x64',
} as const;
const WINDOWS_CLIENT_EXECUTABLE = ['bin', 'palladin-client.exe'] as const;
const LINUX_RUNTIME_PACKAGES = {
  glibc: {
    arm64: '@palladin/runtime-linux-arm64-gnu',
    x64: '@palladin/runtime-linux-x64-gnu',
  },
  musl: {
    arm64: '@palladin/runtime-linux-arm64-musl',
    x64: '@palladin/runtime-linux-x64-musl',
  },
} as const;
const LINUX_CLIENT_EXECUTABLE = ['bin', 'palladin-linux-client'] as const;
const FORWARDED_SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'] as const;
const ELF_PREFIX_LIMIT = 1024 * 1024;
const ELF64_PROGRAM_HEADER_BYTES = 56;
const PT_INTERP = 3;

export interface NativeDispatchHost {
  platform: NodeJS.Platform;
  architecture: string;
  linuxLibc?: LinuxLibc;
  resolvePackageJson(specifier: string): string;
  realpath(path: string): string;
  assertExecutable(path: string): void;
  spawnRuntime(path: string, args: readonly string[]): ChildProcess;
}

export type LinuxLibc = 'glibc' | 'musl' | 'unsupported';

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

  if (host.platform === 'linux') {
    if (host.architecture !== 'arm64' && host.architecture !== 'x64') {
      throw new Error(`Palladin native runtime does not support linux/${host.architecture}`);
    }

    if (host.linuxLibc === undefined || host.linuxLibc === 'unsupported') {
      throw new Error('Palladin native runtime does not support this Linux libc');
    }

    return resolvePackageExecutable(
      host,
      LINUX_RUNTIME_PACKAGES[host.linuxLibc][host.architecture],
      LINUX_CLIENT_EXECUTABLE,
      darwinPath,
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
    linuxLibc: process.platform === 'linux' ? detectSystemLinuxLibc() : undefined,
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

function detectSystemLinuxLibc(): LinuxLibc {
  let descriptor: number | undefined;
  try {
    // /proc/self/exe is a kernel-owned reference to the inode that is actually
    // executing. process.execPath can be atomically replaced during an upgrade.
    descriptor = openSync('/proc/self/exe', fsConstants.O_RDONLY);
    const prefix = Buffer.alloc(ELF_PREFIX_LIMIT);
    const length = readSync(descriptor, prefix, 0, prefix.length, 0);
    return detectLinuxLibcFromElf(prefix.subarray(0, length), process.arch);
  } catch {
    return 'unsupported';
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function detectLinuxLibcFromElf(bytes: Buffer, architecture: string): LinuxLibc {
  if (
    bytes.length < 64
    || bytes[0] !== 0x7f
    || bytes[1] !== 0x45
    || bytes[2] !== 0x4c
    || bytes[3] !== 0x46
    || bytes[4] !== 2
    || bytes[5] !== 1
  ) {
    return 'unsupported';
  }
  const programOffset = boundedNumber(bytes.readBigUInt64LE(32), bytes.length);
  const entrySize = bytes.readUInt16LE(54);
  const entryCount = bytes.readUInt16LE(56);
  if (
    programOffset === undefined
    || entrySize < ELF64_PROGRAM_HEADER_BYTES
    || entryCount === 0
    || entryCount > 128
    || programOffset + entrySize * entryCount > bytes.length
  ) {
    return 'unsupported';
  }
  let detected: LinuxLibc | undefined;
  for (let index = 0; index < entryCount; index += 1) {
    const entry = programOffset + index * entrySize;
    if (bytes.readUInt32LE(entry) !== PT_INTERP) continue;
    if (detected !== undefined) return 'unsupported';
    const interpreterOffset = boundedNumber(bytes.readBigUInt64LE(entry + 8), bytes.length);
    const interpreterLength = boundedNumber(bytes.readBigUInt64LE(entry + 32), 256);
    if (
      interpreterOffset === undefined
      || interpreterLength === undefined
      || interpreterLength < 2
      || interpreterOffset + interpreterLength > bytes.length
    ) {
      return 'unsupported';
    }
    const interpreter = bytes.subarray(interpreterOffset, interpreterOffset + interpreterLength);
    if (interpreter.at(-1) !== 0 || interpreter.subarray(0, -1).includes(0)) {
      return 'unsupported';
    }
    detected = classifyLinuxInterpreter(
      interpreter.subarray(0, -1).toString('utf8'),
      architecture,
    );
  }
  return detected ?? 'unsupported';
}

function classifyLinuxInterpreter(interpreter: string, architecture: string): LinuxLibc {
  if (architecture === 'x64') {
    if (interpreter === '/lib64/ld-linux-x86-64.so.2') return 'glibc';
    if (interpreter === '/lib/ld-musl-x86_64.so.1') return 'musl';
  }
  if (architecture === 'arm64') {
    if (interpreter === '/lib/ld-linux-aarch64.so.1') return 'glibc';
    if (interpreter === '/lib/ld-musl-aarch64.so.1') return 'musl';
  }
  return 'unsupported';
}

function boundedNumber(value: bigint, maximum: number): number | undefined {
  if (value > BigInt(maximum)) return undefined;
  return Number(value);
}

function safeError(error: unknown): string {
  if (!(error instanceof Error)) return 'Palladin native runtime is unavailable';
  if (error.message.startsWith('Palladin native runtime')) return error.message;
  return 'Palladin native runtime package is missing or invalid; reinstall @palladin/agent';
}
