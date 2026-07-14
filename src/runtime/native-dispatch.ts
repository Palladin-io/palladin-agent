import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import {
  constants as fsConstants,
  accessSync,
  closeSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { posix as darwinPath, win32 as windowsPath } from 'node:path';

import {
  loadBundledVerifiedArtifactBinding,
  loadSystemVerifiedArtifactBinding,
  type VerifiedArtifactBinding,
  type VersionPolicyRequest,
} from './version-policy.js';
import { RUNTIME_SOURCE_SHA } from './version-policy-build.js';
import {
  prepareWindowsRuntimeCache,
  sha256File,
  type WindowsRuntimeLease,
  type WindowsRuntimeSource,
} from './windows-runtime-cache.js';

const DARWIN_RUNTIME_PACKAGES = {
  arm64: '@palladin/runtime-darwin-arm64',
  x64: '@palladin/runtime-darwin-x64',
} as const;
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
const NATIVE_RUNTIME_VERSION = '0.1.0';

export interface NativeDispatchHost {
  platform: NodeJS.Platform;
  architecture: string;
  linuxLibc?: LinuxLibc;
  resolvePackageJson(specifier: string): string;
  realpath(path: string): string;
  assertExecutable(path: string): void;
  readPackageManifest(path: string): unknown;
  hashFile(path: string): string;
  loadVerifiedArtifactBinding(request: VersionPolicyRequest): Promise<VerifiedArtifactBinding>;
  loadBundledArtifactBinding(request: VersionPolicyRequest): Promise<VerifiedArtifactBinding>;
  prepareWindowsRuntime(
    source: WindowsRuntimeSource,
    binding: VerifiedArtifactBinding,
  ): WindowsRuntimeLease;
  spawnRuntime(path: string, args: readonly string[], options: SpawnOptions): ChildProcess;
  addSignalHandler(signal: NodeJS.Signals, handler: () => void): void;
  removeSignalHandler(signal: NodeJS.Signals, handler: () => void): void;
}

export type LinuxLibc = 'glibc' | 'musl' | 'unsupported';

interface ResolvedNativeRuntime {
  packageName: string;
  executable: string;
}

export function resolveNativeRuntime(host: NativeDispatchHost): string {
  return resolveNativeRuntimeSource(host).executable;
}

function resolveNativeRuntimeSource(host: NativeDispatchHost): ResolvedNativeRuntime {
  if (host.platform === 'darwin') {
    if (host.architecture !== 'arm64' && host.architecture !== 'x64') {
      throw new Error(`Palladin native runtime does not support darwin/${host.architecture}`);
    }

    return resolvePackageExecutable(
      host,
      DARWIN_RUNTIME_PACKAGES[host.architecture],
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
): ResolvedNativeRuntime {
  let resolvedPackageJson: string;
  try {
    resolvedPackageJson = host.resolvePackageJson(`${packageName}/package.json`);
  } catch {
    throw new Error(
      `Palladin native runtime package ${packageName}@${NATIVE_RUNTIME_VERSION} is unavailable; reinstall @palladin/agent@${NATIVE_RUNTIME_VERSION} without --omit=optional. For an offline install, prefill the npm cache or registry proxy with both exact tarballs`,
    );
  }
  const packageJson = host.realpath(resolvedPackageJson);
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
  validatePackageManifest(host.readPackageManifest(packageJson), packageName, host);
  return { packageName, executable };
}

export async function launchNativeRuntime(
  args: readonly string[],
  host: NativeDispatchHost = systemHost(),
): Promise<number> {
  let runtime: ResolvedNativeRuntime;
  try {
    runtime = resolveNativeRuntimeSource(host);
  } catch (error) {
    process.stderr.write(`Error: ${safeError(error)}\n`);
    return 1;
  }

  const policyIndependentDiagnostic = isPolicyIndependentDiagnostic(args);
  let binding: VerifiedArtifactBinding;
  try {
    const executableSha256 = host.hashFile(runtime.executable);
    const request = {
      packageName: runtime.packageName,
      version: NATIVE_RUNTIME_VERSION,
      executableSha256,
      sourceSha: RUNTIME_SOURCE_SHA,
    };
    // Exact identity-free diagnostics may bypass a dynamic policy outage or
    // revocation, but never artifact integrity. Their offline path still
    // verifies the release-bundled signed binding and exact source hash.
    binding = policyIndependentDiagnostic
      ? await host.loadBundledArtifactBinding(request)
      : await host.loadVerifiedArtifactBinding(request);
    assertExactBinding(
      runtime.packageName,
      executableSha256,
      binding,
      !policyIndependentDiagnostic,
    );
  } catch {
    process.stderr.write('Error: Palladin native runtime failed signed version policy verification\n');
    return 1;
  }

  let executable = runtime.executable;
  let windowsLease: WindowsRuntimeLease | undefined;
  try {
    if (host.platform === 'win32') {
      windowsLease = host.prepareWindowsRuntime({
        packageName: runtime.packageName,
        version: NATIVE_RUNTIME_VERSION,
        executable: runtime.executable,
      }, binding);
      windowsLease.verifyBeforeSpawn();
      executable = windowsLease.executable;
    } else if (host.hashFile(runtime.executable) !== binding.executableSha256) {
      throw new Error('runtime changed after policy verification');
    }
  } catch {
    windowsLease?.release();
    process.stderr.write('Error: Palladin native runtime failed integrity verification\n');
    return 1;
  }

  let child: ChildProcess;
  try {
    const options: SpawnOptions = {
      shell: false,
      stdio: 'inherit',
      windowsHide: true,
      ...(host.platform === 'win32' ? { env: process.env } : {}),
    };
    child = windowsLease === undefined
      ? host.spawnRuntime(executable, args, options)
      : windowsLease.spawnLocked(args, options);
    windowsLease?.bindToChild(child.pid);
  } catch {
    windowsLease?.release();
    process.stderr.write('Error: Palladin native runtime could not be started\n');
    return 1;
  }

  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signal of FORWARDED_SIGNALS) {
    const handler = (): void => {
      if (child.exitCode === null && child.signalCode === null) child.kill(signal);
    };
    handlers.set(signal, handler);
    host.addSignalHandler(signal, handler);
  }

  return await new Promise<number>((resolve) => {
    const cleanup = (): void => {
      for (const [signal, handler] of handlers) host.removeSignalHandler(signal, handler);
      windowsLease?.release();
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

function isPolicyIndependentDiagnostic(args: readonly string[]): boolean {
  return args.length === 1
    && (args[0] === '--help' || args[0] === '-h' || args[0] === '--version'
      || args[0] === '-V' || args[0] === 'doctor');
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
    readPackageManifest: (path) => JSON.parse(readFileSync(path, 'utf8')) as unknown,
    hashFile: sha256File,
    loadVerifiedArtifactBinding: (request) => loadSystemVerifiedArtifactBinding(request),
    loadBundledArtifactBinding: async (request) => loadBundledVerifiedArtifactBinding(request),
    prepareWindowsRuntime: (source, binding) => prepareWindowsRuntimeCache(source, binding),
    spawnRuntime: (path, args, options) => spawn(path, [...args], options),
    addSignalHandler: (signal, handler) => process.on(signal, handler),
    removeSignalHandler: (signal, handler) => process.off(signal, handler),
  };
}

function validatePackageManifest(
  value: unknown,
  packageName: string,
  host: NativeDispatchHost,
): void {
  if (!isRecord(value) || value.name !== packageName || value.version !== NATIVE_RUNTIME_VERSION
    || !exactStringArray(value.os, host.platform)
    || !exactStringArray(value.cpu, host.architecture)
    || Object.hasOwn(value, 'scripts') || Object.hasOwn(value, 'dependencies')
    || Object.hasOwn(value, 'optionalDependencies')) {
    throw new Error('Palladin native runtime package manifest is invalid');
  }
  if (host.platform === 'linux') {
    if (host.linuxLibc === undefined || host.linuxLibc === 'unsupported'
      || !exactStringArray(value.libc, host.linuxLibc)) {
      throw new Error('Palladin native runtime package manifest is invalid');
    }
  } else if (Object.hasOwn(value, 'libc')) {
    throw new Error('Palladin native runtime package manifest is invalid');
  }
}

function assertExactBinding(
  packageName: string,
  executableSha256: string,
  binding: VerifiedArtifactBinding,
  requireAllowed: boolean,
): void {
  if (binding.packageName !== packageName || binding.version !== NATIVE_RUNTIME_VERSION
    || binding.executableSha256 !== executableSha256
    || binding.sourceSha !== RUNTIME_SOURCE_SHA
    || (requireAllowed && !binding.runtimeAllowed)) {
    throw new Error('Palladin native runtime binding is invalid');
  }
}

function exactStringArray(value: unknown, expected: string): boolean {
  return Array.isArray(value) && value.length === 1 && value[0] === expected;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
  return 'Palladin native runtime package is missing or invalid; reinstall @palladin/agent without --omit=optional and ensure npm has online proxy/cache access to @palladin packages';
}
