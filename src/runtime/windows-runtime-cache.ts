import {
  execFileSync,
  spawn,
  type ChildProcess,
  type SpawnOptions,
} from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  constants as fsConstants,
  closeSync,
  copyFileSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, win32 as windowsPath } from 'node:path';

import type { VerifiedArtifactBinding } from './version-policy.js';

const SHA256 = /^[0-9a-f]{64}$/;
const EXACT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const WINDOWS_PACKAGE = /^@palladin\/runtime-win32-(arm64|x64)$/;
const THUMBPRINT = /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/;
const CACHE_SCHEMA = 'v1';
const CLIENT_FILENAME = 'palladin-client.exe';
const LEASE = /^(?:launcher|child)-(\d+)-[0-9a-f-]{36}\.lease$/;
const MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024;
const SYSTEM_ROOT = '\\\\?\\GLOBALROOT\\SystemRoot';
const SYSTEM_POWERSHELL = '\\\\?\\GLOBALROOT\\SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

export interface WindowsRuntimeSource {
  packageName: string;
  version: string;
  executable: string;
}

export interface WindowsRuntimeLease {
  readonly executable: string;
  verifyBeforeSpawn(): void;
  spawnLocked(args: readonly string[], options: SpawnOptions): ChildProcess;
  bindToChild(childProcessId: number | undefined): void;
  release(): void;
}

export interface WindowsRuntimeCacheOptions {
  cacheRoot?: string;
  processId?: number;
  randomId?: () => string;
  processIsAlive?: (processId: number) => boolean;
  verifyAuthenticode?: (path: string, binding: VerifiedArtifactBinding) => void;
}

/**
 * Copy the signed Windows launcher into a version/hash-specific public cache.
 *
 * npm may replace a platform package while an MCP process is still running.
 * Windows locks loaded executables, so the runtime must never execute directly
 * from node_modules. Cache entries contain no Agent state or credentials.
 */
export function prepareWindowsRuntimeCache(
  source: WindowsRuntimeSource,
  binding: VerifiedArtifactBinding,
  options: WindowsRuntimeCacheOptions = {},
): WindowsRuntimeLease {
  validateBinding(source, binding);
  const verifyAuthenticode = options.verifyAuthenticode ?? verifySystemAuthenticode;
  const expectedHash = binding.executableSha256;
  verifyHash(source.executable, expectedHash);

  const cacheRoot = canonicalCacheRoot(
    options.cacheRoot ?? systemCacheRoot(),
    options.cacheRoot === undefined,
  );
  const packageDirectory = join(cacheRoot, CACHE_SCHEMA, packageSegment(source.packageName));
  const versionDirectory = join(packageDirectory, source.version);
  ensurePlainDirectory(join(cacheRoot, CACHE_SCHEMA));
  ensurePlainDirectory(packageDirectory);
  ensurePlainDirectory(versionDirectory);

  const entryDirectory = join(versionDirectory, expectedHash);
  const cachedExecutable = join(entryDirectory, CLIENT_FILENAME);
  if (existsSync(entryDirectory)) {
    assertPlainDirectory(entryDirectory);
    verifyHash(cachedExecutable, expectedHash);
  } else {
    installCacheEntry(
      source.executable,
      entryDirectory,
      cachedExecutable,
      expectedHash,
      options.randomId ?? randomUUID,
    );
  }

  // Re-check the source after policy lookup/copy. A concurrent npm update must
  // fail this launch rather than mix files from two package versions.
  verifyHash(source.executable, expectedHash);

  const processId = options.processId ?? process.pid;
  const randomId = options.randomId ?? randomUUID;
  const leaseDirectory = join(cacheRoot, CACHE_SCHEMA, 'leases', entryIdentity(source, binding));
  ensurePlainDirectory(join(cacheRoot, CACHE_SCHEMA, 'leases'));
  ensurePlainDirectory(leaseDirectory);
  let leasePath = createLease(leaseDirectory, 'launcher', processId, randomId());
  let released = false;

  collectInactiveEntries(
    cacheRoot,
    entryDirectory,
    options.processIsAlive ?? systemProcessIsAlive,
  );

  return {
    executable: cachedExecutable,
    verifyBeforeSpawn(): void {
      if (released) throw new Error('Palladin Windows runtime lease is closed');
      verifyFile(cachedExecutable, expectedHash, binding, verifyAuthenticode);
    },
    spawnLocked(args, spawnOptions): ChildProcess {
      if (released) throw new Error('Palladin Windows runtime lease is closed');
      return spawnLockedSystemRuntime(
        cachedExecutable,
        expectedHash,
        binding,
        args,
        spawnOptions,
      );
    },
    bindToChild(childProcessId): void {
      if (released || childProcessId === undefined || !Number.isSafeInteger(childProcessId)
        || childProcessId <= 0) return;
      try {
        const childLease = createLease(leaseDirectory, 'child', childProcessId, randomId());
        removeLease(leasePath);
        leasePath = childLease;
      } catch {
        // The launcher lease remains valid while it waits for the child. A
        // locked executable is retained even if the lease conversion fails.
      }
    },
    release(): void {
      if (released) return;
      released = true;
      removeLease(leasePath);
      removeEmptyDirectory(leaseDirectory);
    },
  };
}

export function sha256File(path: string): string {
  const descriptor = openSync(path, fsConstants.O_RDONLY);
  try {
    const size = fstatSync(descriptor).size;
    if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_EXECUTABLE_BYTES) {
      throw new Error('Palladin Windows runtime size is invalid');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    while (position < size) {
      const length = readSync(descriptor, buffer, 0, Math.min(buffer.length, size - position), position);
      if (length <= 0) throw new Error('Palladin Windows runtime could not be read');
      hash.update(buffer.subarray(0, length));
      position += length;
    }
    return hash.digest('hex');
  } finally {
    closeSync(descriptor);
  }
}

function validateBinding(source: WindowsRuntimeSource, binding: VerifiedArtifactBinding): void {
  if (!WINDOWS_PACKAGE.test(source.packageName) || !EXACT_VERSION.test(source.version)
    || binding.packageName !== source.packageName || binding.version !== source.version
    || !SHA256.test(binding.executableSha256)
    || typeof binding.authenticodePublisher !== 'string'
    || binding.authenticodePublisher.trim() === ''
    || binding.authenticodePublisher.length > 256
    || [...binding.authenticodePublisher].some((character) => character < ' ' || character > '~')
    || typeof binding.authenticodeThumbprint !== 'string'
    || !THUMBPRINT.test(binding.authenticodeThumbprint)) {
    throw new Error('Palladin Windows runtime binding is invalid');
  }
}

function verifyFile(
  path: string,
  expectedHash: string,
  binding: VerifiedArtifactBinding,
  verifyAuthenticode: (path: string, binding: VerifiedArtifactBinding) => void,
): void {
  verifyHash(path, expectedHash);
  const canonical = realpathSync(path);
  verifyAuthenticode(canonical, binding);
  verifyHash(canonical, expectedHash);
}

function verifyHash(path: string, expectedHash: string): void {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error('Palladin Windows runtime is not a regular file');
  }
  const canonical = realpathSync(path);
  if (sha256File(canonical) !== expectedHash) {
    throw new Error('Palladin Windows runtime hash verification failed');
  }
}

function installCacheEntry(
  sourceExecutable: string,
  entryDirectory: string,
  cachedExecutable: string,
  expectedHash: string,
  randomId: () => string,
): void {
  const versionDirectory = dirname(entryDirectory);
  const temporary = join(versionDirectory, `.${expectedHash}.${randomId()}.tmp`);
  const temporaryExecutable = join(temporary, CLIENT_FILENAME);
  try {
    mkdirSync(temporary, { recursive: false, mode: 0o700 });
    copyFileSync(sourceExecutable, temporaryExecutable, fsConstants.COPYFILE_EXCL);
    syncFile(temporaryExecutable);
    verifyHash(temporaryExecutable, expectedHash);
    try {
      renameSync(temporary, entryDirectory);
    } catch (error) {
      if (!existsSync(entryDirectory)) throw error;
    }
    assertPlainDirectory(entryDirectory);
    verifyHash(cachedExecutable, expectedHash);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function verifySystemAuthenticode(path: string, binding: VerifiedArtifactBinding): void {
  const publisher = binding.authenticodePublisher;
  const thumbprint = binding.authenticodeThumbprint;
  if (publisher === undefined || thumbprint === undefined) {
    throw new Error('Palladin Windows runtime Authenticode binding is missing');
  }
  const { powershell, root: canonicalRoot, modulePath } = trustedPowerShell();
  const script = [
    "$ErrorActionPreference = 'Stop'",
    'Import-Module -Name Microsoft.PowerShell.Security -ErrorAction Stop',
    '$signature = Get-AuthenticodeSignature -LiteralPath $env:PALLADIN_RUNTIME_PATH',
    "$actualThumbprint = $signature.SignerCertificate.Thumbprint.Replace(' ', '').ToUpperInvariant()",
    "if ($signature.Status -ne 'Valid') { exit 41 }",
    'if ($actualThumbprint -cne $env:PALLADIN_EXPECTED_THUMBPRINT) { exit 42 }',
    'if ($signature.SignerCertificate.Subject -cne $env:PALLADIN_EXPECTED_PUBLISHER) { exit 43 }',
    'if ($null -eq $signature.TimeStamperCertificate) { exit 44 }',
  ].join('; ');
  try {
    execFileSync(powershell, [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      script,
    ], {
      encoding: 'utf8',
      shell: false,
      stdio: 'ignore',
      timeout: 10_000,
      windowsHide: true,
      env: {
        SystemRoot: canonicalRoot,
        PSModulePath: modulePath,
        PALLADIN_RUNTIME_PATH: path,
        PALLADIN_EXPECTED_PUBLISHER: publisher,
        PALLADIN_EXPECTED_THUMBPRINT: thumbprint,
      },
    });
  } catch {
    throw new Error('Palladin Windows runtime Authenticode verification failed');
  }
}

function spawnLockedSystemRuntime(
  path: string,
  expectedHash: string,
  binding: VerifiedArtifactBinding,
  args: readonly string[],
  spawnOptions: SpawnOptions,
): ChildProcess {
  const publisher = binding.authenticodePublisher;
  const thumbprint = binding.authenticodeThumbprint;
  if (publisher === undefined || thumbprint === undefined) {
    throw new Error('Palladin Windows runtime Authenticode binding is missing');
  }
  const { powershell, root, modulePath } = trustedPowerShell();
  const commandLine = [path, ...args].map(quoteWindowsArgument).join(' ');
  const lockedProcessSource = String.raw`
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class PalladinLockedProcess {
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint INFINITE = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass, IntPtr information, uint length);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcess(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    public static int Run(string path, string commandLine) {
        IntPtr job = IntPtr.Zero;
        IntPtr information = IntPtr.Zero;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        bool assigned = false;
        try {
            job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int size = Marshal.SizeOf(limits);
            information = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(limits, information, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, information, (uint)size)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            var startup = new STARTUPINFO();
            startup.cb = (uint)Marshal.SizeOf(startup);
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = GetStdHandle(-10);
            startup.hStdOutput = GetStdHandle(-11);
            startup.hStdError = GetStdHandle(-12);
            if (!CreateProcess(path, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, true,
                CREATE_SUSPENDED, IntPtr.Zero, null, ref startup, out process)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (!AssignProcessToJobObject(job, process.hProcess)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            assigned = true;
            if (ResumeThread(process.hThread) == 0xFFFFFFFF) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (WaitForSingleObject(process.hProcess, INFINITE) != 0) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            uint exitCode;
            if (!GetExitCodeProcess(process.hProcess, out exitCode)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return unchecked((int)exitCode);
        } finally {
            if (!assigned && process.hProcess != IntPtr.Zero) TerminateProcess(process.hProcess, 1);
            if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
            if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
            if (information != IntPtr.Zero) Marshal.FreeHGlobal(information);
            if (job != IntPtr.Zero) CloseHandle(job);
        }
    }
}`;
  const script = [
    "$ErrorActionPreference = 'Stop'",
    'Import-Module -Name Microsoft.PowerShell.Security -ErrorAction Stop',
    '$path = $env:PALLADIN_RUNTIME_PATH',
    '$stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)',
    'try {',
    '  $sha = [Security.Cryptography.SHA256]::Create()',
    '  try { $actualHash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "").ToLowerInvariant() } finally { $sha.Dispose() }',
    '  if ($actualHash -cne $env:PALLADIN_EXPECTED_SHA256) { exit 51 }',
    '  $signature = Get-AuthenticodeSignature -LiteralPath $path',
    "  if ($signature.Status -ne 'Valid') { exit 52 }",
    "  $actualThumbprint = $signature.SignerCertificate.Thumbprint.Replace(' ', '').ToUpperInvariant()",
    '  if ($actualThumbprint -cne $env:PALLADIN_EXPECTED_THUMBPRINT) { exit 53 }',
    '  if ($signature.SignerCertificate.Subject -cne $env:PALLADIN_EXPECTED_PUBLISHER) { exit 54 }',
    '  if ($null -eq $signature.TimeStamperCertificate) { exit 55 }',
    `  $source = @'\n${lockedProcessSource}\n'@`,
    '  Add-Type -TypeDefinition $source -Language CSharp',
    '  $commandLine = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PALLADIN_RUNTIME_COMMAND_LINE))',
    "  foreach ($name in @('PALLADIN_RUNTIME_PATH', 'PALLADIN_RUNTIME_COMMAND_LINE', 'PALLADIN_EXPECTED_SHA256', 'PALLADIN_EXPECTED_PUBLISHER', 'PALLADIN_EXPECTED_THUMBPRINT')) { Remove-Item -LiteralPath \"Env:$name\" -ErrorAction SilentlyContinue }",
    '  exit [PalladinLockedProcess]::Run($path, $commandLine)',
    '} finally { $stream.Dispose() }',
  ].join('\n');
  const encodedScript = Buffer.from(script, 'utf16le').toString('base64');
  return spawn(powershell, [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-EncodedCommand',
    encodedScript,
  ], {
    ...spawnOptions,
    shell: false,
    windowsHide: true,
    env: {
      ...(spawnOptions.env ?? process.env),
      SystemRoot: root,
      PSModulePath: modulePath,
      PALLADIN_RUNTIME_PATH: path,
      PALLADIN_RUNTIME_COMMAND_LINE: Buffer.from(commandLine, 'utf8').toString('base64'),
      PALLADIN_EXPECTED_SHA256: expectedHash,
      PALLADIN_EXPECTED_PUBLISHER: publisher,
      PALLADIN_EXPECTED_THUMBPRINT: thumbprint,
    },
  });
}

export function quoteWindowsArgument(value: string): string {
  if (value.includes('\0')) throw new Error('Palladin Windows runtime argument is invalid');
  if (value !== '' && !/[\s"]/u.test(value)) return value;
  let quoted = '"';
  let backslashes = 0;
  for (const character of value) {
    if (character === '\\') {
      backslashes += 1;
    } else if (character === '"') {
      quoted += '\\'.repeat(backslashes * 2 + 1);
      quoted += '"';
      backslashes = 0;
    } else {
      quoted += '\\'.repeat(backslashes);
      quoted += character;
      backslashes = 0;
    }
  }
  quoted += '\\'.repeat(backslashes * 2);
  return `${quoted}"`;
}

function trustedPowerShell(): { powershell: string; root: string; modulePath: string } {
  const rootHint = process.env.SystemRoot;
  if (rootHint === undefined || !windowsPath.isAbsolute(rootHint)) {
    throw new Error('Palladin Windows system root is unavailable');
  }
  const root = realpathSync(rootHint);
  if (!sameFileIdentity(root, SYSTEM_ROOT, 'directory')) {
    throw new Error('Palladin Windows system root is invalid');
  }
  const powershell = realpathSync(windowsPath.join(
    root,
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  ));
  if (!sameFileIdentity(powershell, SYSTEM_POWERSHELL, 'file')) {
    throw new Error('Palladin Windows signature verifier is invalid');
  }
  const pathFromRoot = windowsPath.relative(root, powershell);
  if (pathFromRoot.toLowerCase()
    !== 'system32\\windowspowershell\\v1.0\\powershell.exe') {
    throw new Error('Palladin Windows signature verifier is invalid');
  }
  const modulePath = windowsPath.join(
    root,
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'Modules',
  );
  if (!sameFileIdentity(modulePath, `${SYSTEM_ROOT}\\System32\\WindowsPowerShell\\v1.0\\Modules`, 'directory')) {
    throw new Error('Palladin Windows PowerShell module path is invalid');
  }
  return { powershell, root, modulePath };
}

function sameFileIdentity(
  candidate: string,
  kernelPath: string,
  kind: 'directory' | 'file',
): boolean {
  const candidateDescriptor = openSync(candidate, fsConstants.O_RDONLY);
  try {
    const kernelDescriptor = openSync(kernelPath, fsConstants.O_RDONLY);
    try {
      const candidateMetadata = fstatSync(candidateDescriptor, { bigint: true });
      const kernelMetadata = fstatSync(kernelDescriptor, { bigint: true });
      const expectedKind = kind === 'directory'
        ? candidateMetadata.isDirectory() && kernelMetadata.isDirectory()
        : candidateMetadata.isFile() && kernelMetadata.isFile();
      return expectedKind
        && candidateMetadata.ino !== 0n
        && candidateMetadata.dev === kernelMetadata.dev
        && candidateMetadata.ino === kernelMetadata.ino;
    } finally {
      closeSync(kernelDescriptor);
    }
  } finally {
    closeSync(candidateDescriptor);
  }
}

function canonicalCacheRoot(root: string, requireWindowsAbsolute: boolean): string {
  if (requireWindowsAbsolute && !windowsPath.isAbsolute(root)) {
    throw new Error('Palladin Windows runtime cache path is invalid');
  }
  mkdirSync(root, { recursive: true, mode: 0o700 });
  assertPlainDirectory(root);
  return realpathSync(root);
}

function systemCacheRoot(): string {
  const localAppData = process.env.LOCALAPPDATA;
  if (localAppData === undefined || !windowsPath.isAbsolute(localAppData)) {
    throw new Error('Palladin Windows runtime cache is unavailable');
  }
  return windowsPath.join(localAppData, 'Palladin', 'RuntimeCache');
}

function packageSegment(packageName: string): string {
  const match = WINDOWS_PACKAGE.exec(packageName);
  if (match?.[1] === undefined) throw new Error('Palladin Windows runtime package is invalid');
  return `win32-${match[1]}`;
}

function entryIdentity(source: WindowsRuntimeSource, binding: VerifiedArtifactBinding): string {
  return createHash('sha256')
    .update(`${source.packageName}\0${source.version}\0${binding.executableSha256}`, 'utf8')
    .digest('hex');
}

function ensurePlainDirectory(path: string): void {
  try {
    mkdirSync(path, { recursive: false, mode: 0o700 });
  } catch (error) {
    if (!existsSync(path)) throw error;
  }
  assertPlainDirectory(path);
}

function assertPlainDirectory(path: string): void {
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error('Palladin Windows runtime cache contains an invalid path');
  }
}

function syncFile(path: string): void {
  // Windows requires a write-capable handle for FlushFileBuffers (fsync).
  // This path is the private temporary copy and is closed before hashing and
  // the atomic rename, so granting this handle write access does not weaken
  // the verified executable binding.
  const descriptor = openSync(path, fsConstants.O_RDWR);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function createLease(
  leaseDirectory: string,
  kind: 'launcher' | 'child',
  processId: number,
  randomId: string,
): string {
  if (!Number.isSafeInteger(processId) || processId <= 0
    || !/^[0-9a-f-]{36}$/.test(randomId)) {
    throw new Error('Palladin Windows runtime lease is invalid');
  }
  const path = join(leaseDirectory, `${kind}-${processId}-${randomId}.lease`);
  writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
  return path;
}

function removeLease(path: string): boolean {
  try {
    unlinkSync(path);
    return true;
  } catch {
    // Unknown or undeletable leases force retention during collection.
    return !existsSync(path);
  }
}

function collectInactiveEntries(
  cacheRoot: string,
  currentEntry: string,
  processIsAlive: (processId: number) => boolean,
): void {
  const schemaRoot = join(cacheRoot, CACHE_SCHEMA);
  for (const packageEntry of safeDirectories(schemaRoot)) {
    if (packageEntry !== 'win32-arm64' && packageEntry !== 'win32-x64') continue;
    const packageDirectory = join(schemaRoot, packageEntry);
    for (const version of safeDirectories(packageDirectory)) {
      if (!EXACT_VERSION.test(version)) continue;
      const versionDirectory = join(packageDirectory, version);
      for (const hash of safeDirectories(versionDirectory)) {
        if (!SHA256.test(hash)) continue;
        const entryDirectory = join(versionDirectory, hash);
        if (samePath(entryDirectory, currentEntry)) continue;
        const identity = createHash('sha256')
          .update(`@palladin/runtime-${packageEntry}\0${version}\0${hash}`, 'utf8')
          .digest('hex');
        const leaseDirectory = join(schemaRoot, 'leases', identity);
        if (hasActiveLease(leaseDirectory, processIsAlive)) continue;
        try {
          rmSync(entryDirectory, { recursive: true, force: false });
          removeEmptyDirectory(versionDirectory);
          removeEmptyDirectory(packageDirectory);
          removeEmptyDirectory(leaseDirectory);
        } catch {
          // A loaded Windows image remains locked. Leaving it in place is the
          // safe outcome; a later launch retries collection.
        }
      }
    }
  }
}

function hasActiveLease(
  leaseDirectory: string,
  processIsAlive: (processId: number) => boolean,
): boolean {
  if (!existsSync(leaseDirectory)) return false;
  assertPlainDirectory(leaseDirectory);
  let active = false;
  for (const file of readdirSync(leaseDirectory)) {
    const match = LEASE.exec(file);
    if (match?.[1] === undefined) {
      active = true;
      continue;
    }
    const processId = Number(match[1]);
    if (processIsAlive(processId)) {
      active = true;
      continue;
    }
    if (!removeLease(join(leaseDirectory, file))) active = true;
  }
  return active;
}

function systemProcessIsAlive(processId: number): boolean {
  try {
    process.kill(processId, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function safeDirectories(path: string): string[] {
  if (!existsSync(path)) return [];
  assertPlainDirectory(path);
  return readdirSync(path, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && !entry.isSymbolicLink())
    .map((entry) => entry.name);
}

function removeEmptyDirectory(path: string): void {
  try {
    if (existsSync(path) && readdirSync(path).length === 0) rmSync(path, { recursive: false });
  } catch {
    // Concurrent launch or collector owns this directory now.
  }
}

function samePath(left: string, right: string): boolean {
  return relative(left, right) === '' && relative(right, left) === '';
}
