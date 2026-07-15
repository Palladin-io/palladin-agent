#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, canonicalSha256, loadManifest, validateManifest } from './report.mjs';

const SOURCE_SHA = /^[0-9a-f]{40}$/;
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_CAPTURE = 256 * 1024;
function fail(message) { throw new Error(message); }
function record(value, label) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}
function exactKeys(value, keys, label) {
  const actual = Object.keys(record(value, label)).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has an invalid shape`);
}
function readRegular(path, label) {
  const absolute = resolve(path);
  const descriptor = openSync(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor); const linked = lstatSync(absolute);
    if (!opened.isFile() || linked.isSymbolicLink() || opened.dev !== linked.dev || opened.ino !== linked.ino) {
      fail(`${label} must be an unchanged regular file`);
    }
    return readFileSync(descriptor);
  } finally { closeSync(descriptor); }
}
function readJson(path, label) {
  try { return JSON.parse(readRegular(path, label).toString('utf8')); }
  catch (error) { fail(`${label} is invalid: ${error instanceof Error ? error.message : 'unknown error'}`); }
}
function sha256Bytes(value) { return createHash('sha256').update(value).digest('hex'); }
function sha256File(path) { return sha256Bytes(readRegular(path, `artifact ${basename(path)}`)); }
function writeAtomic(path, value) {
  const absolute = resolve(path); mkdirSync(dirname(absolute), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(absolute), `.${basename(absolute)}.${randomUUID()}.tmp`);
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, absolute);
  } finally { rmSync(temporary, { force: true }); }
}
function safeEnvironment(home, prefix) {
  const source = process.env;
  const allowed = process.platform === 'win32'
    ? ['SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP']
    : ['LANG', 'LC_ALL', 'TERM', 'TMPDIR',
      ...(process.platform === 'darwin' ? ['PALLADIN_APPLICATION_IDENTIFIER', 'PALLADIN_KEYCHAIN_ACCESS_GROUP'] : [])];
  const environment = Object.fromEntries(allowed.filter((key) => source[key] !== undefined).map((key) => [key, source[key]]));
  environment.HOME = home;
  environment.USERPROFILE = home;
  environment.PATH = process.platform === 'win32'
    ? `${source.SystemRoot}\\System32;${dirname(process.execPath)};${prefix}`
    : `/usr/bin:/bin:/usr/sbin:/sbin:${dirname(process.execPath)}:${join(prefix, 'bin')}`;
  environment.npm_config_cache = join(home, '.npm-cache');
  environment.npm_config_loglevel = 'error';
  environment.npm_config_audit = 'false';
  environment.npm_config_fund = 'false';
  return environment;
}
function npmExecutable() { return process.platform === 'win32' ? 'npm.cmd' : 'npm'; }
function bounded(command, args, { cwd, env, input, expected = 0, timeout = 180_000 } = {}) {
  const result = spawnSync(command, args, {
    cwd, env, input, encoding: null, shell: false, windowsHide: true, timeout,
    maxBuffer: MAX_CAPTURE,
  });
  if (input?.fill) input.fill(0);
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.alloc(0);
  if (stdout.length > MAX_CAPTURE || stderr.length > MAX_CAPTURE || result.error || result.status !== expected) {
    stdout.fill(0); stderr.fill(0); fail('a bounded lifecycle command failed');
  }
  return { stdout, stderr };
}
function boundedInheritedInput(command, args, { cwd, env, expected = 0, timeout = 180_000 } = {}) {
  const result = spawnSync(command, args, {
    cwd, env, encoding: null, shell: false, windowsHide: true, timeout,
    maxBuffer: MAX_CAPTURE, stdio: ['inherit', 'pipe', 'pipe'],
  });
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.alloc(0);
  if (stdout.length > MAX_CAPTURE || stderr.length > MAX_CAPTURE || result.error || result.status !== expected) {
    stdout.fill(0); stderr.fill(0); fail('a bounded lifecycle command failed');
  }
  return { stdout, stderr };
}
function assertNoApiKeyEmission(captures) {
  for (const capture of captures) {
    if (/\bpl_[A-Za-z0-9_-]{8,}/.test(capture.toString('utf8'))) {
      capture.fill(0);
      fail('a lifecycle command attempted to emit API-key-shaped input');
    }
  }
}
function captureText(capture) {
  const stdout = capture.stdout.toString('utf8');
  const stderr = capture.stderr.toString('utf8');
  capture.stdout.fill(0); capture.stderr.fill(0);
  return { stdout, stderr };
}
function artifactMap(manifest, directory, sourceSha, version, label) {
  if (manifest.sourceSha !== sourceSha || manifest.version !== version || !Array.isArray(manifest.artifacts)) {
    fail(`${label} manifest binding is invalid`);
  }
  const result = new Map();
  for (const item of manifest.artifacts) {
    const artifact = record(item, `${label} artifact`);
    if (typeof artifact.filename !== 'string' || basename(artifact.filename) !== artifact.filename
      || typeof artifact.sha256 !== 'string' || !SHA256.test(artifact.sha256)) fail(`${label} artifact is invalid`);
    const path = join(directory, artifact.filename);
    if (sha256File(path) !== artifact.sha256) fail(`${label} artifact digest is invalid`);
    result.set(artifact.filename, { path, sha256: artifact.sha256 });
  }
  return result;
}
function expectedNames(target, version) {
  const arch = target.arch;
  if (target.os === 'macos') return {
    agent: `palladin-agent-${version}.tgz`, platform: `palladin-runtime-darwin-${arch}-${version}.tgz`,
    extraRole: 'signed-runtime', extra: 'palladin-runtime-darwin-universal.zip',
  };
  if (target.os === 'windows') return {
    agent: `palladin-agent-${version}.tgz`, platform: `palladin-runtime-win32-${arch}-${version}.tgz`,
    extraRole: 'signed-installer', extra: `palladin-runtime-setup-${arch}-${version}.zip`,
  };
  if (target.distribution === 'alpine-3.22') return {
    agent: `palladin-agent-${version}.tgz`, platform: `palladin-runtime-linux-${arch}-musl-${version}.tgz`,
  };
  if (target.distribution === 'fedora-42') return {
    agent: `palladin-agent-${version}.tgz`, platform: `palladin-runtime-linux-${arch}-gnu-${version}.tgz`,
    extraRole: 'rpm', extra: `palladin-runtime-${version}-1.${arch === 'arm64' ? 'aarch64' : 'x86_64'}.rpm`,
  };
  return {
    agent: `palladin-agent-${version}.tgz`, platform: `palladin-runtime-linux-${arch}-gnu-${version}.tgz`,
    extraRole: 'deb', extra: `palladin-runtime_${version}_${arch === 'arm64' ? 'arm64' : 'amd64'}.deb`,
  };
}
function loadPhase(contract, target, phase) {
  const entry = record(contract.phases[phase], `contract.phases.${phase}`);
  exactKeys(entry, ['version', 'sourceSha', 'directory'], `contract.phases.${phase}`);
  if (!VERSION.test(entry.version) || !SOURCE_SHA.test(entry.sourceSha)) fail(`contract.phases.${phase} is invalid`);
  const directory = resolve(entry.directory);
  const platform = artifactMap(readJson(join(directory, 'release-manifest.json'), `${phase} platform manifest`), directory, entry.sourceSha, entry.version, `${phase} platform`);
  const agent = artifactMap(readJson(join(directory, 'release-manifest-agent.json'), `${phase} agent manifest`), directory, entry.sourceSha, entry.version, `${phase} agent`);
  const names = expectedNames(target, entry.version);
  const required = [
    ['agent-npm', names.agent, agent], ['platform-npm', names.platform, platform],
    ...(names.extra ? [[names.extraRole, names.extra, platform]] : []),
  ];
  const artifacts = required.map(([role, filename, source]) => {
    const found = source.get(filename); if (!found) fail(`${phase} ${role} is missing`);
    return { phase, role, version: entry.version, sourceSha: entry.sourceSha, filename, sha256: found.sha256, path: found.path };
  });
  return { version: entry.version, sourceSha: entry.sourceSha, artifacts };
}
function versionOutput(capture, expected) {
  const text = capture.stdout.toString('utf8').trim();
  capture.stdout.fill(0); capture.stderr.fill(0);
  if (text !== `palladin ${expected}` && text !== expected) fail('installed runtime version is invalid');
}
function requirePinnedNpm(env) {
  const version = captureText(bounded(npmExecutable(), ['--version'], { env }));
  if (version.stdout.trim() !== '11.18.0' || version.stderr !== '') fail('physical lifecycle requires npm 11.18.0');
}
function verifyMacBundle(app, phase, env) {
  bounded('/bin/bash', [resolve('packaging/macos/scripts/verify-bundle.sh'), '--app', app, '--architecture', 'universal'], {
    env, timeout: 300_000,
  });
  const version = captureText(bounded('/usr/libexec/PlistBuddy', [
    '-c', 'Print :CFBundleShortVersionString', join(app, 'Contents', 'Info.plist'),
  ], { env }));
  if (version.stdout.trim() !== phase.version || version.stderr !== '') fail('signed macOS runtime bundle version is invalid');
  return sha256File(join(app, 'Contents', 'MacOS', 'palladin'));
}
function installNativeExtra(target, phase, env, work) {
  const extra = phase.artifacts.find((artifact) => !['agent-npm', 'platform-npm'].includes(artifact.role));
  if (!extra || target.distribution === 'alpine-3.22') return null;
  if (target.os === 'macos') {
    const destination = join(work, `signed-runtime-${phase.version}`);
    mkdirSync(destination, { mode: 0o700 });
    bounded('/usr/bin/ditto', ['-x', '-k', extra.path, destination], { env, timeout: 300_000 });
    const entries = readdirSync(destination);
    const app = join(destination, 'PalladinRuntime.app');
    if (entries.length !== 1 || entries[0] !== 'PalladinRuntime.app'
      || !lstatSync(app).isDirectory() || lstatSync(app).isSymbolicLink()) {
      fail('signed macOS runtime archive has an invalid shape');
    }
    const binary = join(app, 'Contents', 'MacOS', 'palladin');
    const binarySha256 = verifyMacBundle(app, phase, env);
    versionOutput(bounded(binary, ['--version'], { env }), phase.version);
    return { role: extra.role, binarySha256 };
  }
  if (target.os === 'windows') {
    const destination = join(work, `setup-${phase.version}`);
    mkdirSync(destination, { mode: 0o700 });
    bounded('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      'Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1]; & (Join-Path $args[1] "palladin-runtime-setup.exe"); if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }',
      extra.path, destination], { env, timeout: 600_000 });
  } else if (extra.role === 'deb') {
    bounded('sudo', ['--non-interactive', 'apt-get', 'install', '--yes', extra.path], { env, timeout: 600_000 });
  } else {
    bounded('sudo', ['--non-interactive', 'dnf', 'install', '--assumeyes', extra.path], { env, timeout: 600_000 });
  }
  assertNativeExtraInstalled(target, phase, env);
  return { role: extra.role };
}
function npmInstall(phase, prefix, env) {
  const agent = phase.artifacts.find((item) => item.role === 'agent-npm').path;
  const platform = phase.artifacts.find((item) => item.role === 'platform-npm').path;
  bounded(npmExecutable(), ['install', '--global', '--ignore-scripts', '--prefix', prefix, agent, platform], { env, timeout: 300_000 });
}
function npmUninstall(phase, prefix, env) {
  bounded(npmExecutable(), ['uninstall', '--global', '--ignore-scripts', '--prefix', prefix,
    '@palladin/agent', platformPackageName(phase)], { env, timeout: 300_000 });
}
function globalRoot(prefix, env) {
  const capture = bounded(npmExecutable(), ['root', '--global', '--prefix', prefix], { env });
  const value = capture.stdout.toString('utf8').trim(); capture.stdout.fill(0); capture.stderr.fill(0);
  if (!value) fail('npm global root is unavailable'); return value;
}
function platformPackageName(phase) {
  const platform = phase.artifacts.find((item) => item.role === 'platform-npm');
  return `@palladin/${platform.filename.replace(/^palladin-|-[0-9]+\.[0-9]+\.[0-9]+\.tgz$/g, '')}`;
}
function platformDirectory(phase, prefix, env) {
  return join(globalRoot(prefix, env), ...platformPackageName(phase).split('/'));
}
function verifyNativeExtraBinding(target, phase, installedExtra, prefix, env) {
  if (target.os !== 'macos' || installedExtra?.role !== 'signed-runtime') return;
  const packagedApp = join(platformDirectory(phase, prefix, env), 'PalladinRuntime.app');
  if (verifyMacBundle(packagedApp, phase, env) !== installedExtra.binarySha256) {
    fail('npm package runtime does not match the verified signed macOS runtime');
  }
}
function installPhase(target, phase, prefix, env, work) {
  const installedExtra = installNativeExtra(target, phase, env, work);
  npmInstall(phase, prefix, env);
  verifyNativeExtraBinding(target, phase, installedExtra, prefix, env);
}
function assertLinuxNativePayloadAbsent() {
  for (const path of ['/usr/lib/palladin/runtime', '/usr/lib/systemd/system/palladin-runtime.service',
    '/usr/lib/systemd/system/palladin-executor.socket', '/usr/lib/systemd/system/palladin-executor@.service',
    '/usr/lib/sysusers.d/palladin-runtime.conf', '/usr/lib/tmpfiles.d/palladin-runtime.conf',
    '/usr/share/polkit-1/actions/io.palladin.runtime.policy', '/run/palladin-runtime/broker.sock']) {
    if (existsSync(path)) fail('Linux native runtime package left an installed payload');
  }
}
function windowsPackageAssertionScript(target, phase) {
  const version = phase ? `${phase.version}.0` : null;
  const architecture = target.arch === 'arm64' ? 'Arm64' : 'X64';
  return [
    "$ErrorActionPreference = 'Stop'",
    ...(phase ? [`$expectedVersion = '${version}'`, `$expectedArchitecture = '${architecture}'`] : []),
    "$names = @('Palladin.Runtime.Companion', 'Palladin.Runtime.Broker')",
    'foreach ($name in $names) {',
    '  $packages = @(Get-AppxPackage -AllUsers -PackageTypeFilter Main -Name $name)',
    ...(phase ? [
      "  if ($packages.Count -ne 1) { throw 'Palladin Runtime MSIX package count is invalid' }",
      "  if ([string]$packages[0].Version -cne $expectedVersion -or [string]$packages[0].Architecture -cne $expectedArchitecture) { throw 'Palladin Runtime MSIX identity is invalid' }",
    ] : ["  if ($packages.Count -ne 0) { throw 'Palladin Runtime MSIX package remains installed' }"]),
    '}',
    ...(phase ? [
      "$services = @(Get-CimInstance Win32_Service -Filter \"Name='PalladinRuntime'\")",
      "if ($services.Count -ne 1 -or $services[0].State -cne 'Running') { throw 'PalladinRuntime service is not installed and running' }",
    ] : [
      "$services = @(Get-CimInstance Win32_Service -Filter \"Name='PalladinRuntime'\")",
      "if ($services.Count -ne 0) { throw 'PalladinRuntime service remains installed' }",
      "$provisioned = @(Get-AppxProvisionedPackage -Online | Where-Object DisplayName -in $names)",
      "if ($provisioned.Count -ne 0) { throw 'Palladin Runtime provisioned package remains installed' }",
    ]),
  ].join('\n');
}
function assertNativeExtraAbsent(target, env) {
  if (target.os === 'windows') {
    bounded('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      windowsPackageAssertionScript(target, null)], { env });
  } else if (target.os === 'linux' && target.distribution !== 'alpine-3.22') {
    if (target.distribution === 'fedora-42') bounded('rpm', ['--query', '--quiet', 'palladin-runtime'], { env, expected: 1 });
    else bounded('dpkg-query', ['--show', 'palladin-runtime'], { env, expected: 1 });
    assertLinuxNativePayloadAbsent();
  }
}
function assertNativeExtraInstalled(target, phase, env) {
  if (target.os === 'windows') {
    bounded('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      windowsPackageAssertionScript(target, phase)], { env });
  } else if (target.os === 'linux' && target.distribution !== 'alpine-3.22') {
    if (target.distribution === 'fedora-42') {
      const expected = `${phase.version}\t${target.arch === 'arm64' ? 'aarch64' : 'x86_64'}`;
      const result = captureText(bounded('rpm', ['--query', '--queryformat', '%{VERSION}\t%{ARCH}', 'palladin-runtime'], { env }));
      if (result.stdout !== expected || result.stderr !== '') fail('installed RPM identity is invalid');
    } else {
      const expected = `${phase.version}\t${target.arch === 'arm64' ? 'arm64' : 'amd64'}\tii `;
      const result = captureText(bounded('dpkg-query', ['--show', '--showformat=${Version}\t${Architecture}\t${db:Status-Abbrev}', 'palladin-runtime'], { env }));
      if (result.stdout !== expected || result.stderr !== '') fail('installed DEB identity is invalid');
    }
    for (const path of ['/usr/lib/palladin/runtime', '/usr/lib/systemd/system/palladin-runtime.service',
      '/usr/lib/systemd/system/palladin-executor.socket', '/usr/lib/systemd/system/palladin-executor@.service']) {
      if (!existsSync(path)) fail('installed Linux native runtime payload is incomplete');
    }
    if (!existsSync('/run/palladin-runtime/broker.sock')) fail('installed Linux native runtime broker socket is unavailable');
  }
}
function uninstallNativeExtra(target, phase, env) {
  const extra = phase.artifacts.find((artifact) => !['agent-npm', 'platform-npm'].includes(artifact.role));
  if (!extra || target.os === 'macos' || target.distribution === 'alpine-3.22') return;
  assertNativeExtraInstalled(target, phase, env);
  if (target.os === 'windows') {
    const script = [
      "$ErrorActionPreference = 'Stop'",
      "$service = Get-Service -Name PalladinRuntime -ErrorAction SilentlyContinue",
      'if ($null -ne $service) { Stop-Service -Name PalladinRuntime -Force -ErrorAction Stop }',
      "foreach ($name in @('Palladin.Runtime.Companion', 'Palladin.Runtime.Broker')) {",
      '  foreach ($package in @(Get-AppxPackage -AllUsers -PackageTypeFilter Main -Name $name)) {',
      '    Remove-AppxPackage -AllUsers -Package $package.PackageFullName -Confirm:$false -ErrorAction Stop',
      '  }',
      '}',
    ].join('\n');
    bounded('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], { env, timeout: 600_000 });
    assertNativeExtraAbsent(target, env);
  } else if (extra.role === 'deb') {
    bounded('sudo', ['--non-interactive', 'apt-get', 'purge', '--yes', 'palladin-runtime'], { env, timeout: 600_000 });
    bounded('dpkg-query', ['--show', 'palladin-runtime'], { env, expected: 1 });
  } else {
    bounded('sudo', ['--non-interactive', 'dnf', 'remove', '--assumeyes', 'palladin-runtime'], { env, timeout: 600_000 });
    bounded('rpm', ['--query', '--quiet', 'palladin-runtime'], { env, expected: 1 });
  }
  if (target.os === 'linux') {
    bounded('sudo', ['--non-interactive', 'systemctl', 'daemon-reload'], { env });
    for (const unit of ['palladin-runtime.service', 'palladin-executor.socket', 'palladin-executor@.service']) {
      const result = captureText(bounded('systemctl', ['show', '--property=LoadState', '--value', unit], { env }));
      if (result.stdout.trim() !== 'not-found' || result.stderr !== '') fail('Linux native runtime unit remains loaded');
    }
    assertLinuxNativePayloadAbsent();
  }
}
function launcher(prefix) { return process.platform === 'win32' ? join(prefix, 'palladin.cmd') : join(prefix, 'bin', 'palladin'); }
function runCli(prefix, env, args, options = {}) { return bounded(launcher(prefix), args, { env, ...options }); }
function versionCheck(prefix, env, expected) {
  versionOutput(runCli(prefix, env, ['--version']), expected);
}
function shellCompatibilityCheck(prefix, env, expected) {
  const commands = process.platform === 'win32'
    ? [
      [env.COMSPEC ?? 'cmd.exe', ['/d', '/s', '/c', '""%PALLADIN_LIFECYCLE_LAUNCHER%" --version"']],
      ['powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '& $env:PALLADIN_LIFECYCLE_LAUNCHER --version']],
    ]
    : [
      ['/bin/sh', ['-c', '"$1" --version', 'palladin-lifecycle-shell', launcher(prefix)]],
      ...(existsSync('/bin/bash') ? [['/bin/bash', ['-c', '"$1" --version', 'palladin-lifecycle-shell', launcher(prefix)]]] : []),
      ...(existsSync('/bin/zsh') ? [['/bin/zsh', ['-c', '"$1" --version', 'palladin-lifecycle-shell', launcher(prefix)]]] : []),
    ];
  const shellEnv = { ...env, PALLADIN_LIFECYCLE_LAUNCHER: launcher(prefix) };
  for (const [command, args] of commands) {
    const capture = bounded(command, args, { env: shellEnv });
    const text = capture.stdout.toString('utf8').trim(); capture.stdout.fill(0); capture.stderr.fill(0);
    if (text !== `palladin ${expected}` && text !== expected) fail('installed launcher shell compatibility is invalid');
  }
}
function identityDigest(prefix, env, home) {
  const capture = runCli(prefix, env, ['status']);
  capture.stdout.fill(0); capture.stderr.fill(0);
  const registry = readJson(join(home, '.palladin', 'registry.json'), 'public Agent registry');
  if (registry?.schemaVersion !== 3 || typeof registry.default !== 'string' || !Array.isArray(registry.agents)) {
    fail('public Agent registry is invalid');
  }
  const selected = registry.agents.find((item) => item?.name === registry.default);
  if (!selected || typeof selected.identityId !== 'string') fail('default Agent identity is unavailable');
  const config = readJson(
    join(home, '.palladin', 'identities', selected.identityId, 'config.json'),
    'public Agent config',
  );
  const identity = {
    identityId: config.identityId,
    organizationCredentialId: config.organizationCredentialId,
    agentId: config.agentId,
    encryptionPublicKey: config.encryptionPublicKey,
    signingPublicKey: config.signingPublicKey,
  };
  if (identity.identityId !== selected.identityId
    || Object.values(identity).some((value) => typeof value !== 'string' || value.length === 0)) {
    fail('public Agent identity is incomplete');
  }
  return sha256Bytes(Buffer.from(canonicalJson(identity), 'utf8'));
}
async function mcpCall(prefix, env, vaultId, entryId) {
  const child = spawn(launcher(prefix), ['mcp', 'serve'], { env, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let buffer = ''; let stderrBytes = 0; let nextId = 1; const waiting = new Map();
  child.stderr.on('data', (chunk) => { stderrBytes += chunk.length; if (stderrBytes > MAX_CAPTURE) child.kill(); });
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    if (Buffer.byteLength(buffer) > MAX_CAPTURE) { child.kill(); return; }
    for (;;) {
      const newline = buffer.indexOf('\n'); if (newline < 0) break;
      const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
      try { const message = JSON.parse(line); if (waiting.has(message.id)) { waiting.get(message.id)(message); waiting.delete(message.id); } } catch { child.kill(); }
    }
  });
  const request = (method, params) => new Promise((resolvePromise, reject) => {
    const id = nextId++; const timer = setTimeout(() => reject(new Error('MCP timeout')), 300_000);
    waiting.set(id, (value) => { clearTimeout(timer); resolvePromise(value); });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
  try {
    const initialized = await request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'palladin-lifecycle-gate', version: '1' } });
    if (initialized.error) fail('MCP initialization failed');
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    const result = await request('tools/call', { name: 'exec_with_credential', arguments: {
      vaultId, entryId, command: [process.execPath, '-e', 'process.exit(0)'], wait: '5m', progress: 'none',
    } });
    const content = result?.result?.content;
    if (result?.error || result?.result?.isError === true || !Array.isArray(content) || content.length !== 1
      || typeof content[0]?.text !== 'string') fail('grant-backed MCP operation failed');
    const body = JSON.parse(content[0].text);
    if (body.exitCode !== 0 || body.output !== 'withheld') fail('grant-backed MCP operation did not complete safely');
    return sha256Bytes(Buffer.from(canonicalJson({
      operation: 'exec_with_credential', vaultId, entryId,
      result: { exitCode: body.exitCode, output: body.output },
    }), 'utf8'));
  } finally {
    child.stdin.end(); child.kill(); buffer = '';
  }
}
function step(run, id, versionBefore, versionAfter, identityBefore, identityAfter, grantsBefore, grantsAfter, flags = {}) {
  const order = run.steps.length + 1;
  return {
    stepId: id, order, result: 'passed', observedAt: new Date().toISOString(),
    evidenceRef: `github-actions://runs/${run.runId}/attempts/${run.runAttempt}/targets/${run.targetId}/steps/${id}`,
    versionBefore, versionAfter, identityFingerprintBefore: identityBefore, identityFingerprintAfter: identityAfter,
    grantSetDigestBefore: grantsBefore, grantSetDigestAfter: grantsAfter,
    rollbackMode: flags.rollbackMode ?? null,
    concurrentMcpVerified: flags.concurrentMcpVerified ?? false,
    repairVerified: flags.repairVerified ?? false,
    downgradeRejected: flags.downgradeRejected ?? false,
    purgeVerified: flags.purgeVerified ?? false,
  };
}
export async function runPhysicalTarget({ contract, manifest: manifestInput = loadManifest() }) {
  const manifest = validateManifest(manifestInput);
  exactKeys(contract, ['schemaVersion', 'sourceSha', 'runId', 'runAttempt', 'targetId', 'apiHost', 'vaultId', 'entryId', 'phases', 'output'], 'contract');
  if (contract.schemaVersion !== 1 || !SOURCE_SHA.test(contract.sourceSha) || !/^[1-9][0-9]*$/.test(contract.runId)
    || !Number.isSafeInteger(contract.runAttempt) || contract.runAttempt < 1
    || contract.apiHost !== 'https://api.stage.palladin.io'
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(contract.vaultId)
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(contract.entryId)) fail('contract binding is invalid');
  const target = manifest.targets.find((item) => item.id === contract.targetId); if (!target) fail('contract target is invalid');
  const nativeArch = process.arch === 'x64' ? 'x64' : process.arch === 'arm64' ? 'arm64' : 'unsupported';
  if ((target.os === 'macos' && process.platform !== 'darwin') || (target.os === 'windows' && process.platform !== 'win32')
    || (target.os === 'linux' && process.platform !== 'linux') || target.arch !== nativeArch) fail('physical runner does not match the target');
  const baseline = loadPhase(contract, target, 'baseline');
  const candidate = loadPhase(contract, target, 'candidate');
  const rollback = loadPhase(contract, target, 'forward-rollback');
  if (candidate.sourceSha !== contract.sourceSha) fail('candidate source is invalid');
  const root = join(dirname(resolve(contract.output)), `Palladin lifecycle ${target.id} zażółć`);
  const home = join(root, 'home'); const prefix = join(root, 'global prefix');
  mkdirSync(home, { recursive: true, mode: 0o700 }); mkdirSync(prefix, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') { chmodSync(home, 0o700); chmodSync(prefix, 0o700); }
  const env = safeEnvironment(home, prefix);
  const run = { targetId: target.id, runId: contract.runId, runAttempt: contract.runAttempt, steps: [] };
  try {
    requirePinnedNpm(env);
    assertNativeExtraAbsent(target, env);
    installPhase(target, baseline, prefix, env, root); versionCheck(prefix, env, baseline.version);
    shellCompatibilityCheck(prefix, env, baseline.version);
    run.steps.push(step(run, 'install', null, baseline.version, null, null, null, null));
    runCli(prefix, env, ['init']);
    const connect = boundedInheritedInput(launcher(prefix), ['connect', '--api-key-stdin', '--host', contract.apiHost], { env });
    assertNoApiKeyEmission([connect.stdout, connect.stderr]); connect.stdout.fill(0); connect.stderr.fill(0);
    const identity = identityDigest(prefix, env, home);
    run.steps.push(step(run, 'enroll', baseline.version, baseline.version, null, identity, null, null));
    const grants = await mcpCall(prefix, env, contract.vaultId, contract.entryId);
    run.steps.push(step(run, 'mcp', baseline.version, baseline.version, identity, identity, null, grants));
    installPhase(target, candidate, prefix, env, root); versionCheck(prefix, env, candidate.version);
    const afterUpdate = identityDigest(prefix, env, home);
    run.steps.push(step(run, 'update', baseline.version, candidate.version, identity, afterUpdate, grants, grants));
    const concurrent = await Promise.all([mcpCall(prefix, env, contract.vaultId, contract.entryId), mcpCall(prefix, env, contract.vaultId, contract.entryId)]);
    if (concurrent.some((digest) => digest !== grants)) fail('concurrent MCP grant binding changed');
    run.steps.push(step(run, 'concurrent-mcp', candidate.version, candidate.version, afterUpdate, afterUpdate, grants, grants, { concurrentMcpVerified: true }));
    const candidatePlatformDirectory = platformDirectory(candidate, prefix, env);
    if (!existsSync(candidatePlatformDirectory)) fail('installed platform package is unavailable');
    const hidden = `${candidatePlatformDirectory}.missing`;
    renameSync(candidatePlatformDirectory, hidden);
    try {
      const missing = spawnSync(launcher(prefix), ['status'], { env, encoding: 'utf8', shell: false, timeout: 30_000 });
      if (missing.status === 0 || !/reinstall @palladin\/agent@/.test(`${missing.stdout}\n${missing.stderr}`)) fail('missing runtime repair guidance is invalid');
      npmInstall(candidate, prefix, env);
      if (!existsSync(candidatePlatformDirectory)) fail('npm reinstall did not repair the missing runtime');
    } finally {
      if (!existsSync(candidatePlatformDirectory) && existsSync(hidden)) renameSync(hidden, candidatePlatformDirectory);
      else rmSync(hidden, { recursive: true, force: true });
    }
    const afterRepair = identityDigest(prefix, env, home);
    if (await mcpCall(prefix, env, contract.vaultId, contract.entryId) !== grants) fail('repaired MCP grant binding changed');
    run.steps.push(step(run, 'repair', candidate.version, candidate.version, afterUpdate, afterRepair, grants, grants, { repairVerified: true }));
    npmInstall(baseline, prefix, env); const rejected = spawnSync(launcher(prefix), ['status'], { env, encoding: 'utf8', shell: false, timeout: 60_000 });
    if (rejected.error || rejected.signal !== null || rejected.status !== 1
      || rejected.stdout !== ''
      || rejected.stderr !== 'Error: Palladin native runtime version is blocked by signed version policy\n') {
      fail('literal downgrade did not produce the exact signed-policy rejection');
    }
    npmInstall(candidate, prefix, env); const afterRejected = identityDigest(prefix, env, home);
    run.steps.push(step(run, 'downgrade-rejected', candidate.version, candidate.version, afterRepair, afterRejected, grants, grants, { downgradeRejected: true }));
    installPhase(target, rollback, prefix, env, root); versionCheck(prefix, env, rollback.version);
    const afterRollback = identityDigest(prefix, env, home);
    if (await mcpCall(prefix, env, contract.vaultId, contract.entryId) !== grants) fail('rollback MCP grant binding changed');
    run.steps.push(step(run, 'rollback', candidate.version, rollback.version, afterRejected, afterRollback, grants, grants, { rollbackMode: 'forward-rebuild' }));
    npmUninstall(rollback, prefix, env); npmInstall(rollback, prefix, env); const afterReinstall = identityDigest(prefix, env, home);
    if (await mcpCall(prefix, env, contract.vaultId, contract.entryId) !== grants) fail('reinstalled MCP grant binding changed');
    run.steps.push(step(run, 'reinstall', rollback.version, rollback.version, afterRollback, afterReinstall, grants, grants));
    const purged = runCli(prefix, env, ['purge', '--confirm']);
    const purgeStdout = purged.stdout.toString('utf8');
    const purgeStderr = purged.stderr.toString('utf8');
    purged.stdout.fill(0); purged.stderr.fill(0);
    if (purgeStdout !== 'Native Palladin profiles and secret slots purged.\n'
      || purgeStderr !== '' || existsSync(join(home, '.palladin'))) {
      fail('purge did not confirm exact secret-slot deletion and remove the public Agent root');
    }
    run.steps.push(step(run, 'purge', rollback.version, rollback.version, afterReinstall, null, grants, null, { purgeVerified: true }));
    npmUninstall(rollback, prefix, env);
    if (existsSync(launcher(prefix))) fail('npm uninstall left the Agent launcher installed');
    const npmRoot = globalRoot(prefix, env);
    if (existsSync(join(npmRoot, '@palladin', 'agent')) || existsSync(platformDirectory(rollback, prefix, env))) {
      fail('npm uninstall left an Agent package installed');
    }
    uninstallNativeExtra(target, rollback, env);
    run.steps.push(step(run, 'uninstall', rollback.version, null, null, null, null, null));
    const artifacts = [baseline, candidate, rollback].flatMap((phase) => phase.artifacts.map(({ path: _, ...artifact }) => artifact));
    return {
      schemaVersion: 1, sourceSha: contract.sourceSha, manifestSha256: canonicalSha256(manifest),
      runId: contract.runId, runAttempt: contract.runAttempt, target: { targetId: target.id, artifacts, steps: run.steps },
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) fail('usage: run-physical-target.mjs CONTRACT_JSON');
    const contract = readJson(process.argv[2], 'contract');
    const output = await runPhysicalTarget({ contract });
    writeAtomic(contract.output, output);
    process.stdout.write(`lifecycle-target=${contract.targetId} result=passed\n`);
  } catch (error) {
    process.stderr.write(`physical lifecycle target failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  }
}
