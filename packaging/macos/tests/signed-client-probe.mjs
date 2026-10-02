import { randomBytes } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync,
  readFileSync, readdirSync, realpathSync, writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

const [binaryInput, copiedBinaryInput, captureDirectoryInput] = process.argv.slice(2);
if (!binaryInput || !copiedBinaryInput || !captureDirectoryInput) {
  process.stderr.write('usage: signed-client-probe.mjs BINARY COPIED_BINARY CAPTURE_DIRECTORY\n');
  process.exit(64);
}

const binary = realpathSync(binaryInput);
const copiedBinary = realpathSync(copiedBinaryInput);
for (const candidate of [binary, copiedBinary]) {
  const stat = lstatSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0) {
    throw new Error('signed-client probe requires regular executable files');
  }
}

mkdirSync(captureDirectoryInput, { recursive: true, mode: 0o700 });
chmodSync(captureDirectoryInput, 0o700);
const canary = `palladin-boundary-${randomBytes(24).toString('hex')}`;
const maximumCaptureBytes = 1024 * 1024;
const maximumScannedFileBytes = 4 * 1024 * 1024;

function readOpenedRegular(path, expectedMetadata, label) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== expectedMetadata.dev || opened.ino !== expectedMetadata.ino) {
      throw new Error(`${label} changed during the bounded scan`);
    }
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function assertTreeDoesNotContainCanary(root, label) {
  if (!existsSync(root)) return;
  const rootMetadata = lstatSync(root);
  if (rootMetadata.isSymbolicLink()) throw new Error(`${label} contains a symbolic link`);
  const pending = [realpathSync(root)];
  let scannedBytes = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) throw new Error('canary scan state is invalid');
    const metadata = lstatSync(current);
    if (metadata.isSymbolicLink()) throw new Error(`${label} contains a symbolic link`);
    if (metadata.isDirectory()) {
      for (const entry of readdirSync(current)) pending.push(join(current, entry));
      continue;
    }
    if (!metadata.isFile() || metadata.size > maximumScannedFileBytes) {
      throw new Error(`${label} contains an unsupported file`);
    }
    scannedBytes += metadata.size;
    if (scannedBytes > maximumScannedFileBytes) throw new Error(`${label} exceeded the scan bound`);
    if (readOpenedRegular(current, metadata, label).includes(Buffer.from(canary))) {
      throw new Error(`${label} persisted the private boundary canary`);
    }
  }
}

function capture(name, stdout, stderr) {
  if (stdout.length + stderr.length > maximumCaptureBytes) {
    throw new Error('signed-client output exceeded its safe capture bound');
  }
  const combined = Buffer.concat([stdout, stderr]);
  if (combined.includes(Buffer.from(canary))) {
    throw new Error('signed-client output contained the private boundary canary');
  }
  writeFileSync(join(captureDirectoryInput, `${name}.stdout`), stdout, { mode: 0o600 });
  writeFileSync(join(captureDirectoryInput, `${name}.stderr`), stderr, { mode: 0o600 });
}

async function runBounded(name, executable, args, options = {}) {
  process.stderr.write(`Palladin signed-client probe stage: ${name}\n`);
  try {
    return await runBoundedCaptured(name, executable, args, options);
  } catch (error) {
    const reason = error instanceof Error ? ({
      'signed-client output exceeded its safe capture bound': 'capture-bound',
      'signed-client output contained the private boundary canary': 'canary-disclosure',
      'signed-client probe timed out': 'timeout',
    }[error.message] ?? 'probe-error') : 'probe-error';
    process.stderr.write(`Palladin signed-client probe failure: ${name}: ${reason}\n`);
    throw error;
  }
}

async function runBoundedCaptured(name, executable, args, options) {
  const child = spawn(executable, args, {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PALLADIN_BOUNDARY_PRIVATE_CANARY: canary },
  });
  const stdout = [];
  const stderr = [];
  let size = 0;
  let captureOverflowed = false;
  let initializationOutput = '';
  let initialized = false;
  const collect = (target, inspectInitialization = false) => (chunk) => {
    size += chunk.length;
    if (size > maximumCaptureBytes) {
      captureOverflowed = true;
      child.kill('SIGKILL');
    }
    else {
      target.push(Buffer.from(chunk));
      if (inspectInitialization && options.afterInitialize !== undefined && !initialized) {
        initializationOutput += chunk.toString('utf8');
        const newline = initializationOutput.indexOf('\n');
        if (newline !== -1) {
          let response;
          try { response = JSON.parse(initializationOutput.slice(0, newline)); } catch { /* fail closed below */ }
          if (response?.id === 1 && response?.result?.protocolVersion === '2025-11-25') {
            initialized = true;
            child.stdin.write(options.afterInitialize);
          }
        }
      }
    }
  };
  child.stdout.on('data', collect(stdout, true));
  child.stderr.on('data', collect(stderr));
  child.stdin.on('error', () => {});
  if (options.stdin !== undefined) child.stdin.write(options.stdin);
  if (options.keepStdinOpen !== true) child.stdin.end();
  if (options.interruptAfterMs !== undefined) {
    setTimeout(() => child.kill('SIGINT'), options.interruptAfterMs).unref();
  }
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill('SIGKILL');
  }, options.timeoutMs ?? 8_000);
  const result = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer);
  const stdoutBuffer = Buffer.concat(stdout);
  const stderrBuffer = Buffer.concat(stderr);
  if (captureOverflowed) throw new Error('signed-client output exceeded its safe capture bound');
  capture(name, stdoutBuffer, stderrBuffer);
  if (timedOut && options.acceptBoundedDenial !== true) throw new Error('signed-client probe timed out');
  return { ...result, timedOut, stdout: stdoutBuffer, stderr: stderrBuffer };
}

function assertAuthorizationDenial(name, result) {
  if (result.timedOut) {
    if (result.signal !== 'SIGKILL' || result.stdout.length !== 0 || result.stderr.length !== 0) {
      throw new Error(`${name} did not give a clean bounded denial`);
    }
    process.stderr.write(`Palladin signed-client probe result: ${name}: bounded-no-identity\n`);
    return;
  }
  const output = Buffer.concat([result.stdout, result.stderr]).toString('utf8');
  if (!output.includes('fresh operating-system authorization')) {
    const knownFailures = [
      ['profile does not exist; run: palladin agents create', 'profile-not-found'],
      ['Agent is not registered; run palladin status', 'agent-not-registered'],
      ['Agent is not active; approve it in Palladin', 'agent-not-active'],
      ['OS secure storage is unavailable; no file or environment fallback is allowed', 'secure-store-unavailable'],
      ['signed runtime release manifest is unavailable; no identity was opened', 'manifest-unavailable'],
      ['signed runtime release manifest verification failed; no identity was opened', 'manifest-invalid'],
      ['macOS Keychain operation failed (OSStatus ', 'keychain-operation-failed'],
    ];
    const reason = knownFailures.find(([message]) => output.includes(message))?.[1] ?? 'unexpected-output';
    process.stderr.write(`Palladin signed-client probe failure: ${name}: ${reason}\n`);
    throw new Error(`${name} failed before reaching the authenticated identity boundary`);
  }
}

const vault = '11111111111111111111111111111111';
const entry = '22222222222222222222222222222222';
// A fresh profile has no server configuration. Re-running init verifies its existing
// identity and reaches OS authorization without enrolling or contacting the API.
const blindArguments = ['init'];
for (const [name, executable] of [['genuine', binary], ['copied', copiedBinary]]) {
  const result = await runBounded(`blind-${name}`, executable, blindArguments, { acceptBoundedDenial: true });
  if (result.code === 0) throw new Error('blindly spawned signed runtime unexpectedly used an identity');
  assertAuthorizationDenial(`blind-${name}`, result);
}

const cancelled = await runBounded(
  'cancelled-connect',
  binary,
  ['connect', '--api-key-stdin'],
  { keepStdinOpen: true, interruptAfterMs: 300, timeoutMs: 5_000 },
);
if (cancelled.code === 0) throw new Error('cancelled signed-client request unexpectedly succeeded');

const initialize = JSON.stringify({
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'boundary-probe', version: '1' } },
});
const toolCall = JSON.stringify({
  jsonrpc: '2.0', id: 2, method: 'tools/call',
  params: { name: 'get_credential', arguments: { profile: 'default', vaultId: vault, entryId: entry, reason: 'noninteractive boundary probe', noWait: true } },
});
const afterInitialize = `${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n${toolCall}\n`;
const firstMcp = runBounded(
  'mcp-first-connection', binary, ['mcp', 'serve'],
  { stdin: `${initialize}\n`, afterInitialize, keepStdinOpen: true, interruptAfterMs: 1_500, timeoutMs: 5_000 },
);
const secondMcp = runBounded(
  'mcp-second-connection', binary, ['mcp', 'serve'],
  { stdin: `${initialize}\n`, afterInitialize, keepStdinOpen: true, interruptAfterMs: 1_500, timeoutMs: 5_000 },
);
const mcpResults = await Promise.all([firstMcp, secondMcp]);
for (const [index, result] of mcpResults.entries()) {
  const toolResponse = result.stdout.toString('utf8').split('\n').filter(Boolean).map((line) => {
    try { return JSON.parse(line); } catch { return null; }
  }).find((frame) => frame?.id === 2);
  if (toolResponse?.result?.isError !== true || toolResponse.error !== undefined) {
    const reason = toolResponse?.result && toolResponse.error === undefined ? 'unexpected-success' : 'unexpected-output';
    process.stderr.write(`Palladin signed-client probe failure: mcp-connection-${index + 1}: ${reason}\n`);
    throw new Error('unconfigured signed MCP request did not fail as a tool operation');
  }
}

const home = process.env.HOME;
if (!home) throw new Error('HOME is required for the public-state canary scan');
assertTreeDoesNotContainCanary(join(home, '.palladin'), 'public Palladin state');
assertTreeDoesNotContainCanary(captureDirectoryInput, 'bounded probe captures');

process.stdout.write('Blind signed-client, cancellation, second-connection, and public-state probes failed closed.\n');
