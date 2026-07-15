import { randomBytes } from 'node:crypto';
import {
  chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync,
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
    if (readFileSync(current).includes(Buffer.from(canary))) {
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
  const child = spawn(executable, args, {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PALLADIN_BOUNDARY_PRIVATE_CANARY: canary },
  });
  const stdout = [];
  const stderr = [];
  let size = 0;
  const collect = (target) => (chunk) => {
    size += chunk.length;
    if (size > maximumCaptureBytes) child.kill('SIGKILL');
    else target.push(Buffer.from(chunk));
  };
  child.stdout.on('data', collect(stdout));
  child.stderr.on('data', collect(stderr));
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
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer);
  const stdoutBuffer = Buffer.concat(stdout);
  const stderrBuffer = Buffer.concat(stderr);
  capture(name, stdoutBuffer, stderrBuffer);
  if (timedOut) throw new Error('signed-client probe timed out');
  return { ...result, stdout: stdoutBuffer, stderr: stderrBuffer };
}

function assertAuthorizationDenial(name, result) {
  const output = Buffer.concat([result.stdout, result.stderr]).toString('utf8');
  if (!output.includes('fresh operating-system authorization')) {
    throw new Error(`${name} failed before reaching the authenticated identity boundary`);
  }
}

const vault = '11111111111111111111111111111111';
const entry = '22222222222222222222222222222222';
const blindArguments = ['get', vault, entry, '--reason', 'noninteractive boundary probe', '--no-wait'];
for (const [name, executable] of [['genuine', binary], ['copied', copiedBinary]]) {
  const result = await runBounded(`blind-${name}`, executable, blindArguments);
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
  params: { name: 'get_credential', arguments: { vault_id: vault, entry_id: entry, reason: 'noninteractive boundary probe', no_wait: true } },
});
const mcpInput = `${initialize}\n${toolCall}\n`;
const firstMcp = runBounded(
  'mcp-first-connection', binary, ['mcp', 'serve'],
  { stdin: mcpInput, keepStdinOpen: true, interruptAfterMs: 600, timeoutMs: 5_000 },
);
const secondMcp = runBounded(
  'mcp-second-connection', binary, ['mcp', 'serve'],
  { stdin: mcpInput, keepStdinOpen: true, interruptAfterMs: 600, timeoutMs: 5_000 },
);
const mcpResults = await Promise.all([firstMcp, secondMcp]);
if (mcpResults.some((result) => result.code === 0)) {
  throw new Error('blind MCP connection unexpectedly completed an identity operation');
}
mcpResults.forEach((result, index) => assertAuthorizationDenial(`mcp-connection-${index + 1}`, result));

const home = process.env.HOME;
if (!home) throw new Error('HOME is required for the public-state canary scan');
assertTreeDoesNotContainCanary(join(home, '.palladin'), 'public Palladin state');
assertTreeDoesNotContainCanary(captureDirectoryInput, 'bounded probe captures');

process.stdout.write('Blind signed-client, cancellation, second-connection, and public-state probes failed closed.\n');
