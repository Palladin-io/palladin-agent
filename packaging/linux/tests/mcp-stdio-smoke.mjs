import { spawn } from 'node:child_process';

const client = process.argv[2];
if (process.argv.length !== 3 || !client?.startsWith('/')) process.exit(64);

const child = spawn(client, ['mcp', 'serve'], {
  env: {},
  shell: false,
  stdio: ['pipe', 'pipe', 'pipe'],
});

let stdout = '';
let stderrBytes = 0;
let failed = false;
let protocolComplete = false;
const responses = [];

function fail() {
  if (failed) return;
  failed = true;
  child.kill('SIGKILL');
  process.stderr.write('MCP lifecycle smoke failed without emitting child output\n');
  process.exitCode = 1;
}

const timeout = setTimeout(fail, 10_000);
child.stderr.on('data', (chunk) => {
  stderrBytes += chunk.length;
  if (stderrBytes > 64 * 1024) fail();
});
child.stdout.on('data', (chunk) => {
  if (failed || protocolComplete) return;
  stdout += chunk.toString('utf8');
  if (Buffer.byteLength(stdout, 'utf8') > 1024 * 1024) {
    fail();
    return;
  }
  for (;;) {
    const newline = stdout.indexOf('\n');
    if (newline < 0) break;
    const line = stdout.slice(0, newline);
    stdout = stdout.slice(newline + 1);
    if (line.length === 0) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      fail();
      return;
    }
    responses.push(message);
    if (responses.length === 1) {
      if (message?.id !== 1 || message?.result?.protocolVersion !== '2025-11-25') {
        fail();
        return;
      }
      child.stdin.write(`${JSON.stringify({
        jsonrpc: '2.0',
        method: 'notifications/initialized',
      })}\n`);
      child.stdin.write(`${JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      })}\n`);
      continue;
    }
    if (responses.length === 2) {
      const names = message?.result?.tools?.map((tool) => tool?.name);
      const expected = [
        'search_entries',
        'get_credential',
        'exec_with_credential',
        'inject_credential',
        'report_credential_stale',
      ];
      if (message?.id !== 2 || JSON.stringify(names) !== JSON.stringify(expected)) {
        fail();
        return;
      }
      protocolComplete = true;
      clearTimeout(timeout);
      child.stdin.end();
    }
  }
});
child.once('error', fail);
child.once('exit', (code, signal) => {
  clearTimeout(timeout);
  if (failed) return;
  if (!protocolComplete || responses.length !== 2 || code !== 0 || signal !== null) {
    process.stderr.write('MCP lifecycle smoke failed without emitting child output\n');
    process.exitCode = 1;
    return;
  }
  process.stdout.write('mcp-initialize-and-tools-list=passed\n');
});

child.stdin.write(`${JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-11-25',
    capabilities: {},
    clientInfo: { name: 'palladin-lifecycle-smoke', version: '1' },
  },
})}\n`);
