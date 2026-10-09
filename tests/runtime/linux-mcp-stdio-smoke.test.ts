import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

it.skipIf(process.platform === 'win32').each([
  ['current MCP 2.1 contract', false, -32602, 0],
  ['missing discovery tool', true, -32602, 1],
  ['accepted foreign profile', false, 0, 1],
] as const)('checks the Linux lifecycle wire probe against %s', (_name, omitDiscovery, profileError, exitCode) => {
  const root = mkdtempSync(join(tmpdir(), 'palladin-mcp-smoke-'));
  try {
    const contract = JSON.parse(readFileSync('runtime/contracts/mcp/v2.1/mcp-tools.json', 'utf8')) as {
      tools: { name: string }[];
    };
    const tools = contract.tools.filter(tool => !omitDiscovery || tool.name !== 'list_browser_sessions');
    const client = join(root, 'synthetic-client.mjs');
    writeFileSync(client, `#!${process.execPath}
import { createInterface } from 'node:readline';
createInterface({ input: process.stdin }).on('line', line => {
  const request = JSON.parse(line);
  if (request.id === undefined) return;
  const response = request.method === 'initialize'
    ? { result: { protocolVersion: '2025-11-25' } }
    : request.method === 'tools/list'
      ? { result: { tools: ${JSON.stringify(tools)} } }
      : { error: { code: ${profileError} } };
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, ...response }) + '\\n');
});
`, { mode: 0o700 });
    const result = spawnSync(process.execPath, [resolve('packaging/linux/tests/mcp-stdio-smoke.mjs'), client], {
      encoding: 'utf8', timeout: 15_000,
    });
    expect(result.status).toBe(exitCode);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
