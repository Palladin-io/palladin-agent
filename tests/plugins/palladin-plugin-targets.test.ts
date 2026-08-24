import { execFile } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const pluginSourceRoot = resolve(repositoryRoot, 'plugins/palladin-agent');
const canonicalSkill = resolve(
  pluginSourceRoot,
  'core/skills/palladin-browser-login/SKILL.md',
);
const canonicalProviderReference = resolve(
  pluginSourceRoot,
  'core/skills/palladin-browser-login/references/provider-contract.md',
);
const canonicalProviderContract = resolve(pluginSourceRoot, 'core/provider-contract.json');

type Target = {
  id: 'codex' | 'claude' | 'openclaw' | 'hermes';
  manifestPath: string;
  mcpPath: string;
  format: 'codex' | 'claude' | 'agent-plugins-v1';
};

const targets: Target[] = [
  {
    id: 'codex',
    manifestPath: '.codex-plugin/plugin.json',
    mcpPath: '.mcp.json',
    format: 'codex',
  },
  {
    id: 'claude',
    manifestPath: '.claude-plugin/plugin.json',
    mcpPath: '.mcp.json',
    format: 'claude',
  },
  {
    id: 'openclaw',
    manifestPath: 'plugin.json',
    mcpPath: 'mcp.json',
    format: 'agent-plugins-v1',
  },
  {
    id: 'hermes',
    manifestPath: 'plugin.json',
    mcpPath: 'mcp.json',
    format: 'agent-plugins-v1',
  },
];

const targetRoot = (target: Target) =>
  resolve(pluginSourceRoot, `targets/${target.id}/palladin-agent`);

function readMcpServer(format: Target['format'], config: Record<string, unknown>) {
  return (config.mcpServers as Record<string, unknown>).palladin;
}

describe('Palladin plugin targets', () => {
  it('keeps every generated target synchronized with the shared sources', async () => {
    await expect(
      execFileAsync(process.execPath, [
        resolve(pluginSourceRoot, 'scripts/generate-targets.mjs'),
        '--check',
      ]),
    ).resolves.toBeTruthy();
  });

  it.each(targets)('packages the canonical workflow for $id', async (target) => {
    const root = targetRoot(target);
    const manifest = JSON.parse(
      await readFile(resolve(root, target.manifestPath), 'utf8'),
    ) as Record<string, unknown>;

    expect(manifest.name).toBe(basename(root));
    expect(manifest.version).toMatch(/^0\.1\.0-preview\.\d+$/u);
    expect((await stat(resolve(root, 'skills'))).isDirectory()).toBe(true);

    const [sourceSkill, packagedSkill, sourceProvider, packagedProvider, hostAdapter] =
      await Promise.all([
        readFile(canonicalSkill, 'utf8'),
        readFile(resolve(root, 'skills/palladin-browser-login/SKILL.md'), 'utf8'),
        readFile(canonicalProviderReference, 'utf8'),
        readFile(
          resolve(root, 'skills/palladin-browser-login/references/provider-contract.md'),
          'utf8',
        ),
        readFile(
          resolve(root, 'skills/palladin-browser-login/references/host-browser.md'),
          'utf8',
        ),
      ]);

    expect(packagedSkill).toBe(sourceSkill);
    expect(packagedProvider).toBe(sourceProvider);
    expect(hostAdapter.length).toBeGreaterThan(200);
  });

  it.each(targets)('launches the same native MCP command for $id', async (target) => {
    const config = JSON.parse(
      await readFile(resolve(targetRoot(target), target.mcpPath), 'utf8'),
    ) as Record<string, unknown>;
    const server = readMcpServer(target.format, config) as Record<string, unknown>;

    expect(server.command).toBe('palladin');
    expect(server.args).toEqual(['mcp', 'serve']);
    expect(server.env).toBeUndefined();
    if (target.format === 'agent-plugins-v1') {
      expect(server.type).toBe('stdio');
      expect(config.$schema).toBe(
        'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
      );
    }
  });

  it('keeps host, MCP, CLI, and browser provider identifiers aligned', async () => {
    const providerContract = JSON.parse(
      await readFile(canonicalProviderContract, 'utf8'),
    ) as {
      agentHostProviders: Array<{ id: string }>;
      browserProviders: Array<{ id: string; cliValue: string; mcpValue: string }>;
      credentialSurfaces: {
        mcp: { inject: string; search: string; reportStale: string };
        cli: {
          inject: string[];
          search: string[];
          routing: { provider: string; targetTabId: string; targetUrl: string };
        };
      };
    };
    const mcpContract = JSON.parse(
      await readFile(resolve(repositoryRoot, 'runtime/contracts/mcp/v1.1/mcp-tools.json'), 'utf8'),
    ) as {
      tools: Array<{
        name: string;
        inputSchema: { properties?: Record<string, { default?: string }> };
      }>;
    };

    expect(providerContract.agentHostProviders.map(({ id }) => id)).toEqual(
      targets.map(({ id }) => id),
    );
    const toolNames = mcpContract.tools.map(({ name }) => name);
    expect(toolNames).toEqual(
      expect.arrayContaining([
        providerContract.credentialSurfaces.mcp.search,
        providerContract.credentialSurfaces.mcp.inject,
        providerContract.credentialSurfaces.mcp.reportStale,
      ]),
    );

    const injectTool = mcpContract.tools.find(
      ({ name }) => name === providerContract.credentialSurfaces.mcp.inject,
    );
    const cliArgs = await readFile(
      resolve(repositoryRoot, 'runtime/crates/palladin-cli/src/args.rs'),
      'utf8',
    );
    expect(providerContract.credentialSurfaces.cli.search).toEqual([
      'palladin',
      'search',
    ]);
    expect(providerContract.credentialSurfaces.cli.inject).toEqual([
      'palladin',
      'inject',
    ]);
    expect(cliArgs).toContain('Search(SearchArgs)');
    expect(cliArgs).toContain('Inject(InjectArgs)');

    for (const provider of providerContract.browserProviders) {
      expect(provider.cliValue).toBe(provider.id);
      expect(provider.mcpValue).toBe(provider.id);
      expect(injectTool?.inputSchema.properties?.provider?.default).toBe(provider.id);
      expect(cliArgs).toContain(`default_value = "${provider.id}"`);
    }
  });
});
