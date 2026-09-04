import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, relative, resolve } from 'node:path';
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
const canonicalIcon = resolve(pluginSourceRoot, 'core/assets/icon.png');

type Target = {
  id: 'codex' | 'claude' | 'openclaw' | 'hermes';
  manifestPath: string;
  mcpPath: string;
  format: 'codex' | 'claude' | 'agent-plugins-v1';
  expectedMcpArgs: string[];
};

const targets: Target[] = [
  {
    id: 'codex',
    manifestPath: '.codex-plugin/plugin.json',
    mcpPath: '.mcp.json',
    format: 'codex',
    expectedMcpArgs: ['--id', 'codex', 'mcp', 'serve'],
  },
  {
    id: 'claude',
    manifestPath: '.claude-plugin/plugin.json',
    mcpPath: '.mcp.json',
    format: 'claude',
    expectedMcpArgs: ['mcp', 'serve'],
  },
  {
    id: 'openclaw',
    manifestPath: 'plugin.json',
    mcpPath: 'mcp.json',
    format: 'agent-plugins-v1',
    expectedMcpArgs: ['mcp', 'serve'],
  },
  {
    id: 'hermes',
    manifestPath: 'plugin.json',
    mcpPath: 'mcp.json',
    format: 'agent-plugins-v1',
    expectedMcpArgs: ['mcp', 'serve'],
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

  it('rejects artifacts outside the generated target file set', async () => {
    const unexpected = resolve(
      pluginSourceRoot,
      'targets/codex/palladin-agent/unexpected.preview',
    );
    await writeFile(unexpected, 'must not survive generation\n', 'utf8');
    try {
      await expect(
        execFileAsync(process.execPath, [
          resolve(pluginSourceRoot, 'scripts/generate-targets.mjs'),
          '--check',
        ]),
      ).rejects.toMatchObject({
        stderr: expect.stringContaining('unexpected generated artifact'),
      });
      await expect(
        execFileAsync(process.execPath, [
          resolve(pluginSourceRoot, 'scripts/generate-targets.mjs'),
        ]),
      ).resolves.toBeTruthy();
      await expect(stat(unexpected)).rejects.toMatchObject({ code: 'ENOENT' });
    } finally {
      await rm(unexpected, { force: true });
    }
  });

  it.each(targets)('packages the canonical workflow for $id', async (target) => {
    const root = targetRoot(target);
    const manifest = JSON.parse(
      await readFile(resolve(root, target.manifestPath), 'utf8'),
    ) as Record<string, unknown>;

    expect(manifest.name).toBe(basename(root));
    expect(manifest.version).toMatch(
      /^0\.1\.0-preview\.\d+(?:\+codex\.\d{14})?$/u,
    );
    if (target.id === 'codex') {
      expect(manifest.version).toContain('+codex.');
      const interfaceMetadata = manifest.interface as {
        composerIcon: string;
        defaultPrompt: string[];
        displayName: string;
        logo: string;
      };
      expect(interfaceMetadata.displayName).toBe('Palladin');
      expect(interfaceMetadata.composerIcon).toBe('./assets/icon.png');
      expect(interfaceMetadata.logo).toBe('./assets/icon.png');
      expect(interfaceMetadata.defaultPrompt).toHaveLength(3);
      expect(await readFile(resolve(root, interfaceMetadata.composerIcon))).toEqual(
        await readFile(canonicalIcon),
      );
    }
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

  it.each(targets)('launches the intended native MCP profile for $id', async (target) => {
    const config = JSON.parse(
      await readFile(resolve(targetRoot(target), target.mcpPath), 'utf8'),
    ) as Record<string, unknown>;
    const server = readMcpServer(target.format, config) as Record<string, unknown>;

    expect(server.command).toBe('palladin');
    expect(server.args).toEqual(target.expectedMcpArgs);
    expect(server.env).toBeUndefined();
    if (target.format === 'agent-plugins-v1') {
      expect(server.type).toBe('stdio');
      expect(config.$schema).toBe(
        'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
      );
    }
  });

  it('publishes the generated Codex target through the repository marketplace', async () => {
    const marketplacePath = resolve(repositoryRoot, '.agents/plugins/marketplace.json');
    const marketplace = JSON.parse(await readFile(marketplacePath, 'utf8')) as {
      name: string;
      plugins: Array<{
        name: string;
        source: { source: string; path: string };
        policy: { installation: string; authentication: string };
        category: string;
      }>;
    };

    expect(marketplace.name).toBe('palladin-local');
    expect(marketplace.plugins).toHaveLength(1);
    const [plugin] = marketplace.plugins;
    expect(plugin).toMatchObject({
      name: 'palladin-agent',
      source: { source: 'local' },
      policy: { installation: 'AVAILABLE', authentication: 'ON_INSTALL' },
      category: 'Productivity',
    });
    expect(plugin.source.path.startsWith('./')).toBe(true);

    const pluginRoot = resolve(repositoryRoot, plugin.source.path);
    expect(relative(repositoryRoot, pluginRoot).startsWith('..')).toBe(false);
    expect(pluginRoot).toBe(targetRoot(targets[0]));
    await expect(stat(resolve(pluginRoot, '.codex-plugin/plugin.json'))).resolves.toBeTruthy();
  });

  it('creates a deterministic Codex skills-only submission archive', async () => {
    const temporaryRoot = await mkdtemp(resolve(tmpdir(), 'palladin-codex-plugin-'));
    const archiveOne = resolve(temporaryRoot, 'submission-one.zip');
    const archiveTwo = resolve(temporaryRoot, 'submission-two.zip');
    const python = process.platform === 'win32' ? 'python' : 'python3';
    const packager = resolve(
      pluginSourceRoot,
      'scripts/package-codex-skills-only.py',
    );

    try {
      const first = await execFileAsync(python, [packager, archiveOne]);
      const second = await execFileAsync(python, [packager, archiveTwo]);
      const summary = JSON.parse(first.stdout) as {
        entries: string[];
        manifestKeys: string[];
        manifestVersion: string;
        root: string;
      };

      expect(summary.root).toBe('palladin-agent');
      expect(summary.entries).toContain(
        'palladin-agent/skills/palladin-browser-login/SKILL.md',
      );
      expect(summary.entries).toContain(
        'palladin-agent/.codex-plugin/plugin.json',
      );
      expect(summary.entries).toContain('palladin-agent/assets/icon.png');
      expect(summary.entries.some((entry) => basename(entry) === '.mcp.json')).toBe(
        false,
      );
      expect(summary.manifestKeys).not.toContain('mcpServers');
      expect(summary.manifestKeys).not.toContain('apps');
      expect(summary.manifestVersion).toBe('0.1.0-preview.2');
      expect(await readFile(archiveOne)).toEqual(await readFile(archiveTwo));
      expect(JSON.parse(second.stdout)).toMatchObject({
        root: 'palladin-agent',
        entries: summary.entries,
      });
      await expect(
        execFileAsync(process.execPath, [
          resolve(pluginSourceRoot, 'scripts/generate-targets.mjs'),
          '--check',
        ]),
      ).resolves.toBeTruthy();
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
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
      await readFile(resolve(repositoryRoot, 'runtime/contracts/mcp/v1.2/mcp-tools.json'), 'utf8'),
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
    expect(toolNames).toEqual([
      'search_entries',
      'get_credential',
      'exec_with_credential',
      'inject_credential',
      'report_credential_stale',
    ]);
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
      '--json',
    ]);
    expect(providerContract.credentialSurfaces.cli.inject).toEqual([
      'palladin',
      'inject',
    ]);
    expect(cliArgs).toContain('Search(SearchArgs)');
    expect(cliArgs).toContain('pub json: bool');
    expect(cliArgs).toContain('Inject(InjectArgs)');

    for (const provider of providerContract.browserProviders) {
      expect(provider.cliValue).toBe(provider.id);
      expect(provider.mcpValue).toBe(provider.id);
      expect(injectTool?.inputSchema.properties?.provider?.default).toBe(provider.id);
      expect(cliArgs).toContain(`default_value = "${provider.id}"`);
    }
  });
});
