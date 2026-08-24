import { readFile, stat } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const pluginRoot = resolve(
  repositoryRoot,
  'plugins/palladin-agent/targets/codex/palladin-agent',
);
const canonicalSkill = resolve(
  repositoryRoot,
  'plugins/palladin-agent/core/skills/palladin-browser-login/SKILL.md',
);
const packagedSkill = resolve(
  pluginRoot,
  'skills/palladin-browser-login/SKILL.md',
);

describe('Palladin Codex plugin preview', () => {
  it('uses a valid self-contained plugin root', async () => {
    const manifest = JSON.parse(
      await readFile(resolve(pluginRoot, '.codex-plugin/plugin.json'), 'utf8'),
    ) as {
      name: string;
      skills: string;
      mcpServers: string;
      version: string;
    };

    expect(manifest.name).toBe(basename(pluginRoot));
    expect(manifest.version).toMatch(/^0\.1\.0-preview\.\d+$/u);
    expect(manifest.skills).toBe('./skills/');
    expect(manifest.mcpServers).toBe('./.mcp.json');

    expect((await stat(resolve(pluginRoot, manifest.skills))).isDirectory()).toBe(true);
    await expect(
      readFile(resolve(pluginRoot, 'skills/palladin-browser-login/SKILL.md'), 'utf8'),
    ).resolves.toContain('name: palladin-browser-login');
    await expect(readFile(resolve(pluginRoot, manifest.mcpServers), 'utf8')).resolves.toBeTruthy();
  });

  it('starts only the native Palladin MCP command without a shell or secret environment', async () => {
    const config = JSON.parse(await readFile(resolve(pluginRoot, '.mcp.json'), 'utf8')) as {
      mcpServers: Record<string, Record<string, unknown>>;
    };

    expect(config).toEqual({
      mcpServers: {
        palladin: {
          command: 'palladin',
          args: ['mcp', 'serve'],
        },
      },
    });
  });

  it('packages the canonical workflow without target-specific edits', async () => {
    const [canonical, packaged] = await Promise.all([
      readFile(canonicalSkill, 'utf8'),
      readFile(packagedSkill, 'utf8'),
    ]);

    expect(packaged).toBe(canonical);
  });
});
