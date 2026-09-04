import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const pluginSourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const checkOnly = process.argv.includes('--check');
const version = '0.1.0-preview.2';
const codexVersion = `${version}+codex.local-20260904-155016`;

const canonicalSkill = await readFile(
  resolve(pluginSourceRoot, 'core/skills/palladin-browser-login/SKILL.md'),
  'utf8',
);
const providerReference = await readFile(
  resolve(pluginSourceRoot, 'core/skills/palladin-browser-login/references/provider-contract.md'),
  'utf8',
);
const providerContract = await readFile(
  resolve(pluginSourceRoot, 'core/provider-contract.json'),
  'utf8',
);

const metadata = {
  version,
  description: 'Preview of Palladin credential workflows and secure browser injection.',
  author: {
    name: 'Palladin.io',
    url: 'https://palladin.io',
  },
  homepage: 'https://palladin.io',
  repository: 'https://github.com/Palladin-io/palladin-agent',
  license: 'Apache-2.0',
  keywords: ['palladin', 'password-manager', 'browser-login', 'agent'],
};

const mcpCommand = {
  command: 'palladin',
  args: ['mcp', 'serve'],
};

const codexMcpCommand = {
  command: 'palladin',
  args: ['--id', 'codex', 'mcp', 'serve'],
};

const codexManifest = {
  name: 'palladin-agent',
  ...metadata,
  version: codexVersion,
  skills: './skills/',
  mcpServers: './.mcp.json',
  interface: {
    displayName: 'Palladin Agent',
    shortDescription: 'Use granted credentials through Palladin',
    longDescription:
      'Palladin lets Codex discover granted credentials, deliberately retrieve them or use them in local execution when requested, and inject credentials into an exact browser tab through the paired Palladin extension.',
    developerName: 'Palladin.io',
    category: 'Productivity',
    capabilities: [
      'Credential discovery',
      'Explicit credential retrieval',
      'Local credential execution',
      'Browser credential injection',
    ],
    websiteURL: 'https://palladin.io',
    defaultPrompt: [
      'Sign me in to this website with Palladin.',
      'Open the login page and use my Palladin account.',
      'Use Palladin to sign in on this browser tab.',
      'Find a credential I can use through Palladin.',
      'Run this command with a granted Palladin credential.',
    ],
    brandColor: '#D95A4E',
  },
};

const claudeManifest = {
  name: 'palladin-agent',
  ...metadata,
};

const portableManifest = {
  $schema: 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json',
  name: 'palladin-agent',
  ...metadata,
};

const portableMcp = {
  $schema: 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
  mcpServers: {
    palladin: {
      type: 'stdio',
      ...mcpCommand,
    },
  },
};

const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
const targets = [
  {
    id: 'codex',
    manifestPath: '.codex-plugin/plugin.json',
    manifest: codexManifest,
    mcpPath: '.mcp.json',
    mcp: { mcpServers: { palladin: codexMcpCommand } },
    extraFiles: {
      'skills/palladin-browser-login/agents/openai.yaml': [
        'interface:',
        '  display_name: "Palladin Browser Login"',
        '  short_description: "Sign in without exposing credential values"',
        '  default_prompt: "Use $palladin-browser-login to sign in on the exact browser tab through Palladin."',
        '',
      ].join('\n'),
    },
  },
  {
    id: 'claude',
    manifestPath: '.claude-plugin/plugin.json',
    manifest: claudeManifest,
    mcpPath: '.mcp.json',
    mcp: { mcpServers: { palladin: mcpCommand } },
    extraFiles: {},
  },
  {
    id: 'openclaw',
    manifestPath: 'plugin.json',
    manifest: portableManifest,
    mcpPath: 'mcp.json',
    mcp: portableMcp,
    extraFiles: {},
  },
  {
    id: 'hermes',
    manifestPath: 'plugin.json',
    manifest: portableManifest,
    mcpPath: 'mcp.json',
    mcp: portableMcp,
    extraFiles: {},
  },
];

const mismatches = [];

async function listTargetArtifacts(root) {
  const artifacts = [];

  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
      if (error.code === 'ENOENT') return [];
      throw error;
    });

    for (const entry of entries) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(path);
        continue;
      }
      artifacts.push({
        path,
        relativePath: relative(root, path).split(sep).join('/'),
        regularFile: entry.isFile(),
      });
    }
  }

  await walk(root);
  return artifacts;
}

async function materialize(path, content) {
  if (checkOnly) {
    const current = await readFile(path, 'utf8').catch(() => undefined);
    if (current !== content) mismatches.push(path);
    return;
  }
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, 'utf8');
}

for (const target of targets) {
  const root = resolve(pluginSourceRoot, `targets/${target.id}/palladin-agent`);
  const hostAdapter = await readFile(
    resolve(pluginSourceRoot, `core/adapters/${target.id}.md`),
    'utf8',
  );
  const files = {
    [target.manifestPath]: json(target.manifest),
    [target.mcpPath]: json(target.mcp),
    'palladin-provider-contract.json': providerContract,
    'skills/palladin-browser-login/SKILL.md': canonicalSkill,
    'skills/palladin-browser-login/references/provider-contract.md': providerReference,
    'skills/palladin-browser-login/references/host-browser.md': hostAdapter,
    ...target.extraFiles,
  };

  if (checkOnly) {
    const expectedPaths = new Set(Object.keys(files));
    for (const artifact of await listTargetArtifacts(root)) {
      if (!artifact.regularFile || !expectedPaths.has(artifact.relativePath)) {
        mismatches.push(`${artifact.path} (unexpected generated artifact)`);
      }
    }
  } else {
    await rm(root, { recursive: true, force: true });
  }

  for (const [relativePath, content] of Object.entries(files)) {
    await materialize(resolve(root, relativePath), content);
  }
}

if (mismatches.length > 0) {
  throw new Error(`Generated plugin targets are stale:\n${mismatches.join('\n')}`);
}
