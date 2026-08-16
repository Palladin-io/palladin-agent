import { accessSync, constants as fsConstants, readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, relative } from 'node:path';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { injectFormJsonSchema } from '@palladin/agent/inject-contract';

const AGENT_BROWSER_PACKAGE = 'agent-browser';
const AGENT_BROWSER_VERSION = '0.33.2';

const injectTool: Tool = {
  name: 'inject_credential',
  title: 'Inject Palladin credential',
  description: 'Report that AgentBrowser secret delivery is unavailable; no grant is requested and no secret-bearing daemon command is sent.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      vaultId: { type: 'string', minLength: 1, maxLength: 256 },
      entryId: { type: 'string', minLength: 1, maxLength: 256 },
      reason: { type: 'string', maxLength: 4096 },
      wait: { type: 'string', maxLength: 32 },
      noWait: { type: 'boolean' },
      pollInterval: { type: 'string', maxLength: 32 },
      form: injectFormJsonSchema,
      formMap: { type: 'object', additionalProperties: true },
    },
    required: ['vaultId', 'entryId', 'form'],
  },
};

export async function main(): Promise<void> {
  const launcher = resolveAgentBrowserLauncher();
  const configuredSession = process.env.PALLADIN_AGENT_BROWSER_SESSION
    ?? process.env.AGENT_BROWSER_SESSION
    ?? 'default';
  const upstreamTransport = new StdioClientTransport({
    command: process.execPath,
    args: [launcher, 'mcp'],
    env: {
      AGENT_BROWSER_SESSION: configuredSession,
      ...(process.env.AGENT_BROWSER_NAMESPACE === undefined
        ? {}
        : { AGENT_BROWSER_NAMESPACE: process.env.AGENT_BROWSER_NAMESPACE }),
    },
    stderr: 'inherit',
    maxBufferSize: 2 * 1024 * 1024,
  });
  const upstream = new Client(
    { name: 'palladin-agent-browser-provider', version: '0.1.0' },
    { capabilities: {} },
  );
  await upstream.connect(upstreamTransport);

  const server = new Server(
    { name: 'Palladin AgentBrowser', version: '0.1.0' },
    {
      capabilities: { tools: {} },
      instructions: 'AgentBrowser public navigation tools are proxied unchanged. Palladin AgentBrowser Inject is disabled because AgentBrowser 0.33.2 cannot bind secret text insertion to the selected element; inject_credential returns provider-unavailable without requesting or transmitting a credential.',
    },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const listed = await upstream.listTools();
    return {
      ...listed,
      tools: [...listed.tools.filter((tool) => tool.name !== injectTool.name), injectTool],
    };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    if (request.params.name !== injectTool.name) {
      return await upstream.callTool(request.params) as CallToolResult;
    }
    return injectWithPalladin();
  });

  const shutdown = async (): Promise<void> => {
    await server.close().catch(() => undefined);
    await upstream.close().catch(() => undefined);
  };
  process.once('SIGINT', () => void shutdown());
  process.once('SIGTERM', () => void shutdown());
  await server.connect(new StdioServerTransport());
}

export function injectWithPalladin(): CallToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify({
      status: 'provider-unavailable',
      provider: 'agent-browser',
      reason: 'unsupported-secret-delivery',
    }) }],
    isError: true,
  };
}

function resolveAgentBrowserLauncher(): string {
  const require = createRequire(import.meta.url);
  const manifestPath = realpathSync(require.resolve(`${AGENT_BROWSER_PACKAGE}/package.json`));
  const packageRoot = dirname(manifestPath);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as unknown;
  if (!isRecord(manifest) || manifest.name !== AGENT_BROWSER_PACKAGE
    || manifest.version !== AGENT_BROWSER_VERSION) {
    throw new Error('AgentBrowser package identity is invalid');
  }
  const launcher = realpathSync(join(packageRoot, 'bin', 'agent-browser.js'));
  const pathFromPackage = relative(packageRoot, launcher);
  if (pathFromPackage === '' || pathFromPackage === '..'
    || pathFromPackage.startsWith('../') || pathFromPackage.startsWith('..\\')
    || isAbsolute(pathFromPackage)) throw new Error('AgentBrowser launcher is outside its package');
  accessSync(launcher, fsConstants.R_OK);
  return launcher;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
