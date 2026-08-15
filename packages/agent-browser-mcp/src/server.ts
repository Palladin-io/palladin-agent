import { randomBytes } from 'node:crypto';
import type { ChildProcess } from 'node:child_process';
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
import { getDomain } from 'tldts';
import {
  injectFormJsonSchema,
  parseInjectForm,
  parseInjectValues,
  type InjectFieldValue,
  type InjectFormDefinition,
} from '@palladin/agent/inject-contract';
import { parseFormDiscoveryMap, type FormDiscoveryMap } from '@palladin/agent/form-map';

import { AgentBrowserSession } from './agent-browser.js';
import { spawnAgentRuntime } from './agent-runtime.js';

const AGENT_BROWSER_PACKAGE = 'agent-browser';
const AGENT_BROWSER_VERSION = '0.33.2';
const INJECT_PROTOCOL = 'palladin.inject-provider.v1';
const MAX_PROVIDER_FRAME_BYTES = 256 * 1024;
const PROFILE_ARGUMENT = process.env.PALLADIN_AGENT_PROFILE?.trim();

interface InjectArguments {
  vaultId: string;
  entryId: string;
  reason?: string;
  wait?: string;
  noWait?: boolean;
  pollInterval?: string;
  form: InjectFormDefinition;
  formMap?: unknown;
}

interface ProviderCredential {
  protocol: typeof INJECT_PROTOCOL;
  type: 'credential';
  provider: 'agent-browser';
  nonce: string;
  transactionId: string;
  grantId: string;
  entryId: string;
  expectedDomain: string;
  form: InjectFormDefinition;
  values: InjectFieldValue[];
}

const injectTool: Tool = {
  name: 'inject_credential',
  title: 'Inject Palladin credential',
  description: 'Request an Inject grant and fill the active AgentBrowser session without returning credential fields to the model.',
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
      instructions: 'Prepare the public login surface before Inject: dismiss cookie/consent overlays, complete allowed public navigation and any human CAPTCHA, then inspect the visible controls and build the complete value-free multi-step form. Only after the page is ready call inject_credential; it never returns field values.',
    },
  );
  let injectionActive = false;
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const listed = await upstream.listTools();
    return {
      ...listed,
      tools: [...listed.tools.filter((tool) => tool.name !== injectTool.name), injectTool],
    };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    if (injectionActive) return toolError('A trusted Inject operation is already active.');
    if (request.params.name !== injectTool.name) {
      return await upstream.callTool(request.params) as CallToolResult;
    }
    const args = parseInjectArguments(request.params.arguments);
    if (args === null) return toolError('Inject arguments are invalid.');
    injectionActive = true;
    try {
      return await injectWithPalladin(new AgentBrowserSession(configuredSession), args);
    } finally {
      injectionActive = false;
    }
  });

  const shutdown = async (): Promise<void> => {
    await server.close().catch(() => undefined);
    await upstream.close().catch(() => undefined);
  };
  process.once('SIGINT', () => void shutdown());
  process.once('SIGTERM', () => void shutdown());
  await server.connect(new StdioServerTransport());
}

export async function injectWithPalladin(
  browser: AgentBrowserSession,
  args: InjectArguments,
  spawnRuntime: typeof spawnAgentRuntime = spawnAgentRuntime,
): Promise<CallToolResult> {
  if (args.formMap !== undefined) {
    const map = parseFormDiscoveryMap(args.formMap);
    if (map === null || JSON.stringify(map.form) !== JSON.stringify(args.form)) return toolError('Form discovery map does not match the Inject form.');
    await browser.dismissCookieOverlays(map);
  }
  const nonce = randomBytes(32).toString('hex');
  const runtimeArgs: string[] = [];
  if (PROFILE_ARGUMENT) runtimeArgs.push('--id', PROFILE_ARGUMENT);
  runtimeArgs.push(
    'inject', args.vaultId, args.entryId,
    '--provider', 'agent-browser', '--provider-transport-stdio',
  );
  if (args.reason !== undefined) runtimeArgs.push('--reason', args.reason);
  if (args.noWait === true) runtimeArgs.push('--no-wait');
  else if (args.wait !== undefined) runtimeArgs.push('--wait', args.wait);
  if (args.pollInterval !== undefined) runtimeArgs.push('--poll-interval', args.pollInterval);

  let child: ChildProcess | undefined;
  let credential: ProviderCredential | undefined;
  try {
    const currentUrl = await browser.currentUrl();
    child = spawnRuntime(runtimeArgs);
    if (child.stdin === null || child.stdout === null) throw new Error('provider pipe unavailable');
    child.stdin.write(`${JSON.stringify({
      protocol: INJECT_PROTOCOL,
      type: 'open',
      provider: 'agent-browser',
      nonce,
      currentUrl,
      form: args.form,
    })}\n`);
    const received = parseProviderCredential(
      await readOneLine(child.stdout), nonce, args.entryId, args.form,
    );
    if (received === null) throw new Error('provider credential is invalid');
    credential = received;
    const verify = (url: string): void => verifyDomain(url, credential?.expectedDomain ?? '');
    verify(currentUrl);
    await browser.inject(credential, verify);
    child.stdin.end(`${JSON.stringify({
      protocol: INJECT_PROTOCOL,
      type: 'result',
      nonce,
      transactionId: credential.transactionId,
      outcome: 'injected',
    })}\n`);
    if (await waitForExit(child) !== 0) throw new Error('provider runtime failed');
    return {
      content: [{ type: 'text', text: JSON.stringify({ status: 'injected', provider: 'agent-browser' }) }],
      isError: false,
    };
  } catch {
    if (child?.stdin !== null && child?.stdin !== undefined && credential !== undefined) {
      child.stdin.end(`${JSON.stringify({
        protocol: INJECT_PROTOCOL,
        type: 'result',
        nonce,
        transactionId: credential.transactionId,
        outcome: 'provider-unavailable',
      })}\n`);
    }
    child?.kill();
    return toolError('The trusted AgentBrowser Inject provider failed.');
  } finally {
    if (credential !== undefined) {
      for (const field of credential.values) field.value = '';
      credential.values.length = 0;
    }
    credential = undefined;
  }
}

export function parseInjectArguments(value: unknown): InjectArguments | null {
  if (!isRecord(value)) return null;
  const allowed = new Set(['vaultId', 'entryId', 'reason', 'wait', 'noWait', 'pollInterval', 'form', 'formMap']);
  if (Object.keys(value).some((key) => !allowed.has(key))) return null;
  if (!boundedString(value.vaultId, 256) || !boundedString(value.entryId, 256)) return null;
  if (value.reason !== undefined && !boundedString(value.reason, 4096, true)) return null;
  if (value.wait !== undefined && !boundedString(value.wait, 32)) return null;
  if (value.pollInterval !== undefined && !boundedString(value.pollInterval, 32)) return null;
  if (value.noWait !== undefined && typeof value.noWait !== 'boolean') return null;
  const form = parseInjectForm(value.form);
  if (form === null) return null;
  if (value.formMap !== undefined && parseFormDiscoveryMap(value.formMap) === null) return null;
  return { ...(value as unknown as Omit<InjectArguments, 'form'>), form };
}

export function parseProviderCredential(
  line: string,
  nonce: string,
  entryId: string,
  expectedForm: InjectFormDefinition,
): ProviderCredential | null {
  let value: unknown;
  try { value = JSON.parse(line); } catch { return null; }
  if (!isRecord(value)) return null;
  const allowed = new Set([
    'protocol', 'type', 'provider', 'nonce', 'transactionId', 'grantId', 'entryId',
    'expectedDomain', 'form', 'values',
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))) return null;
  if (value.protocol !== INJECT_PROTOCOL || value.type !== 'credential'
    || value.provider !== 'agent-browser' || value.nonce !== nonce
    || value.entryId !== entryId
    || !boundedString(value.transactionId, 256) || !boundedString(value.grantId, 256)
    || !boundedString(value.expectedDomain, 253)) {
    return null;
  }
  const form = parseInjectForm(value.form);
  if (form === null || JSON.stringify(form) !== JSON.stringify(expectedForm)) return null;
  const values = parseInjectValues(value.values, form);
  if (values === null) return null;
  return { ...(value as unknown as Omit<ProviderCredential, 'form' | 'values'>), form, values };
}

export function verifyDomain(url: string, expectedDomain: string): void {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') throw new Error('insecure origin');
  const active = getDomain(parsed.hostname, { allowPrivateDomains: true });
  const expected = getDomain(expectedDomain, { allowPrivateDomains: true });
  if (active === null || expected === null || active !== expected) throw new Error('origin mismatch');
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

function readOneLine(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let length = 0;
    const onData = (chunk: Buffer | string): void => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const newline = bytes.indexOf(0x0a);
      const part = newline === -1 ? bytes : bytes.subarray(0, newline);
      chunks.push(Buffer.from(part));
      length += part.length;
      if (length > MAX_PROVIDER_FRAME_BYTES) { cleanup(); reject(new Error('frame too large')); }
      else if (newline !== -1) {
        const frame = Buffer.concat(chunks, length);
        const line = frame.toString('utf8');
        frame.fill(0);
        cleanup();
        resolve(line);
      }
    };
    const onEnd = (): void => { cleanup(); reject(new Error('provider closed')); };
    const onError = (): void => { cleanup(); reject(new Error('provider failed')); };
    const cleanup = (): void => {
      stream.removeListener('data', onData);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
      for (const chunk of chunks) chunk.fill(0);
    };
    stream.on('data', onData);
    stream.once('end', onEnd);
    stream.once('error', onError);
  });
}

function waitForExit(child: ChildProcess): Promise<number> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) { resolve(child.exitCode); return; }
    child.once('exit', (code) => resolve(code ?? 1));
    child.once('error', () => resolve(1));
  });
}

function toolError(message: string): CallToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function boundedString(value: unknown, max: number, allowEmpty = false): value is string {
  return typeof value === 'string' && value.length <= max && (allowEmpty || value.length > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
