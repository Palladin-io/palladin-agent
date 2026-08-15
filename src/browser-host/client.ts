import { randomBytes } from 'node:crypto';
import { createConnection, type Socket } from 'node:net';

import { spawnNativeProviderRuntime } from '../runtime/native-dispatch.js';
import { JsonLineChannel } from './channel.js';
import { browserHostSocketPath } from './socket.js';
import {
  parseInjectForm,
  parseInjectValues,
  type InjectFormDefinition,
} from '../inject-contract.js';

const PROTOCOL = 'palladin.inject-provider.v1';

export function isExtensionInject(args: readonly string[]): boolean {
  if (!args.includes('inject') || args.includes('--provider-transport-stdio')
    || args.includes('--help') || args.includes('-h')) return false;
  const provider = args.indexOf('--provider');
  return provider === -1 || args[provider + 1] === 'extension';
}

export async function runExtensionInject(
  args: readonly string[],
  spawnRuntime: typeof spawnNativeProviderRuntime = spawnNativeProviderRuntime,
  suppliedForm?: InjectFormDefinition,
): Promise<number> {
  let socket: Socket | undefined;
  let child: Awaited<ReturnType<typeof spawnNativeProviderRuntime>> | undefined;
  try {
    socket = await connectHost();
    const host = new JsonLineChannel(socket, socket);
    const nonce = randomBytes(32).toString('hex');
    host.write({ protocol: PROTOCOL, type: 'prepare', nonce });
    const prepared = await host.read();
    if (!isRecord(prepared) || prepared.protocol !== PROTOCOL || prepared.type !== 'prepare.result'
      || prepared.nonce !== nonce || prepared.outcome !== 'ready'
      || typeof prepared.currentUrl !== 'string') throw new Error('extension is unavailable');

    const parsed = suppliedForm === undefined ? extractFormArgument(args) : suppliedForm;
    const form = parseInjectForm(parsed);
    if (form === null) throw new Error('Inject form definition is invalid');
    const runtimeArgs = removeFormArgument(args);
    if (!runtimeArgs.includes('--provider')) runtimeArgs.push('--provider', 'extension');
    runtimeArgs.push('--provider-transport-stdio');
    child = await spawnRuntime(runtimeArgs);
    if (child.stdin === null || child.stdout === null) throw new Error('runtime pipe unavailable');
    const runtime = new JsonLineChannel(child.stdout, child.stdin);
    runtime.write({
      protocol: PROTOCOL,
      type: 'open',
      provider: 'extension',
      nonce,
      currentUrl: prepared.currentUrl,
      form,
    });
    const credential = await runtime.read();
    if (!isRecord(credential) || credential.protocol !== PROTOCOL || credential.type !== 'credential'
      || credential.provider !== 'extension' || credential.nonce !== nonce
      || typeof credential.transactionId !== 'string'
      || JSON.stringify(parseInjectForm(credential.form)) !== JSON.stringify(form)
      || parseInjectValues(credential.values, form) === null) throw new Error('credential frame invalid');
    host.write(credential);
    const outcome = await host.read();
    if (!isRecord(outcome) || outcome.protocol !== PROTOCOL || outcome.type !== 'inject.result'
      || outcome.transactionId !== credential.transactionId || typeof outcome.outcome !== 'string') {
      throw new Error('extension result invalid');
    }
    runtime.end({
      protocol: PROTOCOL,
      type: 'result',
      nonce,
      transactionId: credential.transactionId,
      outcome: outcome.outcome,
    });
    socket.end();
    return await waitForExit(child);
  } catch {
    socket?.destroy();
    child?.kill();
    process.stderr.write('Error: the Palladin extension Inject provider is unavailable\n');
    return 1;
  }
}

function extractFormArgument(args: readonly string[]): unknown {
  const index = args.indexOf('--form-json');
  if (index === -1 || args[index + 1] === undefined) return null;
  try { return JSON.parse(args[index + 1] ?? ''); } catch { return null; }
}

function removeFormArgument(args: readonly string[]): string[] {
  const index = args.indexOf('--form-json');
  if (index === -1) return [...args];
  return args.filter((_, itemIndex) => itemIndex !== index && itemIndex !== index + 1);
}

/** Read only the extension's current public top-frame URL through the authenticated host. */
export async function extensionCurrentUrl(): Promise<string | null> {
  let socket: Socket | undefined;
  try {
    socket = await connectHost();
    const host = new JsonLineChannel(socket, socket);
    const nonce = randomBytes(32).toString('hex');
    host.write({ protocol: PROTOCOL, type: 'prepare', nonce });
    const prepared = await host.read();
    if (!isRecord(prepared) || prepared.protocol !== PROTOCOL || prepared.type !== 'prepare.result'
      || prepared.nonce !== nonce || prepared.outcome !== 'ready'
      || typeof prepared.currentUrl !== 'string') return null;
    return prepared.currentUrl;
  } catch {
    return null;
  } finally {
    socket?.end();
  }
}

function connectHost(): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(browserHostSocketPath);
    socket.once('connect', () => resolve(socket));
    socket.once('error', () => reject(new Error('browser host unavailable')));
  });
}

function waitForExit(child: Awaited<ReturnType<typeof spawnNativeProviderRuntime>>): Promise<number> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) { resolve(child.exitCode); return; }
    child.once('exit', (code) => resolve(code ?? 1));
    child.once('error', () => resolve(1));
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
