import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  readFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { createConnection } from 'node:net';
import type {
  InjectControl,
  InjectFieldValue,
  InjectFormDefinition,
} from '@palladin/agent/inject-contract';
import type { FormDiscoveryMap } from '@palladin/agent/form-map';

const AGENT_BROWSER_VERSION = '0.33.2';
const MAX_RESPONSE_BYTES = 1024 * 1024;
export interface AgentBrowserCredential {
  form: InjectFormDefinition;
  values: InjectFieldValue[];
}

export class AgentBrowserSession {
  constructor(
    private readonly session = configuredSession(),
    private readonly namespace = process.env.AGENT_BROWSER_NAMESPACE,
    private readonly directory = socketDirectory(namespace),
  ) {}

  async currentUrl(): Promise<string> {
    const data = await this.command({ action: 'url' });
    if (typeof data.url !== 'string') throw new Error('AgentBrowser URL response is invalid');
    return data.url;
  }

  async inject(credential: AgentBrowserCredential, verifyUrl: (url: string) => void): Promise<void> {
    const values = new Map(credential.values.map((field) => [field.entryFieldId, field.value]));
    const filled: Array<{ selector: string; entryFieldId: string; control: InjectControl }> = [];
    try {
      for (const step of credential.form.steps) {
        verifyUrl(await this.currentUrl());
        for (const field of step.fields) {
          const value = values.get(field.entryFieldId);
          if (value === undefined) throw new Error('declared field value is missing');
          await this.validateTarget(field.selector, field.control);
          verifyUrl(await this.currentUrl());
          await this.command({ action: 'fill', selector: field.selector, value });
          filled.push(field);
          verifyUrl(await this.currentUrl());
        }
        verifyUrl(await this.currentUrl());
        if (step.submit.action === 'click') {
          await this.ensureUnique(step.submit.selector);
          await this.command({ action: 'click', selector: step.submit.selector });
        } else {
          await this.command({ action: 'click', selector: step.submit.selector });
          await this.command({ action: 'press', key: 'Enter' });
        }
        if (step.waitFor !== undefined) {
          await this.waitVisible(step.waitFor.selector, step.waitFor.timeoutMs ?? 20_000);
          await this.ensureUnique(step.waitFor.selector);
        }
        verifyUrl(await this.currentUrl());
      }
    } catch (error) {
      for (const field of filled.reverse()) {
        if (field.control !== 'password' && field.control !== 'otp'
          && !/(?:password|passcode|otp|totp|secret|token)/i.test(field.entryFieldId)) continue;
        await this.command({ action: 'fill', selector: field.selector, value: '' }).catch(() => undefined);
      }
      throw error;
    }
  }

  async dismissCookieOverlays(map: FormDiscoveryMap): Promise<void> {
    for (const overlay of map.cookieOverlays ?? []) {
      for (const selector of overlay.selectors) {
        if (await this.count(selector).catch(() => 0) === 0) continue;
        if (await this.count(overlay.dismiss.selector).catch(() => 0) !== 1) continue;
        await this.command({ action: 'click', selector: overlay.dismiss.selector });
        break;
      }
    }
  }

  private async waitVisible(selector: string, timeout: number): Promise<void> {
    try {
      await this.command({ action: 'wait', selector, state: 'visible', timeout }, timeout + 5_000);
    } catch (error) {
      if (error instanceof Error && error.message === 'AgentBrowser command timed out') {
        throw new Error('AgentBrowser declared transition timed out');
      }
      throw error;
    }
  }

  private async count(selector: string): Promise<number> {
    const data = await this.command({ action: 'count', selector });
    if (typeof data.count !== 'number' || !Number.isSafeInteger(data.count)) {
      throw new Error('AgentBrowser count response is invalid');
    }
    return data.count;
  }

  private async validateTarget(selector: string, control: InjectControl): Promise<void> {
    if (!/^@e[0-9]+$/.test(selector)) {
      if (control === 'password' && !/type\s*=\s*["']?password["']?/i.test(selector)) {
        throw new Error('AgentBrowser cannot attest the declared password control');
      }
      await this.ensureUnique(selector);
      return;
    }
    const data = await this.command({ action: 'snapshot', interactive: true });
    const refs = data.refs;
    const id = selector.slice(1);
    const descriptor = isRecord(refs) ? refs[id] : undefined;
    if (!isRecord(descriptor) || descriptor.role !== 'textbox') {
      throw new Error('AgentBrowser declared field is unavailable');
    }
    const name = descriptor.name;
    if (control === 'password'
      && (typeof name !== 'string' || !/password/i.test(name))) {
      throw new Error('AgentBrowser password field attestation failed');
    }
    if (control === 'username'
      && (typeof name !== 'string' || !/(?:e-?mail|user(?:name)?|login)/i.test(name))) {
      throw new Error('AgentBrowser username field attestation failed');
    }
  }

  private async ensureUnique(selector: string): Promise<void> {
    if (/^@e[0-9]+$/.test(selector)) return;
    if (await this.count(selector) !== 1) {
      throw new Error('AgentBrowser declared selector is missing or ambiguous');
    }
  }

  private async command(
    body: Record<string, unknown>,
    timeoutMs = 30_000,
  ): Promise<Record<string, unknown>> {
    const socketPath = this.secureSocketPath();
    const id = randomBytes(16).toString('hex');
    const request = Buffer.from(`${JSON.stringify({ id, ...body })}\n`, 'utf8');
    if (request.length > 256 * 1024) {
      request.fill(0);
      throw new Error('AgentBrowser request is too large');
    }
    return await new Promise((resolve, reject) => {
      const socket = createConnection(socketPath);
      const chunks: Buffer[] = [];
      let length = 0;
      let settled = false;
      const finish = (error?: Error, value?: Record<string, unknown>): void => {
        if (settled) return;
        settled = true;
        socket.destroy();
        request.fill(0);
        for (const chunk of chunks) chunk.fill(0);
        if (error !== undefined) reject(error);
        else if (value !== undefined) resolve(value);
        else reject(new Error('AgentBrowser response is invalid'));
      };
      socket.setTimeout(timeoutMs, () => finish(new Error('AgentBrowser command timed out')));
      socket.once('error', () => finish(new Error('AgentBrowser daemon is unavailable')));
      socket.once('connect', () => {
        socket.write(request, () => request.fill(0));
      });
      socket.on('data', (chunk: Buffer) => {
        const newline = chunk.indexOf(0x0a);
        const part = newline === -1 ? chunk : chunk.subarray(0, newline);
        chunks.push(Buffer.from(part));
        length += part.length;
        if (length > MAX_RESPONSE_BYTES) {
          finish(new Error('AgentBrowser response is too large'));
          return;
        }
        if (newline === -1) return;
        let parsed: unknown;
        try {
          const response = Buffer.concat(chunks, length);
          try {
            parsed = JSON.parse(response.toString('utf8')) as unknown;
          } finally {
            response.fill(0);
          }
        } catch {
          finish(new Error('AgentBrowser response JSON is invalid'));
          return;
        }
        if (!isRecord(parsed) || parsed.id !== id || parsed.success !== true || !isRecord(parsed.data)) {
          finish(new Error('AgentBrowser rejected the browser operation'));
          return;
        }
        finish(undefined, parsed.data);
      });
      socket.once('end', () => finish(new Error('AgentBrowser daemon closed the channel')));
    });
  }

  private secureSocketPath(): string {
    if (process.platform === 'win32') {
      throw new Error('AgentBrowser Inject requires an authenticated Windows local pipe');
    }
    const directory = this.directory;
    const directoryInfo = lstatSync(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()
      || (process.getuid !== undefined && directoryInfo.uid !== process.getuid())) {
      throw new Error('AgentBrowser socket directory is unsafe');
    }
    chmodSync(directory, 0o700);
    const stream = join(directory, `${this.session}.stream`);
    if (existsSync(stream)) throw new Error('AgentBrowser streaming must be disabled during Inject');
    const version = readFileSync(join(directory, `${this.session}.version`), 'utf8').trim();
    if (version !== AGENT_BROWSER_VERSION) throw new Error('AgentBrowser version is unsupported');
    const socket = join(directory, `${this.session}.sock`);
    const socketInfo = lstatSync(socket);
    if (!socketInfo.isSocket() || socketInfo.isSymbolicLink()
      || (process.getuid !== undefined && socketInfo.uid !== process.getuid())) {
      throw new Error('AgentBrowser socket is unsafe');
    }
    chmodSync(socket, 0o600);
    return socket;
  }
}

function isDiscoveryVisibleUsername(entryFieldId: string, control: InjectControl): boolean {
  return entryFieldId === 'credential.username' && control === 'username';
}

function configuredSession(): string {
  const value = process.env.PALLADIN_AGENT_BROWSER_SESSION
    ?? process.env.AGENT_BROWSER_SESSION
    ?? 'default';
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw new Error('AgentBrowser session is invalid');
  return value;
}

function socketDirectory(namespace: string | undefined): string {
  const explicit = process.env.AGENT_BROWSER_SOCKET_DIR;
  const runtime = process.env.XDG_RUNTIME_DIR;
  let base = explicit && explicit.length > 0
    ? explicit
    : runtime && runtime.length > 0
      ? join(runtime, 'agent-browser')
      : homedir().length > 0
        ? join(homedir(), '.agent-browser')
        : join(tmpdir(), 'agent-browser');
  const safeNamespace = namespace === undefined ? '' : sanitize(namespace);
  if (safeNamespace.length > 0) base = join(base, 'namespaces', safeNamespace, 'run');
  return base;
}

function sanitize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^[-_]+|[-_]+$/g, '');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
