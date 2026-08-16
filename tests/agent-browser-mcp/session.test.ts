import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { AgentBrowserSession } from '../../packages/agent-browser-mcp/src/agent-browser.js';

const SESSION = 'palladin-test';
const FIXTURE_SECRET = 'fixture-value-not-production';
const form = {
  version: 1 as const,
  steps: [
    {
      fields: [{ entryFieldId: 'credential.username', selector: '@e17', control: 'username' as const }],
      submit: { action: 'press-enter' as const, selector: '@e17' },
      waitFor: { selector: '@e23', timeoutMs: 20_000 },
    },
    {
      fields: [{ entryFieldId: 'credential.password', selector: '@e23', control: 'password' as const }],
      submit: { action: 'press-enter' as const, selector: '@e23' },
    },
  ],
};

interface Command { action: string; selector?: string; value?: string; key?: string }
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => { while (cleanups.length > 0) await cleanups.pop()?.(); });

// Agent Browser's authenticated daemon transport is a Unix-domain socket. The
// production bridge intentionally fails closed on Windows until a separately
// authenticated Windows transport exists; don't turn that unsupported transport
// into a CI failure by attempting to bind a `.sock` path on Windows.
const describeAgentBrowser = process.platform === 'win32' ? describe.skip : describe;

describeAgentBrowser('AgentBrowser owner-only Inject channel', () => {
  it('executes the declared multi-step plan without a secret-bearing argv', async () => {
    const commands: Command[] = [];
    let url = 'https://x.com/i/flow/login';
    let passwordVisible = false;
    const fixture = await daemonFixture(async (command) => {
      commands.push(command);
      if (command.action === 'url') return { url };
      if (command.action === 'snapshot') return passwordVisible
        ? { refs: { e23: { role: 'textbox', name: 'Password' } } }
        : { refs: { e17: { role: 'textbox', name: 'Email or username' } } };
      if (command.action === 'wait') { passwordVisible = true; return {}; }
      if (command.action === 'press' && command.key === 'Enter' && passwordVisible) {
        url = 'https://x.com/home';
      }
      return {};
    });
    const session = new AgentBrowserSession(SESSION, undefined, fixture.directory);

    await session.inject({
      form,
      values: [
        { entryFieldId: 'credential.username', value: 'fixture-user' },
        { entryFieldId: 'credential.password', value: FIXTURE_SECRET },
      ],
    }, (activeUrl) => expect(new URL(activeUrl).hostname).toBe('x.com'));

    expect(commands.filter((command) => command.action === 'fill').map((command) => command.value))
      .toEqual(['fixture-user', FIXTURE_SECRET]);
    expect(commands.filter((command) => command.action === 'fill').map((command) => command.selector))
      .toEqual(['@e17', '@e23']);
    expect(process.argv).not.toContain(FIXTURE_SECRET);
  });

  it('fails closed when a declared accessibility ref does not match its control', async () => {
    const fixture = await daemonFixture(async (command) => {
      if (command.action === 'url') return { url: 'https://x.com/i/flow/login' };
      if (command.action === 'snapshot') return { refs: { e23: { role: 'textbox', name: 'Search' } } };
      return {};
    });
    const session = new AgentBrowserSession(SESSION, undefined, fixture.directory);
    const passwordOnly = { version: 1 as const, steps: [{
      fields: [{ entryFieldId: 'credential.password', selector: '@e23', control: 'password' as const }],
      submit: { action: 'press-enter' as const, selector: '@e23' },
    }] };

    await expect(session.inject({
      form: passwordOnly,
      values: [{ entryFieldId: 'credential.password', value: FIXTURE_SECRET }],
    }, () => undefined)).rejects.toThrow('password field attestation failed');
  });

  it('binds password attestation to the same selector used by the secret-bearing fill', async () => {
    const commands: Command[] = [];
    const fixture = await daemonFixture(async (command) => {
      commands.push(command);
      if (command.action === 'url') return { url: 'https://x.com/i/flow/login' };
      if (command.action === 'count') return { count: 1 };
      return {};
    });
    const session = new AgentBrowserSession(SESSION, undefined, fixture.directory);
    const passwordOnly = { version: 1 as const, steps: [{
      fields: [{
        entryFieldId: 'credential.password',
        selector: 'input[type="password"], input[name="otp"]',
        control: 'password' as const,
      }],
      submit: { action: 'press-enter' as const, selector: 'input[name="otp"]' },
    }] };

    await session.inject({
      form: passwordOnly,
      values: [{ entryFieldId: 'credential.password', value: FIXTURE_SECRET }],
    }, () => undefined);

    const expected = 'input[type="password" i]:is(input[type="password"], input[name="otp"])';
    expect(commands.find((command) => command.action === 'count')?.selector).toBe(expected);
    expect(commands.find((command) => command.action === 'fill' && command.value === FIXTURE_SECRET)?.selector)
      .toBe(expected);
    expect(commands.some((command) => command.action === 'evaluate')).toBe(false);
  });

  it('fails closed if the hardened password selector no longer matches at fill time', async () => {
    const commands: Command[] = [];
    const fixture = await daemonFixture(async (command) => {
      commands.push(command);
      if (command.action === 'url') return { url: 'https://x.com/i/flow/login' };
      if (command.action === 'count') return { count: 1 };
      if (command.action === 'fill' && command.value === FIXTURE_SECRET) {
        throw new Error('the page replaced the password input with an OTP input');
      }
      return {};
    });
    const session = new AgentBrowserSession(SESSION, undefined, fixture.directory);
    const passwordOnly = { version: 1 as const, steps: [{
      fields: [{
        entryFieldId: 'credential.password',
        selector: 'input[type="password"], input[name="otp"]',
        control: 'password' as const,
      }],
      submit: { action: 'press-enter' as const, selector: 'input[name="otp"]' },
    }] };

    await expect(session.inject({
      form: passwordOnly,
      values: [{ entryFieldId: 'credential.password', value: FIXTURE_SECRET }],
    }, () => undefined)).rejects.toThrow('AgentBrowser rejected the browser operation');

    const secretFill = commands.find(
      (command) => command.action === 'fill' && command.value === FIXTURE_SECRET,
    );
    expect(secretFill?.selector).toBe(
      'input[type="password" i]:is(input[type="password"], input[name="otp"])',
    );
    expect(commands.some((command) => command.action === 'evaluate')).toBe(false);
  });

  it('retains the Discovery-visible username but clears a filled password after rejection', async () => {
    const commands: Command[] = [];
    const fixture = await daemonFixture(async (command) => {
      commands.push(command);
      if (command.action === 'url') return { url: 'https://x.com/i/flow/login' };
      if (command.action === 'snapshot') {
        return { refs: {
          e17: { role: 'textbox', name: 'Email or username' },
          e23: { role: 'textbox', name: 'Password' },
        } };
      }
      if (command.action === 'press') throw new Error('site rejected');
      return {};
    });
    const session = new AgentBrowserSession(SESSION, undefined, fixture.directory);
    const oneStep = { version: 1 as const, steps: [{
      fields: [
        { entryFieldId: 'credential.username', selector: '@e17', control: 'username' as const },
        { entryFieldId: 'credential.password', selector: '@e23', control: 'password' as const },
      ],
      submit: { action: 'press-enter' as const, selector: '@e23' },
    }] };

    await expect(session.inject({
      form: oneStep,
      values: [
        { entryFieldId: 'credential.username', value: 'fixture-user' },
        { entryFieldId: 'credential.password', value: FIXTURE_SECRET },
      ],
    }, () => undefined)).rejects.toThrow('AgentBrowser rejected the browser operation');

    expect(commands.filter((command) => command.action === 'fill'))
      .toEqual([
        expect.objectContaining({ selector: '@e17', value: 'fixture-user' }),
        expect.objectContaining({ selector: '@e23', value: FIXTURE_SECRET }),
        expect.objectContaining({ selector: '@e23', value: '' }),
      ]);
  });

  it('fails closed while AgentBrowser streaming could broadcast daemon commands', async () => {
    const fixture = await daemonFixture(async () => ({ url: 'https://x.com/' }));
    await writeFile(join(fixture.directory, `${SESSION}.stream`), 'active', { mode: 0o600 });
    const session = new AgentBrowserSession(SESSION, undefined, fixture.directory);
    await expect(session.currentUrl()).rejects.toThrow('streaming must be disabled');
  });
});

async function daemonFixture(
  handler: (command: Command) => Promise<Record<string, unknown>>,
): Promise<{ directory: string }> {
  const directory = await mkdtemp(join(tmpdir(), 'palladin-agent-browser-'));
  await chmod(directory, 0o700);
  await writeFile(join(directory, `${SESSION}.version`), '0.33.2\n', { mode: 0o600 });
  const socketPath = join(directory, `${SESSION}.sock`);
  const server = createServer((socket) => {
    let pending = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      const newline = pending.indexOf(0x0a);
      if (newline === -1) return;
      const frame = pending.subarray(0, newline).toString('utf8');
      pending.fill(0); pending = Buffer.alloc(0);
      const parsed = JSON.parse(frame) as Command & { id: string };
      void handler(parsed).then(
        (data) => socket.end(`${JSON.stringify({ id: parsed.id, success: true, data })}\n`),
        () => socket.end(`${JSON.stringify({ id: parsed.id, success: false, error: 'failed' })}\n`),
      );
    });
  });
  await listen(server, socketPath);
  await chmod(socketPath, 0o600);
  cleanups.push(async () => { await close(server); await rm(directory, { recursive: true, force: true }); });
  return { directory };
}

function listen(server: Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => { server.removeListener('error', reject); resolve(); });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}
