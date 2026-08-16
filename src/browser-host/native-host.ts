#!/usr/bin/env node

import { chmodSync } from 'node:fs';
import { createServer, type Socket } from 'node:net';

import { ChromeNativeChannel, JsonLineChannel } from './channel.js';
import { browserHostSocketPath, prepareBrowserHostSocket } from './socket.js';
import { parseInjectForm, parseInjectValues } from '../inject-contract.js';

const PROTOCOL = 'palladin.inject-provider.v1';
const native = new ChromeNativeChannel(process.stdin, process.stdout);
let busy = false;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function serveClient(socket: Socket): Promise<void> {
  if (busy) { socket.end(); return; }
  busy = true;
  const local = new JsonLineChannel(socket, socket);
  try {
    const prepare = await local.read();
    if (!isRecord(prepare) || prepare.protocol !== PROTOCOL || prepare.type !== 'prepare'
      || typeof prepare.nonce !== 'string') throw new Error('invalid prepare');
    native.write(prepare);
    const prepared = await native.read();
    if (!isRecord(prepared) || prepared.protocol !== PROTOCOL || prepared.type !== 'prepare.result'
      || prepared.nonce !== prepare.nonce) throw new Error('invalid prepare result');
    local.write(prepared);
    if (prepared.outcome !== 'ready') { local.end(); return; }

    const credential = await local.read();
    const form = isRecord(credential) ? parseInjectForm(credential.form) : null;
    if (!isRecord(credential) || credential.protocol !== PROTOCOL || credential.type !== 'credential'
      || credential.provider !== 'extension' || credential.nonce !== prepare.nonce
      || typeof credential.transactionId !== 'string' || form === null
      || parseInjectValues(credential.values, form) === null) throw new Error('invalid credential frame');
    const injection: Record<string, unknown> = { ...credential, type: 'inject' };
    delete injection.provider;
    delete injection.nonce;
    native.write(injection);
    const outcome = await native.read();
    if (!isRecord(outcome) || outcome.protocol !== PROTOCOL || outcome.type !== 'inject.result'
      || outcome.transactionId !== credential.transactionId) throw new Error('invalid injection result');
    local.end(outcome);
  } catch {
    socket.destroy();
  } finally {
    busy = false;
  }
}

try {
  if (process.platform === 'win32') throw new Error('Windows requires the brokered pipe host');
  prepareBrowserHostSocket();
  const server = createServer((socket) => void serveClient(socket));
  server.listen(browserHostSocketPath, () => chmodSync(browserHostSocketPath, 0o600));
  process.once('SIGTERM', () => server.close());
  process.once('SIGINT', () => server.close());
} catch {
  process.stderr.write('Error: Palladin browser host could not start\n');
  process.exitCode = 1;
}
