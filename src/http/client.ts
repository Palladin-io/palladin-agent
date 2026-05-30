import os from 'os';
import { AgentConfig } from '../config/config.js';
import { Keypair, publicKeyBase64 } from '../crypto/keypair.js';

export async function apiFetch(
  path: string,
  config: AgentConfig,
  keypair: Keypair,
  init?: RequestInit,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set('X-Api-Key',        config.apiKey);
  headers.set('X-Agent-Key',      publicKeyBase64(keypair));
  headers.set('X-Agent-Hostname', os.hostname());
  headers.set('Content-Type',     'application/json');
  return fetch(`${config.host}${path}`, { ...init, headers });
}
