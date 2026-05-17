import { loadConfig } from '../config/config.js';
import { loadKeypair, publicKeyBase64 } from '../crypto/keypair.js';

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const config = loadConfig();
  const keypair = loadKeypair();

  const headers = new Headers(init?.headers);
  headers.set('X-Api-Key', config.apiKey);
  headers.set('X-Agent-Key', publicKeyBase64(keypair));
  headers.set('Content-Type', 'application/json');

  return fetch(`${config.host}${path}`, { ...init, headers });
}
