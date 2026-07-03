import os from 'os';
import { AgentConfig } from '../config/config.js';
import { Keypair, publicKeyBase64 } from '../crypto/keypair.js';
import { SigningKeypair, buildSignatureHeaders } from '../crypto/signing.js';

export interface SigningContext {
  agentId: string;
  keypair: SigningKeypair;
}

/** Loopback hosts where plaintext http is acceptable for local dev. `*.localhost` is trusted despite relying on the system resolver — only exploitable by an attacker already on the machine. */
export function isLocalHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return h === 'localhost' || h.endsWith('.localhost') || h === '127.0.0.1' || h === '::1' || h === '[::1]';
}

/** Reject any host that would send the API key in cleartext: https always, http only for loopback. */
export function assertSecureHost(host: string): void {
  let url: URL;
  try {
    url = new URL(host);
  } catch {
    throw new Error(`Invalid --host URL: "${host}"`);
  }
  if (url.protocol === 'https:') return;
  if (url.protocol === 'http:' && isLocalHost(url.hostname)) return;
  if (url.protocol === 'http:') {
    throw new Error(
      `Refusing to connect over http:// to "${url.hostname}" — the API key would be sent in cleartext. ` +
        'Use https:// (http:// is allowed only for localhost).',
    );
  }
  throw new Error(`Unsupported --host scheme "${url.protocol}" — use https:// (or http:// for localhost).`);
}

export async function apiFetch(
  path: string,
  config: AgentConfig,
  keypair: Keypair,
  init?: RequestInit,
  signing?: SigningContext,
): Promise<Response> {
  assertSecureHost(config.host); // defence in depth: a hand-edited config could point http:// remote
  const headers = new Headers(init?.headers);
  headers.set('X-Api-Key',        config.apiKey);
  headers.set('X-Agent-Key',      publicKeyBase64(keypair));
  headers.set('X-Agent-Hostname', os.hostname());
  // No JSON content-type on bodyless GETs — FastEndpoints would bind from the empty body and ignore query params.
  const body = init?.body;
  if (body !== undefined && body !== null) {
    headers.set('Content-Type', 'application/json');
  }

  if (signing) {
    const sig = await buildSignatureHeaders({
      agentId: signing.agentId,
      keypair: signing.keypair,
      method: init?.method ?? 'GET',
      pathWithQuery: path,
      body: normalizeBody(body),
    });
    for (const [k, v] of Object.entries(sig)) {
      headers.set(k, v);
    }
  }

  return fetch(`${config.host}${path}`, { ...init, headers });
}

function normalizeBody(body: BodyInit | null | undefined): string | Uint8Array {
  if (body === undefined || body === null) return '';
  if (typeof body === 'string') return body;
  if (body instanceof Uint8Array) return body;
  // Anything else would sign a hash that doesn't match the wire bytes.
  throw new Error('apiFetch: unsupported request body type for signing (expected string or Uint8Array)');
}
