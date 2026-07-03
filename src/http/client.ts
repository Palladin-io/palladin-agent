import os from 'os';
import { AgentConfig } from '../config/config.js';
import { Keypair, publicKeyBase64 } from '../crypto/keypair.js';
import { SigningKeypair, buildSignatureHeaders } from '../crypto/signing.js';

export interface SigningContext {
  agentId: string;
  keypair: SigningKeypair;
}

/**
 * Loopback hosts where plaintext http is acceptable for local development.
 *
 * `*.localhost` is trusted as a deliberate dev-only trade-off: RFC 6761 reserves it for loopback,
 * but resolution ultimately goes through the system resolver, so a hostile `/etc/hosts` could point
 * `foo.localhost` elsewhere. That only matters to an attacker already on the machine (who has lost
 * the game anyway); we keep the subdomain form because local dev commonly uses it.
 */
export function isLocalHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return h === 'localhost' || h.endsWith('.localhost') || h === '127.0.0.1' || h === '::1' || h === '[::1]';
}

/**
 * Reject any host that would send the API key in cleartext (CVT-219). `https://` is always allowed;
 * `http://` is allowed only for loopback hosts (local dev). Any other scheme, or `http://` to a
 * remote host, throws — the API key is a bearer secret and must never travel unencrypted.
 */
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
  // Defence in depth: a hand-edited config could point at an http:// remote — never leak the key.
  assertSecureHost(config.host);

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
