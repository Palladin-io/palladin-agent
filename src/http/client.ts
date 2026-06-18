import os from 'os';
import { AgentConfig } from '../config/config.js';
import { Keypair, publicKeyBase64 } from '../crypto/keypair.js';
import { SigningKeypair, buildSignatureHeaders } from '../crypto/signing.js';

export interface SigningContext {
  agentId: string;
  keypair: SigningKeypair;
}

export async function apiFetch(
  path: string,
  config: AgentConfig,
  keypair: Keypair,
  init?: RequestInit,
  signing?: SigningContext,
): Promise<Response> {
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
