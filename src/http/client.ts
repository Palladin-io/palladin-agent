import os from 'os';
import { AgentConfig } from '../config/config.js';
import { Keypair, publicKeyBase64 } from '../crypto/keypair.js';
import { SigningKeypair, buildSignatureHeaders } from '../crypto/signing.js';

/**
 * Proof-of-possession material for request signing (CVT-157). When present, apiFetch adds the
 * X-Agent-Id / X-Agent-Timestamp / X-Agent-Nonce / X-Agent-Signature headers so the backend can
 * verify the request was signed by the agent's Ed25519 key.
 */
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
  // Only declare a JSON body when one is actually sent. On bodyless requests (GET) an
  // application/json content-type makes FastEndpoints bind the request from the (empty) body
  // and ignore query-string params — which 400s query-bound endpoints like entry discovery.
  const body = init?.body;
  if (body !== undefined && body !== null) {
    headers.set('Content-Type', 'application/json');
  }

  // Signature must cover the SAME bytes the server reads. The path is signed including its query
  // string; the canonical hashes the raw body bytes (empty body → sha256 of zero bytes).
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

/** The signed canonical hashes the raw body bytes. Only the body shapes the CLI sends are supported. */
function normalizeBody(body: BodyInit | null | undefined): string | Uint8Array {
  if (body === undefined || body === null) return '';
  if (typeof body === 'string') return body;
  if (body instanceof Uint8Array) return body;
  // The CLI only ever sends JSON strings (or no body). Anything else would sign a hash that does not
  // match the wire bytes, so fail loudly rather than send an unverifiable request.
  throw new Error('apiFetch: unsupported request body type for signing (expected string or Uint8Array)');
}
