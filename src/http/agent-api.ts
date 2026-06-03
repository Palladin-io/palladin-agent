import os from 'os';
import { AgentConfig } from '../config/config.js';
import { Keypair, publicKeyBase64 } from '../crypto/keypair.js';
import { apiFetch } from './client.js';
import { EncryptedCredential } from '../crypto/decrypt.js';

export type AgentRegistrationResult =
  | { status: 'pending';     agentId: string }
  | { status: 'active';      agentId: string; name: string | null }
  | { status: 'deactivated'; agentId: string }
  | { status: 'invalid_key' }
  | { status: 'unreachable'; error: string };

export async function registerAgent(
  config: AgentConfig,
  keypair: Keypair,
  name?: string,
): Promise<AgentRegistrationResult> {
  const headers = new Headers({
    'X-Api-Key':         config.apiKey,
    'X-Agent-Key':       publicKeyBase64(keypair),
    'X-Agent-Hostname':  os.hostname(),
    'Content-Type':      'application/json',
  });

  if (name) {
    headers.set('X-Agent-Name', name);
  }

  let res: Response;
  try {
    res = await fetch(`${config.host}/api/agent/me`, { headers });
  } catch (err) {
    return { status: 'unreachable', error: String(err) };
  }

  if (res.status === 401) {
    const agentId = res.headers.get('X-Agent-Id');
    if (agentId) {
      return { status: 'pending', agentId };
    }
    return { status: 'invalid_key' };
  }

  if (res.ok) {
    const body = await res.json() as { id: string; name: string | null; status: string };
    if (body.status === 'Deactivated') {
      return { status: 'deactivated', agentId: body.id };
    }
    return { status: 'active', agentId: body.id, name: body.name };
  }

  return { status: 'unreachable', error: `HTTP ${res.status}` };
}

// ── Credential access flow (CVT-61) ──────────────────────────────────────────
// Grant lifecycle the agent drives: request-access (creates Pending grant) →
// poll status until Active → deliver (returns ciphertext, decrypted locally).

export type GrantStatus =
  | 'Pending' | 'Active' | 'Denied' | 'Revoked' | 'Expired' | 'Consumed';

export interface RequestAccessResult {
  grantId: string;
  status: GrantStatus;
}

export interface GrantStatusResult {
  grantId: string;
  status: GrantStatus;
  expiresAt: string | null;
  queryLimit: number | null;
}

/** Raised for any non-success HTTP response so callers can surface a clear message. */
export class AgentApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'AgentApiError';
  }
}

/**
 * Ask the user to grant access to a single entry. Idempotent server-side: an
 * existing Pending/Active grant for the same entry is returned as-is.
 */
export async function requestAccess(
  config: AgentConfig,
  keypair: Keypair,
  vaultId: string,
  entryId: string,
  reason: string,
): Promise<RequestAccessResult> {
  const res = await apiFetch(
    `/api/agent/vaults/${encodeURIComponent(vaultId)}/request-access`,
    config,
    keypair,
    { method: 'POST', body: JSON.stringify({ entryId, reason }) },
  );
  if (!res.ok) {
    throw new AgentApiError(res.status, `request-access failed (HTTP ${res.status})`);
  }
  return await res.json() as RequestAccessResult;
}

/** Poll the status of one of this agent's own grants. */
export async function getGrantStatus(
  config: AgentConfig,
  keypair: Keypair,
  vaultId: string,
  grantId: string,
): Promise<GrantStatusResult> {
  const res = await apiFetch(
    `/api/agent/vaults/${encodeURIComponent(vaultId)}/grants/${encodeURIComponent(grantId)}/status`,
    config,
    keypair,
  );
  if (res.status === 404) {
    throw new AgentApiError(404, 'Grant not found — it may belong to another agent or never existed.');
  }
  if (!res.ok) {
    throw new AgentApiError(res.status, `grant status failed (HTTP ${res.status})`);
  }
  return await res.json() as GrantStatusResult;
}

/**
 * Fetch the encrypted credential envelope. The ONLY call that returns ciphertext.
 * HTTP status codes are mapped to actionable errors:
 *   403 → grant expired
 *   404 → no active grant (request access first) / material not yet available
 *   429 → query limit reached (grant consumed)
 * Decryption is done by the caller via `decryptCredential` so the plaintext is
 * never marshalled through this transport layer.
 */
export async function deliverCredential(
  config: AgentConfig,
  keypair: Keypair,
  vaultId: string,
  entryId: string,
): Promise<{ entryId: string; label: string } & EncryptedCredential> {
  const res = await apiFetch(
    `/api/agent/vaults/${encodeURIComponent(vaultId)}/credentials/${encodeURIComponent(entryId)}`,
    config,
    keypair,
  );

  switch (res.status) {
    case 403:
      throw new AgentApiError(403, 'Grant expired — request access again.');
    case 404:
      throw new AgentApiError(404, 'No active grant for this entry — call request_access first and wait for approval.');
    case 429:
      throw new AgentApiError(429, 'Query limit reached — this grant is consumed. Request access again.');
  }
  if (!res.ok) {
    throw new AgentApiError(res.status, `credential delivery failed (HTTP ${res.status})`);
  }
  return await res.json() as { entryId: string; label: string } & EncryptedCredential;
}
