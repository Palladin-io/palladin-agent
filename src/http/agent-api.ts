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

// ── Discovery (CVT-144) ──────────────────────────────────────────────────────
// Org-wide entry search. Metadata only — never ciphertext. Starting point of the
// flow: search_entries → request_access → get_grant_status → retrieve_credential.

export interface EntrySearchItem {
  entryId: string;
  vaultId: string;
  label: string;
  urlDomain: string | null;
  description: string | null;
}

export interface EntrySearchResult {
  items: EntrySearchItem[];
  nextCursor: string | null;
}

/**
 * Search entry metadata across every vault in the agent's organization.
 * `query` must be at least 2 characters (server-enforced MinLength 2).
 */
export async function searchEntries(
  config: AgentConfig,
  keypair: Keypair,
  query: string,
  options?: { cursor?: string; pageSize?: number },
): Promise<EntrySearchResult> {
  const params = new URLSearchParams({ query });
  if (options?.cursor) params.set('cursor', options.cursor);
  if (options?.pageSize) params.set('pageSize', String(options.pageSize));

  const res = await apiFetch(`/api/agent/entries?${params.toString()}`, config, keypair);
  if (!res.ok) {
    throw new AgentApiError(res.status, `entry search failed (HTTP ${res.status})`);
  }
  return await res.json() as EntrySearchResult;
}

// ── Inject failure telemetry (CVT-155) ───────────────────────────────────────
// Reports a REDACTED inject diagnostic to the backend so the team sees unsupported
// sites in near-real-time. Carries no field values, no secret, only the origin.

export interface InjectFailureUpload {
  entryId: string;
  domain: string | null;
  reason: string;
  pageOrigin: string | null;
  controls: unknown[];
}

/**
 * Best-effort upload of a redacted inject-failure report. Never throws — telemetry must not break
 * the command, and the local JSONL copy is the offline fallback. Returns true when the backend
 * accepted it. Disabled by CLAW_VAULT_NO_DIAGNOSTICS=1.
 */
export async function uploadInjectFailure(
  config: AgentConfig,
  keypair: Keypair,
  body: InjectFailureUpload,
): Promise<boolean> {
  if (process.env['CLAW_VAULT_NO_DIAGNOSTICS'] === '1') {
    return false;
  }
  try {
    const res = await apiFetch('/api/agent/inject-failures', config, keypair, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Stale-credential reporting (CVT-162 — Notification Center) ────────────────
// The agent tells the backend that a stored credential did not work (wrong/expired
// password, login refused). The backend turns this into a `credential_stale`
// notification for the vault's members (see Notification Center design). Carries
// no secret and no field values — only the entry/vault reference + a redacted
// reason/code. Reporting a stale credential does NOT create a new one — issuing a
// fresh credential stays a human action in the panel for now.

/** Why the credential is being reported as not working. Mirrors the values the backend expects. */
export type StaleReasonCode =
  /** A login attempt was refused (e.g. inject observed a `rejected` outcome / 401). */
  | 'login_rejected'
  /** The agent could not authenticate with the credential through some other path. */
  | 'auth_failed'
  /** The user/agent is reporting it manually with no machine signal. */
  | 'manual';

export interface ReportCredentialStaleInput {
  vaultId: string;
  entryId: string;
  /** Machine-readable cause, defaults to `manual`. */
  code?: StaleReasonCode;
  /** Optional free-text note for the vault owner. NEVER include the secret or typed values. */
  note?: string;
}

/**
 * Report a credential as not working so the backend emits `credential_stale` to the vault members.
 *
 * Manual reports (the `report-stale` command) surface a clear error on failure so the agent knows
 * the report did not land. The inject/exec auto-report path wraps this in {@link tryReportCredentialStale},
 * which is best-effort and never throws (telemetry must not break the command).
 *
 * Disabled by CLAW_VAULT_NO_DIAGNOSTICS=1 — like the inject-failure telemetry, this is a diagnostic
 * signal and respects the same opt-out.
 *
 * NOTE (backend contract, to sync with CVT-163): assumed agent-facing endpoint
 *   POST /api/agent/vaults/{vaultId}/entries/{entryId}/credential-failure
 *   body { code, note? }  → 200/202 on accept
 * Headers are the standard agent auth set (X-Api-Key, X-Agent-Key, X-Agent-Hostname) added by apiFetch.
 */
export async function reportCredentialStale(
  config: AgentConfig,
  keypair: Keypair,
  input: ReportCredentialStaleInput,
): Promise<void> {
  const body: Record<string, unknown> = { code: input.code ?? 'manual' };
  if (input.note) {
    body.note = input.note;
  }

  const res = await apiFetch(
    `/api/agent/vaults/${encodeURIComponent(input.vaultId)}/entries/${encodeURIComponent(input.entryId)}/credential-failure`,
    config,
    keypair,
    { method: 'POST', body: JSON.stringify(body) },
  );

  if (!res.ok) {
    throw new AgentApiError(res.status, `could not report the credential as stale (HTTP ${res.status})`);
  }
}

/**
 * Best-effort variant of {@link reportCredentialStale} for the inject/exec auto-report path: returns
 * `true` when the backend accepted the report, `false` on any error or when diagnostics are opted
 * out. Never throws — an auto-report failure must not mask the real command result.
 */
export async function tryReportCredentialStale(
  config: AgentConfig,
  keypair: Keypair,
  input: ReportCredentialStaleInput,
): Promise<boolean> {
  if (process.env['CLAW_VAULT_NO_DIAGNOSTICS'] === '1') {
    return false;
  }
  try {
    await reportCredentialStale(config, keypair, input);
    return true;
  } catch {
    return false;
  }
}

/** Raised for any non-success HTTP response so callers can surface a clear message. */
export class AgentApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'AgentApiError';
  }
}

// ── Unified credential access (CVT-61) ───────────────────────────────────────
// A single call drives the whole flow. The agent calls get_credential; if it has
// no grant yet the server creates a pending one (user approves in the panel) and
// returns access:"pending". The agent calls again; once approved the server
// returns access:"granted" with the encrypted envelope, decrypted locally.

/** How the agent intends to use the credential (CVT-149). Mirrors backend GrantMethods flag names. */
export type CredentialMethod = 'get' | 'exec' | 'inject';

/** Discriminated result of POST .../credential, keyed on `access`. */
export type CredentialAccess =
  /**
   * Approved: encrypted envelope present, decrypt locally. `urlDomain` is the entry's backend-bound
   * domain — the TRUSTED source for inject's anti-phishing origin check (never the page or agent).
   */
  | ({ access: 'granted'; entryId: string; label: string; urlDomain: string | null } & EncryptedCredential)
  /**
   * Awaiting user approval. `created` = the grant was just requested by this call. The optional
   * `pollIntervalMs` / `maxWaitMs` are the org's approval-wait policy (CVT-157) — the CLI uses them
   * as defaults for its long-poll when no explicit `--wait` / `--poll-interval` flag is given.
   */
  | { access: 'pending'; grantId: string; created?: boolean; pollIntervalMs?: number; maxWaitMs?: number }
  /** Terminal "no access" states. */
  | { access: 'denied' }
  | { access: 'revoked' }
  | { access: 'expired' }
  | { access: 'consumed' }
  /** The grant does not whitelist the method the agent asked for (CVT-149). */
  | { access: 'method-not-allowed' }
  /** FULL grant covers the entry but no wrapped material exists yet. */
  | { access: 'unavailable' }
  /** Agent is deactivated. */
  | { access: 'blocked' };

/**
 * Get (or request) a credential in one call.
 *
 * The endpoint encodes the outcome in the `access` field across several HTTP
 * statuses (200/202/403/429), so any of those carries a valid body we parse.
 * Only a genuine transport/validation failure (e.g. 400 "reason required", 5xx)
 * is surfaced as an AgentApiError. Decryption is left to the caller so plaintext
 * never passes through this transport layer.
 */
export interface GetCredentialOptions {
  reason?: string;
  /** Delivery method the agent intends to use (CVT-149). Defaults server-side to `get`. */
  method?: CredentialMethod;
  /**
   * Methods to put on the grant if this call has to create a Pending one. Defaults server-side to
   * the delivery method, so a plain `exec` call requests exec access.
   */
  requestedMethods?: CredentialMethod[];
}

export async function getCredential(
  config: AgentConfig,
  keypair: Keypair,
  vaultId: string,
  entryId: string,
  options?: GetCredentialOptions,
): Promise<CredentialAccess> {
  const body: Record<string, unknown> = {};
  if (options?.reason) {
    body.reason = options.reason;
  }
  if (options?.method) {
    body.method = methodFlag(options.method);
  }
  if (options?.requestedMethods && options.requestedMethods.length > 0) {
    body.requestedMethods = options.requestedMethods.map(methodFlag).join(', ');
  }

  const res = await apiFetch(
    `/api/agent/vaults/${encodeURIComponent(vaultId)}/entries/${encodeURIComponent(entryId)}/credential`,
    config,
    keypair,
    { method: 'POST', body: JSON.stringify(body) },
  );

  // 200 (granted/unavailable), 202 (pending), 403 (denied/revoked/expired/blocked/method-not-allowed)
  // and 429 (consumed) all return a JSON body with the `access` discriminator.
  if (res.status === 200 || res.status === 202 || res.status === 403 || res.status === 429) {
    return await res.json() as CredentialAccess;
  }

  if (res.status === 400) {
    throw new AgentApiError(400, 'A reason is required to request access to this entry — pass --reason.');
  }
  throw new AgentApiError(res.status, `credential request failed (HTTP ${res.status})`);
}

// The backend binds GrantMethods (a [Flags] enum) from its PascalCase member names.
function methodFlag(method: CredentialMethod): string {
  return { get: 'Get', exec: 'Exec', inject: 'Inject' }[method];
}
