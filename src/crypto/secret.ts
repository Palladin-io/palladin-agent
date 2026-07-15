import { TotpParams } from '../credential/totp.js';

/** A v2 custom field's type. Unknown types are ignored at parse time (forward-compat, spec §1). */
export type CustomFieldType = 'text' | 'concealed' | 'multiline' | 'totp';

const KNOWN_FIELD_TYPES: readonly CustomFieldType[] = ['text', 'concealed', 'multiline', 'totp'];

/**
 * An additive v2 custom field carried in the blob's `fields[]` array. `value` holds the raw string
 * for text/concealed/multiline fields, or a JSON-encoded {@link TotpParams} descriptor for `totp`
 * fields — the TOTP secret, never a computed code.
 */
export interface CustomField {
  id: string;
  label: string;
  type: CustomFieldType;
  value: string;
  /** User marked this field as visible to agents (metadata hint; not enforced by the CLI). */
  agentVisible?: boolean;
}

/** A declared env-var → referenced-entry mapping in a Script entry (spec §5). */
export interface ScriptRef {
  /** The environment variable name the script reads (e.g. `GITHUB_TOKEN`). */
  env: string;
  vaultId: string | null;
  entryId: string;
  /** Which field of the referenced entry supplies the value (default: the primary secret). */
  field: string | null;
}

/** The decrypted payload of a Script entry (spec §5). */
export interface ScriptPayload {
  script: string;
  interpreter: string;
  refs: ScriptRef[];
}

/**
 * A decrypted credential's plaintext payload. The backend stores a JSON blob whose shape depends on
 * the entry type (see Vault Data Model):
 *   CREDENTIAL → { username, password, url?, notes? }
 *   KEY        → { value, notes? }
 *   SCRIPT     → { script, interpreter, refs?, notes? }
 * v2 blobs additionally carry `fields[]` (custom fields) alongside the well-known keys; a missing
 * `v` is treated as v1 (spec §1). Unknown keys and unknown field types are ignored, never rejected.
 *
 * `decryptCredential` returns the raw JSON string; this parses it into a typed structure the
 * get/exec/inject paths can use without each re-implementing the shape. Plaintext only — never log it.
 */
export interface ParsedSecret {
  /** CREDENTIAL username, or null for KEY/SCRIPT entries. */
  username: string | null;
  /** CREDENTIAL password or KEY value — the primary secret. Empty string for a SCRIPT entry. */
  password: string;
  url: string | null;
  notes: string | null;
  /** Legacy top-level otpauth URI from imported CREDENTIAL blobs. Never added to `fields`. */
  legacyTotp: string | null;
  /**
   * Well-known + non-totp custom fields, keyed for env injection (`CLAW_<UPPER>`). Excludes totp
   * secrets (a code is derived on demand instead) and Script structural keys.
   */
  fields: Record<string, string>;
  /** Structured v2 custom fields, including totp descriptors. Empty for a v1 blob. */
  customFields: CustomField[];
  /** Present only for SCRIPT entries; null otherwise. */
  script: ScriptPayload | null;
}

// Top-level keys that carry structure, not an injectable well-known value.
const STRUCTURAL_KEYS = new Set(['v', 'fields', 'script', 'interpreter', 'refs', 'totp']);

/**
 * Parse the decrypted plaintext. Accepts every entry shape; falls back to treating the whole
 * plaintext as the secret value when it is not JSON (defensive — a raw secret should still be usable
 * by `get`/`exec`).
 */
export function parseSecret(plaintext: string): ParsedSecret {
  let raw: unknown;
  try {
    raw = JSON.parse(plaintext);
  } catch {
    return rawSecret(plaintext);
  }

  if (typeof raw !== 'object' || raw === null) {
    return rawSecret(plaintext);
  }

  const obj = raw as Record<string, unknown>;
  const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);

  const customFields = parseCustomFields(obj.fields);
  const script = parseScript(obj);

  const username = str(obj.username);
  // CREDENTIAL uses `password`, KEY uses `value`. SCRIPT has neither — leave it empty.
  const password = str(obj.password) ?? str(obj.value) ?? '';

  const fields: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string' && !STRUCTURAL_KEYS.has(k)) {
      fields[k] = v;
    }
  }
  // Expose non-totp custom fields for env injection under a sanitised, upper-snake key. Totp fields
  // are omitted: their `value` is the shared secret, and only a short-lived code may be surfaced.
  for (const field of customFields) {
    if (field.type === 'totp') {
      continue;
    }
    const key = envFieldKey(field.label);
    if (key && !(key in fields)) {
      fields[key] = field.value;
    }
  }

  return {
    username,
    password,
    url: str(obj.url),
    notes: str(obj.notes),
    legacyTotp: str(obj.totp),
    fields,
    customFields,
    script,
  };
}

function rawSecret(plaintext: string): ParsedSecret {
  return {
    username: null,
    password: plaintext,
    url: null,
    notes: null,
    legacyTotp: null,
    fields: { value: plaintext },
    customFields: [],
    script: null,
  };
}

function parseCustomFields(value: unknown): CustomField[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const fields: CustomField[] = [];
  for (const entry of value) {
    if (typeof entry !== 'object' || entry === null) {
      continue;
    }
    const record = entry as Record<string, unknown>;
    const id = typeof record.id === 'string' ? record.id : null;
    const label = typeof record.label === 'string' ? record.label.trim() : null;
    const type = record.type;
    // Web/mobile write a totp field's value as a JSON OBJECT descriptor; normalise it to the
    // JSON-encoded string form so CustomField.value stays a string everywhere downstream.
    const fieldValue =
      typeof record.value === 'string'
        ? record.value
        : typeof record.value === 'object' && record.value !== null
          ? JSON.stringify(record.value)
          : null;
    // A field missing id/label/value is malformed; an unknown type is ignored (forward-compat).
    if (id === null || label === null || fieldValue === null) {
      continue;
    }
    if (typeof type !== 'string' || !KNOWN_FIELD_TYPES.includes(type as CustomFieldType)) {
      continue;
    }
    const field: CustomField = { id, label, type: type as CustomFieldType, value: fieldValue };
    if (record.agentVisible === true) {
      field.agentVisible = true;
    }
    fields.push(field);
  }
  return fields;
}

function parseScript(obj: Record<string, unknown>): ScriptPayload | null {
  const script = typeof obj.script === 'string' ? obj.script : null;
  const interpreter = typeof obj.interpreter === 'string' ? obj.interpreter.trim() : null;
  if (script === null || interpreter === null) {
    return null;
  }
  return { script, interpreter, refs: parseScriptRefs(obj.refs) };
}

function parseScriptRefs(value: unknown): ScriptRef[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error('Script entry contains malformed credential references');
  }
  const refs: ScriptRef[] = [];
  for (const entry of value) {
    if (typeof entry !== 'object' || entry === null) {
      throw new Error('Script entry contains a malformed credential reference');
    }
    const record = entry as Record<string, unknown>;
    // Accept `placeholder` as a legacy alias for `env` (spec draft §1).
    const envRaw =
      typeof record.env === 'string' ? record.env : typeof record.placeholder === 'string' ? record.placeholder : null;
    const env = envRaw?.trim() ?? null;
    const entryId = typeof record.entryId === 'string' ? record.entryId.trim() : null;
    if (!env || !entryId) {
      throw new Error('Script entry contains a malformed credential reference');
    }
    const vaultId = typeof record.vaultId === 'string' && record.vaultId.trim() ? record.vaultId.trim() : null;
    const field = typeof record.field === 'string' && record.field.trim() ? record.field.trim() : null;
    refs.push({ env, vaultId, entryId, field });
  }
  return refs;
}

/** Descriptor of a totp field parsed from its JSON `value`, or null if the value is not a descriptor. */
export function parseTotpParams(value: string): TotpParams | null {
  let raw: unknown;
  try {
    raw = JSON.parse(value);
  } catch {
    return null;
  }
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const record = raw as Record<string, unknown>;
  if (typeof record.secret !== 'string') {
    return null;
  }
  const params: TotpParams = { secret: record.secret };
  if (record.algorithm === 'SHA1' || record.algorithm === 'SHA256' || record.algorithm === 'SHA512') {
    params.algorithm = record.algorithm;
  }
  if (typeof record.digits === 'number') {
    params.digits = record.digits;
  }
  if (typeof record.period === 'number') {
    params.period = record.period;
  }
  return params;
}

/** Sanitise a field label into an env-var-safe key fragment (`Recovery email` → `RECOVERY_EMAIL`). */
export function envFieldKey(label: string): string {
  return label
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
}
