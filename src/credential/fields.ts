import { CustomField, ParsedSecret, parseTotpParams } from '../crypto/secret.js';
import { generateTotp } from './totp.js';

/** A `--field <label>` / `--field-id <uuid>` selector. At most one should be set. */
export interface FieldSelector {
  field?: string;
  fieldId?: string;
}

/**
 * The outcome of addressing a single field. `totp` carries only the derived short-lived code (never
 * the shared secret); `value` carries the field's plaintext for non-totp fields.
 */
export type ResolvedField =
  | { kind: 'value'; label: string; type: 'well-known' | 'text' | 'concealed' | 'multiline'; value: string }
  | { kind: 'totp'; label: string; code: string; expiresIn: number };

/** Thrown when a selector matches no field, or matches an ambiguous set (duplicate labels). */
export class FieldSelectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FieldSelectionError';
  }
}

// Well-known fields addressable by a stable alias regardless of entry type (spec §4).
const WELL_KNOWN_ALIASES = ['username', 'password', 'url', 'value', 'notes'] as const;
type WellKnownAlias = (typeof WELL_KNOWN_ALIASES)[number];

/**
 * Resolve a single field of a decrypted secret by label or id. Matching is case-insensitive and
 * trimmed. A totp field yields its current code + `expiresIn`; every other field yields its value.
 * Backend delivers the whole blob — this selection happens locally, in memory, after decryption.
 */
export function resolveField(secret: ParsedSecret, selector: FieldSelector): ResolvedField {
  if (selector.fieldId !== undefined) {
    return resolveById(secret, selector.fieldId.trim());
  }
  if (selector.field !== undefined) {
    return resolveByLabel(secret, selector.field.trim());
  }
  throw new FieldSelectionError('no field selector given (use --field <label> or --field-id <uuid>)');
}

/** The string value to inject for a resolved field — the code for totp, the plaintext otherwise. */
export function injectionValue(resolved: ResolvedField): string {
  return resolved.kind === 'totp' ? resolved.code : resolved.value;
}

function resolveById(secret: ParsedSecret, id: string): ResolvedField {
  const matches = secret.customFields.filter((f) => f.id === id);
  if (matches.length === 0) {
    throw new FieldSelectionError(`no custom field with id "${id}". ${availableHint(secret)}`);
  }
  return toResolved(matches[0]!);
}

function resolveByLabel(secret: ParsedSecret, label: string): ResolvedField {
  const lower = label.toLowerCase();

  const custom = secret.customFields.filter((f) => f.label.toLowerCase() === lower);
  if (custom.length > 1) {
    const ids = custom.map((f) => f.id).join(', ');
    throw new FieldSelectionError(`multiple fields are labelled "${label}" — disambiguate with --field-id <uuid>: ${ids}`);
  }
  if (custom.length === 1) {
    return toResolved(custom[0]!);
  }

  if ((WELL_KNOWN_ALIASES as readonly string[]).includes(lower)) {
    return resolveWellKnown(secret, lower as WellKnownAlias, label);
  }

  throw new FieldSelectionError(`no field named "${label}". ${availableHint(secret)}`);
}

function resolveWellKnown(secret: ParsedSecret, alias: WellKnownAlias, label: string): ResolvedField {
  const value = {
    username: secret.username,
    password: secret.password,
    // `value` addresses the primary secret (KEY value / CREDENTIAL password).
    value: secret.password,
    url: secret.url,
    notes: secret.notes,
  }[alias];

  if (value === null || value === undefined || value === '') {
    throw new FieldSelectionError(`this entry has no "${label}" field. ${availableHint(secret)}`);
  }
  return { kind: 'value', label: alias, type: 'well-known', value };
}

function toResolved(field: CustomField): ResolvedField {
  if (field.type === 'totp') {
    const params = parseTotpParams(field.value);
    if (!params) {
      throw new FieldSelectionError(`field "${field.label}" is a TOTP field but its descriptor is unreadable`);
    }
    const { code, expiresIn } = generateTotp(params);
    return { kind: 'totp', label: field.label, code, expiresIn };
  }
  return { kind: 'value', label: field.label, type: field.type, value: field.value };
}

/**
 * Redact TOTP shared secrets in a decrypted plaintext before it is surfaced by a full `get`: each
 * totp field's descriptor is replaced with the current code + expiry. The code suffices to complete
 * an MFA login; the long-lived shared secret never needs to enter an agent's context. Returns the
 * plaintext unchanged when it has no totp fields (or is not JSON).
 */
export function redactTotpSecrets(plaintext: string): string {
  let raw: unknown;
  try {
    raw = JSON.parse(plaintext);
  } catch {
    return plaintext;
  }
  if (typeof raw !== 'object' || raw === null || !Array.isArray((raw as Record<string, unknown>).fields)) {
    return plaintext;
  }

  const obj = raw as Record<string, unknown> & { fields: unknown[] };
  let redacted = false;
  obj.fields = obj.fields.map((field) => {
    if (typeof field !== 'object' || field === null) {
      return field;
    }
    const record = field as Record<string, unknown>;
    if (record.type !== 'totp') {
      return field;
    }
    const descriptor = typeof record.value === 'string' ? record.value : JSON.stringify(record.value);
    const params = parseTotpParams(descriptor);
    if (!params) {
      return field;
    }
    redacted = true;
    const { code, expiresIn } = generateTotp(params);
    return { ...record, value: { code, expiresIn, note: 'TOTP secret withheld — use --field to get a fresh code' } };
  });

  return redacted ? JSON.stringify(obj) : plaintext;
}

/** A value-free hint listing addressable field names, to guide a failed selection. */
function availableHint(secret: ParsedSecret): string {
  const wellKnown = WELL_KNOWN_ALIASES.filter((alias) => {
    const present = { username: secret.username, password: secret.password, value: secret.password, url: secret.url, notes: secret.notes }[alias];
    return present !== null && present !== undefined && present !== '';
  });
  const custom = secret.customFields.map((f) => f.label);
  const names = [...wellKnown, ...custom];
  return names.length > 0 ? `Available fields: ${names.join(', ')}.` : 'This entry has no addressable fields.';
}
