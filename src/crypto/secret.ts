/**
 * A decrypted credential's plaintext payload. The backend stores a JSON blob whose shape depends on
 * the entry type (see Vault Data Model):
 *   CREDENTIAL → { username, password, url?, notes? }
 *   KEY        → { value, notes? }
 *
 * `decryptCredential` returns the raw JSON string; this parses it into a typed structure the
 * exec/inject paths can use without each re-implementing the shape. Plaintext only — never log it.
 */
export interface ParsedSecret {
  /** CREDENTIAL username, or null for KEY entries. */
  username: string | null;
  /** CREDENTIAL password or KEY value — the primary secret. Never null after a successful parse. */
  password: string;
  url: string | null;
  notes: string | null;
  /** All key/value pairs from the payload, for env injection (CLAW_<UPPER> per field). */
  fields: Record<string, string>;
}

/**
 * Parse the decrypted plaintext. Accepts both entry shapes; falls back to treating the whole
 * plaintext as the secret value when it is not JSON (defensive — a future entry type or a raw
 * secret should still be usable by `exec`).
 */
export function parseSecret(plaintext: string): ParsedSecret {
  let raw: unknown;
  try {
    raw = JSON.parse(plaintext);
  } catch {
    return { username: null, password: plaintext, url: null, notes: null, fields: { value: plaintext } };
  }

  if (typeof raw !== 'object' || raw === null) {
    return { username: null, password: plaintext, url: null, notes: null, fields: { value: plaintext } };
  }

  const obj = raw as Record<string, unknown>;
  const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);

  const username = str(obj.username);
  // CREDENTIAL uses `password`, KEY uses `value`. Prefer the explicit one present.
  const password = str(obj.password) ?? str(obj.value) ?? '';

  const fields: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') {
      fields[k] = v;
    }
  }

  return {
    username,
    password,
    url: str(obj.url),
    notes: str(obj.notes),
    fields,
  };
}
