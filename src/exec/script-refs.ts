import { ParsedSecret, ScriptRef } from '../crypto/secret.js';
import { resolveField, injectionValue, FieldSelectionError } from '../credential/fields.js';

/** How a single referenced entry is delivered — the agent's own grant flow, adapted per caller. */
export type RefDelivery = { ok: true; secret: ParsedSecret } | { ok: false; message: string };
export type RefResolver = (ref: ScriptRef) => Promise<RefDelivery>;

export type PreparedScriptEnv =
  | { ok: true; env: Record<string, string>; secretValues: string[] }
  | { ok: false; message: string };

// A script reference maps to a real POSIX-ish env var name; reject anything that isn't one so we
// never write a surprising key into the child's environment.
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Deliver every declared script reference through the agent's own grants and build the environment
 * for the subprocess. Runs to completion BEFORE any script executes: a single missing grant, missing
 * vaultId, or bad env name aborts the whole run with a clear message and nothing is executed.
 *
 * Reference values are injected as env vars named exactly `ref.env` and never printed to stdout.
 */
export async function prepareScriptEnv(refs: ScriptRef[], resolve: RefResolver): Promise<PreparedScriptEnv> {
  const env: Record<string, string> = {};
  const secretValues: string[] = [];

  for (const ref of refs) {
    if (!ENV_NAME_RE.test(ref.env)) {
      return { ok: false, message: `invalid env var name "${ref.env}" in a script reference.` };
    }
    if (!ref.vaultId) {
      return {
        ok: false,
        message: `script reference "${ref.env}" (entry ${ref.entryId}) is missing its vaultId — re-save the script entry in the panel.`,
      };
    }

    const delivery = await resolve(ref);
    if (!delivery.ok) {
      return {
        ok: false,
        message:
          `cannot run: the referenced entry for "${ref.env}" (${ref.entryId}) is not available — ${delivery.message} ` +
          `Request it with: palladin get ${ref.vaultId} ${ref.entryId} --reason "…"`,
      };
    }

    let value: string;
    try {
      value = ref.field
        ? injectionValue(resolveField(delivery.secret, { field: ref.field }))
        : delivery.secret.password;
    } catch (err) {
      if (err instanceof FieldSelectionError) {
        return { ok: false, message: `script reference "${ref.env}" (${ref.entryId}): ${err.message}` };
      }
      throw err;
    }

    env[ref.env] = value;
    if (value) {
      secretValues.push(value);
    }
  }

  return { ok: true, env, secretValues };
}
