import { z } from 'zod';
import { AgentConfig } from '../config/config.js';
import { Keypair } from '../crypto/keypair.js';
import {
  AgentApiError,
  searchEntries,
  getCredential,
  reportCredentialStale,
  STALE_REASON_CODES,
  CredentialMethod,
  SigningContext,
} from '../http/agent-api.js';
import { decryptCredential } from '../crypto/decrypt.js';
import { parseSecret, ScriptPayload } from '../crypto/secret.js';
import { accessMessage, GET_EXPOSURE_WARNING } from '../credential/access.js';
import { resolveField, injectionValue, redactTotpSecrets, FieldSelectionError } from '../credential/fields.js';
import { runExecForTool } from '../exec/run-exec.js';
import { runScriptForTool, assertAllowedInterpreter, ScriptError } from '../exec/run-script.js';
import { prepareScriptEnv, applyDefaultVaultId } from '../exec/script-refs.js';
import { INJECT_UNAVAILABLE } from '../commands/inject.js';

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

export interface LegacyMcpToolRegistry {
  registerTool<TSchema extends z.ZodType>(
    name: string,
    definition: { description: string; inputSchema: TSchema },
    handler: (input: z.infer<TSchema>) => Promise<ToolResult>,
  ): void;
}

function ok(text: string): ToolResult {
  return { content: [{ type: 'text', text }] };
}

function fail(text: string): ToolResult {
  return { content: [{ type: 'text', text }], isError: true };
}

function errorMessage(err: unknown): string {
  if (err instanceof AgentApiError) return err.message;
  return `Unexpected error: ${(err as Error).message ?? String(err)}`;
}

// Discovery is org-wide via GET /api/agent/entries (agent-auth, metadata only).
// The legacy CVT-44 placeholders list_vaults / list_entries called JwtBearer (user)
// endpoints and returned 401 under agent-auth — they are intentionally not exposed.
export function registerTools(server: LegacyMcpToolRegistry, config: AgentConfig, keypair: Keypair, signing?: SigningContext): void {
  server.registerTool(
    'search_entries',
    {
      description:
        "Search vault entries by name/url/description (e.g. 'facebook') across the agent's organization. " +
        'Returns candidates (id, vaultId, name, url, description) — metadata only, no secrets. ' +
        'Pick one and call exec_with_credential, or get_credential only when plaintext must enter the model context. Browser injection is currently unavailable.',
      inputSchema: z.object({
        query: z.string().min(2).describe('Search term — matched against entry name, url and description (min 2 chars)'),
      }),
    },
    async ({ query }) => {
      try {
        const result = await searchEntries(config, keypair, query.trim(), undefined, signing);
        return ok(JSON.stringify(result, null, 2));
      } catch (err) {
        return fail(errorMessage(err));
      }
    }
  );

  server.registerTool(
    'get_credential',
    {
      description:
        "Get a credential as PLAINTEXT. WARNING: this places the secret in your context — on a hosted model it leaves the user's machine. " +
        'Prefer exec_with_credential when the secret only needs to authenticate a command. Browser injection is currently unavailable. ' +
        "If the agent has no grant yet, this requests one (user approves in the panel) and returns access:'pending' — call again shortly.",
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID'),
        reason: z.string().optional().describe('Justification shown to the approving user (required when first requesting access)'),
        field: z.string().optional().describe('Return a single field by label (well-known: username, password, url, value, notes). A TOTP field returns only its current code, never the shared secret.'),
      }),
    },
    async ({ vaultId, entryId, reason, field }) => {
      try {
        const result = await getCredential(config, keypair, vaultId, entryId, { reason: reason?.trim(), method: 'get' }, signing);
        if (result.access === 'granted') {
          const plaintext = await decryptCredential(result, keypair);
          const trimmedField = field?.trim();
          if (trimmedField) {
            const resolved = resolveField(parseSecret(plaintext), { field: trimmedField });
            const body =
              resolved.kind === 'totp'
                ? { access: 'granted', entryId: result.entryId, label: result.label, field: resolved.label, code: resolved.code, expiresIn: resolved.expiresIn }
                : { access: 'granted', entryId: result.entryId, label: result.label, field: resolved.label, value: resolved.value };
            return ok(JSON.stringify(body, null, 2));
          }
          return ok(JSON.stringify(
            { access: 'granted', entryId: result.entryId, label: result.label, secret: redactTotpSecrets(plaintext), warning: GET_EXPOSURE_WARNING },
            null,
            2,
          ));
        }
        const grantId = result.access === 'pending' ? result.grantId : undefined;
        return ok(JSON.stringify({ access: result.access, message: accessMessage(result.access, 'get', grantId) }, null, 2));
      } catch (err) {
        if (err instanceof FieldSelectionError) return fail(err.message);
        return fail(errorMessage(err));
      }
    }
  );

  server.registerTool(
    'exec_with_credential',
    {
      description:
        'Run a shell command with the credential injected as environment variables (CLAW_SECRET, CLAW_USERNAME, CLAW_PASSWORD, CLAW_<FIELD>). ' +
        'The secret is NOT returned to you. Neither is the command output: stdout/stderr are streamed to the operator and withheld from you, ' +
        'because a command can be coerced into re-encoding the secret (base64/hex/reverse) to slip it past any filter — so you receive only the exit code and a note. Judge success from the exit code. ' +
        'Use this instead of get_credential whenever the secret is only needed to authenticate a command (curl, psql, git, …). ' +
        'For a Script entry, omit `command`: the stored script runs under its own interpreter with its referenced entries injected as env vars.',
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID'),
        command: z.array(z.string()).optional().describe('Command and args, e.g. ["curl","-u","$CLAW_USERNAME:$CLAW_PASSWORD","https://api…"]. Omit for a Script entry.'),
        reason: z.string().optional().describe('Justification shown to the approving user (required when first requesting access)'),
      }),
    },
    async ({ vaultId, entryId, command, reason }) => {
      const resolved = await resolveForTool(config, keypair, vaultId, entryId, 'exec', reason, signing);
      if ('error' in resolved) {
        return fail(resolved.error);
      }

      if (resolved.secret.script) {
        if (command && command.length > 0) {
          return fail('this entry is a script — omit `command`; it runs its own interpreter.');
        }
        return execScriptForTool(config, keypair, vaultId, resolved.secret.script, reason, signing);
      }

      if (!command || command.length === 0) {
        return fail('no command given — provide `command`, or target a Script entry to run its stored script.');
      }
      const result = await runExecForTool(command, resolved.secret);
      return ok(JSON.stringify(result, null, 2));
    }
  );

  server.registerTool(
    'inject_credential',
    {
      description:
        'Browser injection is fail-closed in this runtime. Unauthenticated CDP endpoints can spoof page origins, so this tool does not request or decrypt a credential until a reviewed authenticated browser boundary is installed.',
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID'),
        cdp: z.string().describe('Deprecated unauthenticated CDP endpoint. It is accepted for contract compatibility, always rejected, and never contacted.'),
        reason: z.string().optional().describe('Reserved for a future reviewed implementation'),
        pageUrl: z.string().optional().describe('Reserved for a future reviewed implementation'),
        usernameSelector: z.string().optional().describe('Reserved for a future reviewed implementation'),
        passwordSelector: z.string().optional().describe('Reserved for a future reviewed implementation'),
        submitSelector: z.string().optional().describe('Reserved for a future reviewed implementation'),
      }),
    },
    async () => {
      return fail(INJECT_UNAVAILABLE);
    }
  );

  server.registerTool(
    'report_credential_stale',
    {
      description:
        'Report that a stored credential did NOT work (wrong/expired password, login refused). ' +
        'This notifies the vault owners so they can rotate it. Send NO secret and no typed values — only the entry reference and an optional note. ' +
        'It does NOT create a new credential; issuing a fresh one is a human action in the panel. ' +
        'Use this after a failed authentication attempt. Browser injection is currently unavailable until a reviewed authenticated browser boundary is installed.',
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID'),
        code: z.enum(STALE_REASON_CODES).optional()
          .describe('Cause: login_rejected (a login was refused) | auth_failed (could not authenticate some other way) | manual (default)'),
        note: z.string().optional().describe('Short note for the owner — NEVER include the secret or any typed value'),
      }),
    },
    async ({ vaultId, entryId, code, note }) => {
      try {
        await reportCredentialStale(config, keypair, { vaultId, entryId, code: code ?? 'manual', note: note?.trim() || undefined }, signing);
        return ok('Reported the credential as not working — the vault owners have been notified to rotate it.');
      } catch (err) {
        return fail(errorMessage(err));
      }
    }
  );
}

/**
 * Shared resolve for the exec tool: returns the parsed secret + trusted domain, or an
 * `error` string for any non-granted access state (so the tool reports it without throwing).
 */
async function resolveForTool(
  config: AgentConfig,
  keypair: Keypair,
  vaultId: string,
  entryId: string,
  method: CredentialMethod,
  reason?: string,
  signing?: SigningContext,
): Promise<{ secret: ReturnType<typeof parseSecret>; urlDomain: string | null } | { error: string }> {
  try {
    const result = await getCredential(config, keypair, vaultId, entryId, { reason: reason?.trim(), method }, signing);
    if (result.access !== 'granted') {
      const grantId = result.access === 'pending' ? result.grantId : undefined;
      return { error: accessMessage(result.access, method, grantId) };
    }
    const plaintext = await decryptCredential(result, keypair);
    return { secret: parseSecret(plaintext), urlDomain: result.urlDomain };
  } catch (err) {
    return { error: errorMessage(err) };
  }
}

/**
 * Run a Script entry for the MCP exec tool: validate the interpreter, deliver every referenced entry
 * through the agent's own grants, then execute with references in the environment. Output is withheld
 * from the model exactly like a plain exec (CVT-200) — only exit code + note come back.
 */
async function execScriptForTool(
  config: AgentConfig,
  keypair: Keypair,
  scriptVaultId: string,
  script: ScriptPayload,
  reason: string | undefined,
  signing: SigningContext | undefined,
): Promise<ToolResult> {
  try {
    assertAllowedInterpreter(script.interpreter);
  } catch (err) {
    if (err instanceof ScriptError) return fail(err.message);
    throw err;
  }

  const refs = applyDefaultVaultId(script.refs, scriptVaultId);
  const prepared = await prepareScriptEnv(refs, async (ref) => {
    const resolved = await resolveForTool(config, keypair, ref.vaultId!, ref.entryId, 'exec', reason, signing);
    return 'error' in resolved ? { ok: false, message: resolved.error } : { ok: true, secret: resolved.secret };
  });
  if (!prepared.ok) {
    return fail(prepared.message);
  }

  const result = await runScriptForTool(script.script, script.interpreter, {
    env: { ...process.env, ...prepared.env },
    secretValues: prepared.secretValues,
  });
  return ok(JSON.stringify(result, null, 2));
}
