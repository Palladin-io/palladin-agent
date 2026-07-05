import { Command } from 'commander';
import { loadConfig } from '../config/config.js';
import { Keypair } from '../crypto/keypair.js';
import { ProfilePaths } from '../config/paths.js';
import {
  AgentApiError,
  searchEntries,
  getCredential,
  reportCredentialStale,
  CredentialAccess,
  CredentialMethod,
  StaleReasonCode,
  STALE_REASON_CODES,
  SigningContext,
} from '../http/agent-api.js';
import { resolveAgentContext } from '../http/agent-context.js';
import { decryptCredential } from '../crypto/decrypt.js';
import { ParsedSecret, parseSecret, ScriptPayload } from '../crypto/secret.js';
import { accessMessage, GET_EXPOSURE_WARNING } from '../credential/access.js';
import { resolveField, injectionValue, redactTotpSecrets, FieldSelector, FieldSelectionError } from '../credential/fields.js';
import { runExec } from '../exec/run-exec.js';
import { runScript, assertAllowedInterpreter, ScriptError } from '../exec/run-script.js';
import { prepareScriptEnv } from '../exec/script-refs.js';
import {
  awaitGrant,
  makeHeartbeat,
  realSleep,
  resolveWaitPolicy,
  WaitCliOptions,
} from '../credential/await-grant.js';
import { addWaitOptions, parseWaitCli, RawWaitOpts } from '../credential/wait-options.js';
import { exitCodeForAccess } from '../credential/exit-codes.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

function fail(message: string): never {
  console.error(`Error: ${message}`);
  process.exit(1);
}

function describe(err: unknown): string {
  if (err instanceof AgentApiError) return err.message;
  return (err as Error).message ?? String(err);
}

async function profileContext(getProfile: GetProfile) {
  const { name, paths } = getProfile();
  return resolveAgentContext(name, paths);
}

/** palladin search <query> — discovery (entry metadata, no secrets). */
export function searchCommand(getProfile: GetProfile): Command {
  return new Command('search')
    .description("Search entries by name/url/description across the agent's organization")
    .argument('<query>', 'search term (min 2 chars)')
    .option('--json', 'output raw JSON')
    .action(async (query: string, opts: { json?: boolean }) => {
      const { config, keypair, signing } = await profileContext(getProfile);
      let result;
      try {
        result = await searchEntries(config, keypair, query.trim(), undefined, signing);
      } catch (err) {
        fail(describe(err));
      }

      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      if (result.items.length === 0) {
        console.log('No entries found.');
        return;
      }

      for (const item of result.items) {
        console.log(`${item.label}`);
        console.log(`  entryId:     ${item.entryId}`);
        console.log(`  vaultId:     ${item.vaultId}`);
        if (item.urlDomain)   console.log(`  url:         ${item.urlDomain}`);
        if (item.description) console.log(`  description: ${item.description}`);
        console.log('');
      }
      if (result.nextCursor) {
        console.log('(more results available — refine your query)');
      }
    });
}

export function reportStaleCommand(getProfile: GetProfile): Command {
  return new Command('report-stale')
    .description('Report a credential as not working — notifies the vault owners so they can rotate it (sends no secret)')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .option('--note <text>', 'short note for the owner (never include the secret or any typed value)')
    .option(`--code <code>`, `cause: ${STALE_REASON_CODES.join(' | ')} (default: manual)`)
    .action(async (vaultId: string, entryId: string, opts: { note?: string; code?: string }) => {
      const code = opts.code?.trim();
      if (code !== undefined && !STALE_REASON_CODES.includes(code as StaleReasonCode)) {
        fail(`invalid --code "${code}". Use one of: ${STALE_REASON_CODES.join(', ')}.`);
      }

      const { config, keypair, signing } = await profileContext(getProfile);
      try {
        await reportCredentialStale(config, keypair, {
          vaultId: vaultId.trim(),
          entryId: entryId.trim(),
          code: (code as StaleReasonCode) ?? 'manual',
          note: opts.note?.trim() || undefined,
        }, signing);
      } catch (err) {
        fail(describe(err));
      }
      console.log('Reported credential as not working — the vault owners have been notified to rotate it.');
    });
}

async function getCredentialWaiting(
  config: ReturnType<typeof loadConfig>,
  keypair: Keypair,
  vaultId: string,
  entryId: string,
  opts: { reason?: string; method: CredentialMethod; wait: WaitCliOptions },
  signing?: SigningContext,
): Promise<CredentialAccess> {
  const call = () =>
    getCredential(config, keypair, vaultId, entryId, {
      reason: opts.reason?.trim(),
      method: opts.method,
    }, signing);

  let result = await call();
  if (result.access !== 'pending') return result;

  const policy = resolveWaitPolicy(opts.wait, {
    pollIntervalMs: result.pollIntervalMs,
    maxWaitMs: result.maxWaitMs,
  });
  if (policy.waitMs <= 0) return result; // --wait 0 / --no-wait: behave like a single shot

  return awaitGrant(result, policy, {
    poll: call,
    sleep: realSleep,
    heartbeat: makeHeartbeat(policy.progress),
  });
}

export function getCredentialCommand(getProfile: GetProfile): Command {
  const cmd = new Command('get')
    .alias('retrieve')
    .description('Get a credential as plaintext — requests a grant on first use, waits for approval, returns the secret')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .option('--reason <reason>', 'justification shown to the approving user (required on first request)')
    .option('--field <label>', 'return a single field by label (well-known: username, password, url, value, notes; a TOTP field returns its current code only)')
    .option('--field-id <uuid>', 'return a single custom field by id (disambiguates duplicate labels)')
    .option('--quiet', 'suppress the LLM-exposure warning');
  addWaitOptions(cmd);
  return cmd.action(
    async (vaultId: string, entryId: string, opts: { reason?: string; field?: string; fieldId?: string; quiet?: boolean } & RawWaitOpts) => {
      const { config, keypair, signing } = await profileContext(getProfile);

      let result;
      try {
        result = await getCredentialWaiting(config, keypair, vaultId, entryId, {
          reason: opts.reason,
          method: 'get',
          wait: parseWaitCli(opts),
        }, signing);
      } catch (err) {
        fail(describe(err));
      }

      if (result.access === 'granted') {
        const plaintext = await decryptCredential(result, keypair);
        outputCredential(result.entryId, result.label, plaintext, { field: opts.field, fieldId: opts.fieldId });
        if (!opts.quiet) {
          console.error(GET_EXPOSURE_WARNING);
        }
        return;
      }

      // Exit code lets the agent branch: 75 = retryable/pending, 77 = denied.
      const grantId = result.access === 'pending' ? result.grantId : undefined;
      console.error(`Error: ${accessMessage(result.access, 'get', grantId)}`);
      process.exit(exitCodeForAccess(result.access));
    },
  );
}

/** Print the whole (TOTP-redacted) blob, or a single addressed field. Intentional plaintext output. */
function outputCredential(entryId: string, label: string, plaintext: string, selector: FieldSelector): void {
  if (selector.field === undefined && selector.fieldId === undefined) {
    const secret = redactTotpSecrets(plaintext);
    console.log(JSON.stringify({ entryId, label, secret }, null, 2));
    return;
  }

  let resolved;
  try {
    resolved = resolveField(parseSecret(plaintext), selector);
  } catch (err) {
    if (err instanceof FieldSelectionError) fail(err.message);
    throw err;
  }

  if (resolved.kind === 'totp') {
    console.log(JSON.stringify({ entryId, label, field: resolved.label, code: resolved.code, expiresIn: resolved.expiresIn }, null, 2));
  } else {
    console.log(JSON.stringify({ entryId, label, field: resolved.label, value: resolved.value }, null, 2));
  }
}

export function execCommand(getProfile: GetProfile): Command {
  const cmd = new Command('exec')
    .description('Run a command with the credential injected as env vars — the secret never enters the agent context. For a Script entry, omit the command to run the stored script.')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .argument('[command...]', 'command and args to run (use -- to separate, e.g. exec V E -- curl -u $CLAW_USERNAME:$CLAW_PASSWORD ...); omit for a Script entry')
    .option('--reason <reason>', 'justification shown to the approving user (required on first request)')
    .option('--env <mapping>', 'map an env var to a field: NAME=field (repeatable; a TOTP field maps its current code)', collectEnv, []);
  addWaitOptions(cmd);
  return cmd.action(
    async (vaultId: string, entryId: string, command: string[], opts: { reason?: string; env: string[] } & RawWaitOpts) => {
      const { config, keypair, signing } = await profileContext(getProfile);
      const wait = parseWaitCli(opts);

      const resolved = await resolveSecret(config, keypair, vaultId, entryId, 'exec', opts.reason, wait, signing);
      if (!resolved.ok) {
        console.error(`Error: ${resolved.message}`);
        process.exit(exitCodeForAccess(resolved.access));
      }

      if (resolved.secret.script) {
        if (command.length > 0) {
          fail('this entry is a script — do not pass a command; run `palladin exec <vaultId> <entryId>` to execute the stored script.');
        }
        const code = await execScriptEntry(config, keypair, signing, resolved.secret.script, { reason: opts.reason, wait });
        process.exit(code);
      }

      if (command.length === 0) {
        fail('No command given. Usage: palladin exec <vaultId> <entryId> -- <command> [args...]');
      }
      const extra = resolveEnvMappings(resolved.secret, opts.env);
      const code = await runExec(command, resolved.secret, { extraEnv: extra.env, extraSecretValues: extra.secretValues });
      process.exit(code);
    },
  );
}

function collectEnv(value: string, previous: string[]): string[] {
  return previous.concat([value]);
}

const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Resolve `--env NAME=field` mappings against the delivered secret (TOTP fields map their code). */
function resolveEnvMappings(secret: ParsedSecret, mappings: string[]): { env: Record<string, string>; secretValues: string[] } {
  const env: Record<string, string> = {};
  const secretValues: string[] = [];
  for (const mapping of mappings) {
    const eq = mapping.indexOf('=');
    if (eq <= 0) {
      fail(`invalid --env "${mapping}" — expected NAME=field.`);
    }
    const name = mapping.slice(0, eq).trim();
    const fieldRef = mapping.slice(eq + 1).trim();
    if (!ENV_NAME_RE.test(name)) {
      fail(`invalid env var name "${name}" in --env.`);
    }
    let value: string;
    try {
      value = injectionValue(resolveField(secret, { field: fieldRef }));
    } catch (err) {
      if (err instanceof FieldSelectionError) fail(`--env ${name}: ${err.message}`);
      throw err;
    }
    env[name] = value;
    if (value) {
      secretValues.push(value);
    }
  }
  return { env, secretValues };
}

/**
 * Execute a Script entry: validate the interpreter, deliver every referenced entry through this
 * agent's own grants, then run the script with the references injected as env vars. All references
 * are resolved BEFORE anything runs — a single missing grant aborts with nothing executed.
 */
async function execScriptEntry(
  config: ReturnType<typeof loadConfig>,
  keypair: Keypair,
  signing: SigningContext | undefined,
  script: ScriptPayload,
  opts: { reason?: string; wait: WaitCliOptions },
): Promise<number> {
  try {
    assertAllowedInterpreter(script.interpreter);
  } catch (err) {
    if (err instanceof ScriptError) fail(err.message);
    throw err;
  }

  const prepared = await prepareScriptEnv(script.refs, async (ref) => {
    const r = await resolveSecret(config, keypair, ref.vaultId!, ref.entryId, 'exec', opts.reason, opts.wait, signing);
    return r.ok ? { ok: true, secret: r.secret } : { ok: false, message: r.message };
  });
  if (!prepared.ok) {
    fail(prepared.message);
  }

  const result = await runScript(script.script, script.interpreter, {
    env: { ...process.env, ...prepared.env },
    secretValues: prepared.secretValues,
    mirror: 'terminal',
  });
  return result.code;
}

export type ResolvedSecret =
  | { ok: true; secret: ParsedSecret; urlDomain: string | null; label: string }
  | { ok: false; access: Exclude<CredentialAccess['access'], 'granted'>; message: string };

// Shared fetch+decrypt for exec/inject; plaintext is held only in memory.
async function resolveSecret(
  config: ReturnType<typeof loadConfig>,
  keypair: Keypair,
  vaultId: string,
  entryId: string,
  method: CredentialMethod,
  reason?: string,
  wait: WaitCliOptions = {},
  signing?: SigningContext,
): Promise<ResolvedSecret> {
  let result;
  try {
    result = await getCredentialWaiting(config, keypair, vaultId, entryId, { reason, method, wait }, signing);
  } catch (err) {
    fail(describe(err));
  }

  if (result.access !== 'granted') {
    const grantId = result.access === 'pending' ? result.grantId : undefined;
    return { ok: false, access: result.access, message: accessMessage(result.access, method, grantId) };
  }

  const plaintext = await decryptCredential(result, keypair);
  return { ok: true, secret: parseSecret(plaintext), urlDomain: result.urlDomain, label: result.label };
}

export { resolveSecret };
