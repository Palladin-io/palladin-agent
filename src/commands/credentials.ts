import { Command } from 'commander';
import { loadConfig } from '../config/config.js';
import { loadKeypair, Keypair } from '../crypto/keypair.js';
import { ProfilePaths } from '../config/paths.js';
import {
  AgentApiError,
  searchEntries,
  getCredential,
  reportCredentialStale,
  CredentialAccess,
  CredentialMethod,
  StaleReasonCode,
} from '../http/agent-api.js';
import { decryptCredential } from '../crypto/decrypt.js';
import { ParsedSecret, parseSecret } from '../crypto/secret.js';
import { accessMessage, GET_EXPOSURE_WARNING } from '../credential/access.js';
import { runExec } from '../exec/run-exec.js';
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
  const config = loadConfig(paths);
  const keypair = await loadKeypair(name, paths);
  return { config, keypair };
}

/** claw-vault search <query> — discovery (entry metadata, no secrets). */
export function searchCommand(getProfile: GetProfile): Command {
  return new Command('search')
    .description("Search entries by name/url/description across the agent's organization")
    .argument('<query>', 'search term (min 2 chars)')
    .option('--json', 'output raw JSON')
    .action(async (query: string, opts: { json?: boolean }) => {
      const { config, keypair } = await profileContext(getProfile);
      let result;
      try {
        result = await searchEntries(config, keypair, query.trim());
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

const STALE_CODES: readonly StaleReasonCode[] = ['login_rejected', 'auth_failed', 'manual'];

/**
 * claw-vault report-stale <vaultId> <entryId> [--note <text>] [--code <code>]
 *
 * Tells the backend that the stored credential did not work (wrong/expired password, login refused),
 * which surfaces a `credential_stale` notification to the vault's members so they can rotate it. No
 * secret or typed value is ever sent — only the entry reference, a reason code, and an optional note.
 * This does NOT create a new credential; issuing a fresh one stays a human action in the panel.
 */
export function reportStaleCommand(getProfile: GetProfile): Command {
  return new Command('report-stale')
    .description('Report a credential as not working — notifies the vault owners so they can rotate it (sends no secret)')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .option('--note <text>', 'short note for the owner (never include the secret or any typed value)')
    .option(`--code <code>`, `cause: ${STALE_CODES.join(' | ')} (default: manual)`)
    .action(async (vaultId: string, entryId: string, opts: { note?: string; code?: string }) => {
      const code = opts.code?.trim();
      if (code !== undefined && !STALE_CODES.includes(code as StaleReasonCode)) {
        fail(`invalid --code "${code}". Use one of: ${STALE_CODES.join(', ')}.`);
      }

      const { config, keypair } = await profileContext(getProfile);
      try {
        await reportCredentialStale(config, keypair, {
          vaultId: vaultId.trim(),
          entryId: entryId.trim(),
          code: (code as StaleReasonCode) ?? 'manual',
          note: opts.note?.trim() || undefined,
        });
      } catch (err) {
        fail(describe(err));
      }
      console.log('Reported credential as not working — the vault owners have been notified to rotate it.');
    });
}

/**
 * Fetch the credential once and, if the grant is still pending, long-poll the backend until it is
 * approved, reaches a terminal state, or the wait budget runs out (CVT-157). A heartbeat is emitted
 * on stderr while waiting so the host sees the process is alive; the wait is configurable CLI >
 * backend > default. The first POST creates the pending grant; subsequent polls reuse it (the
 * endpoint is idempotent for an in-flight pending), so no duplicate requests are created.
 */
async function getCredentialWaiting(
  config: ReturnType<typeof loadConfig>,
  keypair: Keypair,
  vaultId: string,
  entryId: string,
  opts: { reason?: string; method: CredentialMethod; wait: WaitCliOptions },
): Promise<CredentialAccess> {
  const call = () =>
    getCredential(config, keypair, vaultId, entryId, {
      reason: opts.reason?.trim(),
      method: opts.method,
    });

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

/**
 * claw-vault get <vaultId> <entryId> [--reason <reason>]   (alias: retrieve)
 *
 * Returns the decrypted secret as plaintext on stdout. This puts the secret in the agent's context;
 * prefer `exec`/`inject` for hosted LLMs. Requests a grant on first use (method=get) and, by
 * default, waits for approval (see the wait flags).
 */
export function getCredentialCommand(getProfile: GetProfile): Command {
  const cmd = new Command('get')
    .alias('retrieve')
    .description('Get a credential as plaintext — requests a grant on first use, waits for approval, returns the secret')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .option('--reason <reason>', 'justification shown to the approving user (required on first request)')
    .option('--quiet', 'suppress the LLM-exposure warning');
  addWaitOptions(cmd);
  return cmd.action(
    async (vaultId: string, entryId: string, opts: { reason?: string; quiet?: boolean } & RawWaitOpts) => {
      const { config, keypair } = await profileContext(getProfile);

      let result;
      try {
        result = await getCredentialWaiting(config, keypair, vaultId, entryId, {
          reason: opts.reason,
          method: 'get',
          wait: parseWaitCli(opts),
        });
      } catch (err) {
        fail(describe(err));
      }

      if (result.access === 'granted') {
        const secret = await decryptCredential(result, keypair);
        // Intentional plaintext output: this is the requested result for the user.
        console.log(JSON.stringify({ entryId: result.entryId, label: result.label, secret }, null, 2));
        if (!opts.quiet) {
          console.error(GET_EXPOSURE_WARNING);
        }
        return;
      }

      // Non-granted after the wait: report on stderr and exit with a code the agent can branch on
      // (75 = still pending / retryable, 77 = denied & friends).
      const grantId = result.access === 'pending' ? result.grantId : undefined;
      console.error(`Error: ${accessMessage(result.access, 'get', grantId)}`);
      process.exit(exitCodeForAccess(result.access));
    },
  );
}

/**
 * claw-vault exec <vaultId> <entryId> -- <command> [args...]
 *
 * Fetches the credential with method=exec and runs the command with the secret injected as
 * environment variables (CLAW_SECRET / CLAW_USERNAME / CLAW_PASSWORD / CLAW_<FIELD>). The plaintext
 * never reaches the agent's stdout — only the subprocess's output (with the secret masked) does.
 */
export function execCommand(getProfile: GetProfile): Command {
  const cmd = new Command('exec')
    .description('Run a command with the credential injected as env vars — the secret never enters the agent context')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .argument('<command...>', 'command and args to run (use -- to separate, e.g. exec V E -- curl -u $CLAW_USERNAME:$CLAW_PASSWORD ...)')
    .option('--reason <reason>', 'justification shown to the approving user (required on first request)');
  addWaitOptions(cmd);
  return cmd.action(
    async (vaultId: string, entryId: string, command: string[], opts: { reason?: string } & RawWaitOpts) => {
      if (command.length === 0) {
        fail('No command given. Usage: claw-vault exec <vaultId> <entryId> -- <command> [args...]');
      }
      const { config, keypair } = await profileContext(getProfile);

      const resolved = await resolveSecret(config, keypair, vaultId, entryId, 'exec', opts.reason, parseWaitCli(opts));
      if (!resolved.ok) {
        console.error(`Error: ${resolved.message}`);
        process.exit(exitCodeForAccess(resolved.access));
      }
      const code = await runExec(command, resolved.secret);
      process.exit(code);
    },
  );
}

/** Outcome of [resolveSecret] — either the parsed plaintext or a non-granted state to exit on. */
export type ResolvedSecret =
  | { ok: true; secret: ParsedSecret; urlDomain: string | null; label: string }
  | { ok: false; access: Exclude<CredentialAccess['access'], 'granted'>; message: string };

/**
 * Shared fetch+decrypt for exec/inject: fetches the grant for `method` (waiting for approval per the
 * CLI/backend policy), and on success returns the parsed plaintext plus the entry's trusted bound
 * domain (for inject's origin gate). On any non-granted state it returns `{ ok: false }` with a
 * ready message + the access kind so the caller can pick the right exit code. The plaintext is held
 * only in memory.
 */
async function resolveSecret(
  config: ReturnType<typeof loadConfig>,
  keypair: Keypair,
  vaultId: string,
  entryId: string,
  method: CredentialMethod,
  reason?: string,
  wait: WaitCliOptions = {},
): Promise<ResolvedSecret> {
  let result;
  try {
    result = await getCredentialWaiting(config, keypair, vaultId, entryId, { reason, method, wait });
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
