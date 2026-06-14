import { CredentialAccess } from '../http/agent-api.js';

// ── Defaults (CVT-157) ────────────────────────────────────────────────────────
// A human approving in the web/mobile panel realistically takes tens of seconds to a couple of
// minutes, so we long-poll on a *flat* interval (no sub-second backoff — nobody approves in 2s).
export const DEFAULT_WAIT_MS = 180_000; // total budget: 3 minutes
export const DEFAULT_POLL_MS = 30_000; // re-check the backend every 30s (POST is idempotent)
export const DEFAULT_HEARTBEAT_MS = 10_000; // liveness line every 10s, decoupled from the poll
export const MIN_POLL_MS = 5_000; // local safety floor so nothing can hammer the backend

export type ProgressMode = 'plain' | 'json' | 'none';

/** Effective wait policy after merging CLI > backend > defaults. `waitMs <= 0` means "don't wait". */
export interface WaitPolicy {
  waitMs: number;
  pollMs: number;
  heartbeatMs: number;
  progress: ProgressMode;
}

/** Backend-provided hints (org policy) carried on the `pending` response. Used only when the CLI is silent. */
export interface WaitHints {
  pollIntervalMs?: number;
  maxWaitMs?: number;
}

/** Parsed CLI inputs (ms). `undefined` = flag not given, so the next tier in the hierarchy applies. */
export interface WaitCliOptions {
  waitMs?: number; // --wait <dur> ; --no-wait → 0
  pollMs?: number; // --poll-interval <dur>
  progress?: ProgressMode; // --progress
}

/**
 * Resolve the wait policy. Hierarchy is **CLI > Backend > default** — an explicit flag always wins;
 * backend hints fill the gaps; built-in defaults are the floor. A local minimum keeps the poll
 * interval sane regardless of where the value came from, and the heartbeat is never slower than a
 * poll (so liveness keeps flowing between backend checks).
 */
export function resolveWaitPolicy(cli: WaitCliOptions = {}, hints: WaitHints = {}): WaitPolicy {
  const waitMs = Math.max(0, cli.waitMs ?? hints.maxWaitMs ?? DEFAULT_WAIT_MS);
  const pollMs = Math.max(MIN_POLL_MS, cli.pollMs ?? hints.pollIntervalMs ?? DEFAULT_POLL_MS);
  const heartbeatMs = Math.max(1_000, Math.min(DEFAULT_HEARTBEAT_MS, pollMs));
  return { waitMs, pollMs, heartbeatMs, progress: cli.progress ?? 'plain' };
}

export interface HeartbeatInfo {
  grantId?: string;
  elapsedMs: number;
  deadlineMs: number;
}

export interface AwaitGrantDeps {
  /** Re-query the credential endpoint. Idempotent for an in-flight pending (server reuses it). */
  poll: () => Promise<CredentialAccess>;
  /** Sleep for `ms` (injected so tests can drive a fake clock). */
  sleep: (ms: number) => Promise<void>;
  /** Emit a liveness heartbeat — stderr text / NDJSON / no-op. Never touches stdout. */
  heartbeat: (info: HeartbeatInfo) => void;
}

/** Real wall-clock sleep. */
export const realSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Build a heartbeat emitter for the chosen [ProgressMode]. Writes to stderr by default so stdout
 * (the `exec` child output / `get` secret) stays clean and machine-parseable.
 */
export function makeHeartbeat(
  progress: ProgressMode,
  write: (s: string) => void = (s) => void process.stderr.write(s),
): (info: HeartbeatInfo) => void {
  if (progress === 'none') return () => {};
  if (progress === 'json') {
    return (info) =>
      write(
        JSON.stringify({
          event: 'awaiting-approval',
          grantId: info.grantId ?? null,
          elapsedMs: info.elapsedMs,
          deadlineMs: info.deadlineMs,
        }) + '\n',
      );
  }
  return (info) => {
    const elapsed = Math.round(info.elapsedMs / 1000);
    const total = Math.round(info.deadlineMs / 1000);
    write(
      `[claw-vault] awaiting approval · grant=${info.grantId ?? '—'} · ${elapsed}s/${total}s · approve in the app\n`,
    );
  };
}

/**
 * Long-poll a pending grant until it is granted, reaches a terminal state, or the wait budget runs
 * out — without interrupting the agent's flow: a heartbeat is emitted every `heartbeatMs` so the
 * host (Claude Code / MCP) sees the process is alive, while the backend is re-polled only every
 * `pollMs`. The first poll happens after one full interval (nobody approves instantly).
 *
 * `initial` is the pending we already received from the first call, so we don't poll again at t=0.
 * Returns the final [CredentialAccess]: `granted`, a terminal/`unavailable` state, or the last
 * `pending` (timed out — the caller treats that as retryable).
 */
export async function awaitGrant(
  initial: Extract<CredentialAccess, { access: 'pending' }>,
  policy: WaitPolicy,
  deps: AwaitGrantDeps,
): Promise<CredentialAccess> {
  let last: CredentialAccess = initial;
  let grantId: string | undefined = initial.grantId;
  let waited = 0;
  let sincePoll = 0;

  while (waited < policy.waitMs) {
    const step = Math.min(policy.heartbeatMs, policy.waitMs - waited);
    await deps.sleep(step);
    waited += step;
    sincePoll += step;
    deps.heartbeat({ grantId, elapsedMs: waited, deadlineMs: policy.waitMs });

    if (sincePoll >= policy.pollMs) {
      sincePoll = 0;
      const result = await deps.poll();
      last = result;
      // Anything other than a fresh pending is a final answer — stop waiting immediately.
      if (result.access !== 'pending') return result;
      grantId = result.grantId ?? grantId;
    }
  }

  return last; // budget exhausted — still pending
}
