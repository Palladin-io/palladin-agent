import { CredentialAccess } from '../http/agent-api.js';

// ── Defaults (CVT-157) ────────────────────────────────────────────────────────
// A human approving in the web/mobile panel realistically takes tens of seconds to a couple of
// minutes, so we long-poll on a *flat* interval (no sub-second backoff — nobody approves in 2s).
export const DEFAULT_WAIT_MS = 180_000; // total budget: 3 minutes
export const DEFAULT_POLL_MS = 30_000; // re-check the backend every 30s (POST is idempotent)
export const DEFAULT_HEARTBEAT_MS = 10_000; // liveness line every 10s, decoupled from the poll
export const DEFAULT_POLL_TIMEOUT_MS = 10_000; // one request may never block heartbeat indefinitely
export const MIN_POLL_MS = 5_000; // local safety floor so nothing can hammer the backend

export type ProgressMode = 'plain' | 'json' | 'none';

/** Effective wait policy after merging CLI > backend > defaults. `waitMs <= 0` means "don't wait". */
export interface WaitPolicy {
  waitMs: number;
  pollMs: number;
  heartbeatMs: number;
  pollTimeoutMs: number;
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
  const pollTimeoutMs = Math.min(DEFAULT_POLL_TIMEOUT_MS, heartbeatMs);
  return { waitMs, pollMs, heartbeatMs, pollTimeoutMs, progress: cli.progress ?? 'plain' };
}

export interface HeartbeatInfo {
  grantId?: string;
  elapsedMs: number;
  deadlineMs: number;
}

export interface AwaitGrantDeps {
  /** Re-query the credential endpoint. Idempotent for an in-flight pending (server reuses it). */
  poll: (signal?: AbortSignal) => Promise<CredentialAccess>;
  /** Sleep for `ms` (injected so tests can drive a fake clock). */
  sleep: (ms: number) => Promise<void>;
  /** Emit a liveness heartbeat — stderr text / NDJSON / no-op. Never touches stdout. */
  heartbeat: (info: HeartbeatInfo) => void;
  /** Optional process-level cancellation (SIGINT/SIGTERM is bridged by the native runtime). */
  signal?: AbortSignal;
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
      `[palladin] awaiting approval - grant=${info.grantId ?? 'unknown'} - ${elapsed}s/${total}s - approve in the app\n`,
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
  let nextPoll = policy.pollMs;
  let nextHeartbeat = policy.heartbeatMs;
  const wallStarted = Date.now();

  while (waited < policy.waitMs) {
    throwIfAborted(deps.signal);
    const nextEvent = Math.min(nextPoll, nextHeartbeat, policy.waitMs);
    const step = nextEvent - waited;
    await raceWithAbort(deps.sleep(step), deps.signal);
    waited = nextEvent;

    if (waited >= nextHeartbeat) {
      deps.heartbeat({ grantId, elapsedMs: waited, deadlineMs: policy.waitMs });
      nextHeartbeat += policy.heartbeatMs;
    }

    if (waited >= nextPoll) {
      const wallRemaining = policy.waitMs - (Date.now() - wallStarted);
      if (wallRemaining <= 0) return last;
      const timeoutMs = Math.max(1, Math.min(policy.pollTimeoutMs, policy.waitMs - waited, wallRemaining));
      let result: CredentialAccess;
      try {
        result = await pollWithTimeout(deps, timeoutMs);
      } catch (error) {
        if (!(error instanceof PollTimeoutError)) throw error;
        deps.heartbeat({ grantId, elapsedMs: waited, deadlineMs: policy.waitMs });
        nextPoll += policy.pollMs;
        continue;
      }
      last = result;
      // Anything other than a fresh pending is a final answer — stop waiting immediately.
      if (result.access !== 'pending') return result;
      grantId = result.grantId ?? grantId;
      nextPoll += policy.pollMs;
    }
  }

  return last; // budget exhausted — still pending
}

class PollTimeoutError extends Error {
  constructor() {
    super('credential poll timed out');
    this.name = 'PollTimeoutError';
  }
}

async function pollWithTimeout(deps: AwaitGrantDeps, timeoutMs: number): Promise<CredentialAccess> {
  const controller = new AbortController();
  const forwardAbort = () => controller.abort(deps.signal?.reason);
  deps.signal?.addEventListener('abort', forwardAbort, { once: true });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      const error = new PollTimeoutError();
      reject(error);
      controller.abort(error);
    }, timeoutMs);
  });
  try {
    return await raceWithAbort(Promise.race([deps.poll(controller.signal), timedOut]), deps.signal);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    deps.signal?.removeEventListener('abort', forwardAbort);
    if (!controller.signal.aborted) controller.abort();
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error('credential wait was cancelled');
  }
}

function raceWithAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return promise;
  throwIfAborted(signal);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason instanceof Error ? signal.reason : new Error('credential wait was cancelled'));
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}
