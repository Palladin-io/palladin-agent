import { describe, it, expect, vi } from 'vitest';
import {
  awaitGrant,
  makeHeartbeat,
  resolveWaitPolicy,
  DEFAULT_WAIT_MS,
  DEFAULT_POLL_MS,
  MIN_POLL_MS,
  HeartbeatInfo,
} from '../../src/credential/await-grant.js';
import { CredentialAccess } from '../../src/http/agent-api.js';

const pending: CredentialAccess = { access: 'pending', grantId: 'g1' };
const granted = { access: 'granted' } as CredentialAccess;

/** Fake deps with a virtual clock: `sleep` just accumulates time, `poll` walks a scripted list. */
function harness(responses: CredentialAccess[]) {
  const heartbeats: HeartbeatInfo[] = [];
  let pollCount = 0;
  let slept = 0;
  const deps = {
    poll: async () => {
      const r = responses[Math.min(pollCount, responses.length - 1)]!;
      pollCount += 1;
      return r;
    },
    sleep: async (ms: number) => {
      slept += ms;
    },
    heartbeat: (info: HeartbeatInfo) => heartbeats.push({ ...info }),
  };
  return { deps, heartbeats, get pollCount() { return pollCount; }, get slept() { return slept; } };
}

describe('resolveWaitPolicy — hierarchy CLI > backend > default', () => {
  it('falls back to built-in defaults when nothing is provided', () => {
    const p = resolveWaitPolicy();
    expect(p.waitMs).toBe(DEFAULT_WAIT_MS);
    expect(p.pollMs).toBe(DEFAULT_POLL_MS);
    expect(p.progress).toBe('plain');
  });

  it('uses backend hints when the CLI is silent', () => {
    const p = resolveWaitPolicy({}, { pollIntervalMs: 45_000, maxWaitMs: 120_000 });
    expect(p.pollMs).toBe(45_000);
    expect(p.waitMs).toBe(120_000);
  });

  it('lets the CLI override the backend', () => {
    const p = resolveWaitPolicy({ waitMs: 60_000, pollMs: 20_000 }, { pollIntervalMs: 45_000, maxWaitMs: 120_000 });
    expect(p.waitMs).toBe(60_000);
    expect(p.pollMs).toBe(20_000);
  });

  it('clamps the poll interval to the local safety floor', () => {
    const p = resolveWaitPolicy({ pollMs: 1_000 });
    expect(p.pollMs).toBe(MIN_POLL_MS);
  });

  it('keeps the heartbeat no slower than a poll', () => {
    const p = resolveWaitPolicy({ pollMs: 6_000 });
    expect(p.heartbeatMs).toBeLessThanOrEqual(p.pollMs);
  });
});

describe('awaitGrant', () => {
  it('returns granted once approval lands, and stops polling', async () => {
    // poll #1 (30s) pending, #2 (60s) pending, #3 (90s) granted
    const h = harness([pending, pending, granted]);
    const policy = resolveWaitPolicy(); // 180s budget, 30s poll, 10s heartbeat
    const result = await awaitGrant(pending, policy, h.deps);
    expect(result.access).toBe('granted');
    expect(h.pollCount).toBe(3);
    expect(h.slept).toBe(90_000); // stopped at the 90s mark, not the full budget
    expect(h.heartbeats).toHaveLength(9); // a 10s heartbeat for each step until 90s
  });

  it('short-circuits immediately on a terminal state', async () => {
    const h = harness([{ access: 'denied' }]);
    const result = await awaitGrant(pending, resolveWaitPolicy(), h.deps);
    expect(result.access).toBe('denied');
    expect(h.pollCount).toBe(1); // first poll at 30s ends it
    expect(h.slept).toBe(30_000);
  });

  it('returns the last pending when the budget is exhausted', async () => {
    const h = harness([pending]); // always pending
    const result = await awaitGrant(pending, resolveWaitPolicy(), h.deps);
    expect(result.access).toBe('pending');
    expect(h.slept).toBe(DEFAULT_WAIT_MS); // waited the whole budget
    expect(h.pollCount).toBe(6); // 180s / 30s
  });

  it('carries the grantId into the heartbeat', async () => {
    const h = harness([pending]);
    await awaitGrant(pending, resolveWaitPolicy({ waitMs: 10_000 }), h.deps);
    expect(h.heartbeats[0]!.grantId).toBe('g1');
    expect(h.heartbeats[0]!.deadlineMs).toBe(10_000);
  });

  it('polls at exact non-multiple intervals', async () => {
    const h = harness([pending, { access: 'denied' }]);
    const result = await awaitGrant(pending, {
      waitMs: 40_000,
      pollMs: 15_000,
      heartbeatMs: 10_000,
      pollTimeoutMs: 10_000,
      progress: 'plain',
    }, h.deps);
    expect(result.access).toBe('denied');
    expect(h.slept).toBe(30_000);
    expect(h.heartbeats.map((heartbeat) => heartbeat.elapsedMs)).toEqual([10_000, 20_000, 30_000]);
  });

  it('interrupts an in-flight wait when cancelled', async () => {
    const controller = new AbortController();
    const deps = {
      poll: async () => pending,
      sleep: async () => new Promise<void>(() => {}),
      heartbeat: () => {},
      signal: controller.signal,
    };
    const waiting = awaitGrant(pending, resolveWaitPolicy(), deps);
    controller.abort(new Error('cancelled'));
    await expect(waiting).rejects.toThrow('cancelled');
  });

  it('times out a hung poll and keeps heartbeats moving', async () => {
    const heartbeats: number[] = [];
    const result = await awaitGrant(pending, {
      waitMs: 6_000,
      pollMs: 5_000,
      heartbeatMs: 1_000,
      pollTimeoutMs: 10,
      progress: 'plain',
    }, {
      poll: async () => new Promise<CredentialAccess>(() => {}),
      sleep: async () => {},
      heartbeat: (heartbeat) => heartbeats.push(heartbeat.elapsedMs),
    });
    expect(result.access).toBe('pending');
    expect(heartbeats).toEqual([1_000, 2_000, 3_000, 4_000, 5_000, 5_000, 6_000]);
  });
});

describe('makeHeartbeat', () => {
  it('plain mode writes a human line to the sink', () => {
    const lines: string[] = [];
    makeHeartbeat('plain', (s) => lines.push(s))({ grantId: 'g9', elapsedMs: 40_000, deadlineMs: 180_000 });
    expect(lines[0]).toContain('awaiting approval');
    expect(lines[0]).toContain('g9');
    expect(lines[0]).toContain('40s/180s');
  });

  it('json mode emits one NDJSON object', () => {
    const lines: string[] = [];
    makeHeartbeat('json', (s) => lines.push(s))({ grantId: 'g9', elapsedMs: 40_000, deadlineMs: 180_000 });
    const obj = JSON.parse(lines[0]!);
    expect(obj).toMatchObject({ event: 'awaiting-approval', grantId: 'g9', elapsedMs: 40_000, deadlineMs: 180_000 });
  });

  it('none mode writes nothing', () => {
    const write = vi.fn();
    makeHeartbeat('none', write)({ grantId: 'g', elapsedMs: 1, deadlineMs: 2 });
    expect(write).not.toHaveBeenCalled();
  });
});
