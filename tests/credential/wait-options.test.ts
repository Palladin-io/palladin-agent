import { describe, it, expect } from 'vitest';
import { parseWaitCli } from '../../src/credential/wait-options.js';
import { exitCodeForAccess, EX_TEMPFAIL, EX_NOPERM } from '../../src/credential/exit-codes.js';

describe('parseWaitCli', () => {
  it('maps --no-wait to a zero budget', () => {
    expect(parseWaitCli({ wait: false }).waitMs).toBe(0);
  });

  it('parses --wait and --poll-interval durations', () => {
    const out = parseWaitCli({ wait: '3m', pollInterval: '30s' });
    expect(out.waitMs).toBe(180_000);
    expect(out.pollMs).toBe(30_000);
  });

  it('leaves values undefined when flags are absent (so backend/default apply)', () => {
    expect(parseWaitCli({})).toEqual({});
  });

  it('accepts valid progress modes and rejects junk', () => {
    expect(parseWaitCli({ progress: 'json' }).progress).toBe('json');
    expect(() => parseWaitCli({ progress: 'loud' })).toThrow(/invalid --progress/);
  });
});

describe('exitCodeForAccess', () => {
  it('treats pending / unavailable as retryable (TEMPFAIL)', () => {
    expect(exitCodeForAccess('pending')).toBe(EX_TEMPFAIL);
    expect(exitCodeForAccess('unavailable')).toBe(EX_TEMPFAIL);
  });

  it('treats denials & friends as non-retryable (NOPERM)', () => {
    for (const a of ['denied', 'revoked', 'expired', 'consumed', 'blocked', 'method-not-allowed'] as const) {
      expect(exitCodeForAccess(a)).toBe(EX_NOPERM);
    }
  });
});
