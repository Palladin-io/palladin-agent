import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { exitCodeForAccess } from '../../src/credential/exit-codes.js';
import { generateTotp, parseTotpValue } from '../../src/credential/totp.js';
import { resolveField, redactTotpSecrets } from '../../src/credential/fields.js';
import { parseDuration } from '../../src/credential/duration.js';
import { awaitGrant, resolveWaitPolicy } from '../../src/credential/await-grant.js';
import { parseSecret } from '../../src/crypto/secret.js';
import { CredentialAccess } from '../../src/http/agent-api.js';

interface CredentialFixture {
  totpUnixSeconds: number;
  cases: Array<{
    name: string;
    plaintext: string;
    primary?: string;
    customFieldCount?: number;
    parseError?: boolean;
    totpFieldId?: string;
    totpFieldLabel?: string;
    totpCode?: string;
    scriptRefCount?: number;
    redactionForbidden?: string;
    redactionContains?: string;
    selectorField?: string;
    selectorFieldId?: string;
    expectedFieldValue?: string;
    selectionError?: boolean;
  }>;
}

interface GrantFixture {
  states: Array<{ access: string; exitCode: number; retryable: boolean }>;
  waitPolicies: Array<{
    name: string;
    options: { waitMs?: number; pollMs?: number };
    hints: { pollIntervalMs?: number; maxWaitMs?: number };
    expected: { waitMs: number; pollMs: number; heartbeatMs: number; pollTimeoutMs: number };
  }>;
  durations: Array<{ input: string; expectedMs: number }>;
  waitScenarios: Array<{
    name: string;
    policy: { waitMs: number; pollMs: number; heartbeatMs: number; pollTimeoutMs: number };
    responses?: string[];
    expectedSleepMs?: number[];
    expectedHeartbeatMs?: number[];
    expectedAccess?: string;
    cancelDuring?: 'poll';
    expectedError?: 'cancelled';
    hangPoll?: boolean;
  }>;
}

const credentials = fixture<CredentialFixture>('credential-blobs.json');
const grants = fixture<GrantFixture>('grant-access.json');

describe('frozen credential runtime vectors', () => {
  it('keeps TypeScript parsing aligned with the native runtime', () => {
    for (const vector of credentials.cases) {
      if (vector.parseError) {
        expect(() => parseSecret(vector.plaintext), vector.name).toThrow();
        continue;
      }
      const parsed = parseSecret(vector.plaintext);
      if (vector.primary !== undefined) expect(parsed.password, vector.name).toBe(vector.primary);
      if (vector.customFieldCount !== undefined) expect(parsed.customFields.length, vector.name).toBe(vector.customFieldCount);
      if ((vector.totpFieldId || vector.totpFieldLabel) && vector.totpCode) {
        const custom = parsed.customFields.find((candidate) => candidate.id === vector.totpFieldId);
        const descriptor = custom?.value ?? parsed.legacyTotp ?? '';
        const params = parseTotpValue(descriptor);
        expect(params, vector.name).not.toBeNull();
        if (params === null) throw new Error(`missing synthetic TOTP params: ${vector.name}`);
        expect(generateTotp(params, credentials.totpUnixSeconds * 1000).code, vector.name).toBe(vector.totpCode);
      }
      if (vector.scriptRefCount !== undefined) {
        expect(parsed.script?.refs.length, vector.name).toBe(vector.scriptRefCount);
      }
      if (vector.redactionForbidden || vector.redactionContains) {
        const redacted = redactTotpSecrets(vector.plaintext);
        if (vector.redactionForbidden) expect(redacted, vector.name).not.toContain(vector.redactionForbidden);
        if (vector.redactionContains) expect(redacted, vector.name).toContain(vector.redactionContains);
      }
      if (vector.selectorField || vector.selectorFieldId) {
        const selection = () => resolveField(parsed, { field: vector.selectorField, fieldId: vector.selectorFieldId });
        if (vector.selectionError) {
          expect(selection, vector.name).toThrow();
        } else {
          const resolved = selection();
          expect(resolved.kind === 'value' ? resolved.value : resolved.code, vector.name).toBe(vector.expectedFieldValue);
        }
      }
    }
  });

  it('keeps exit classes and wait policy precedence aligned', () => {
    for (const vector of grants.states) {
      const access = accessState(vector.access);
      expect(exitCodeForAccess(access.access), vector.access).toBe(vector.exitCode);
      expect(vector.exitCode === 75, vector.access).toBe(vector.retryable);
    }
    for (const vector of grants.waitPolicies) {
      const actual = resolveWaitPolicy(vector.options, vector.hints);
      expect(
        { waitMs: actual.waitMs, pollMs: actual.pollMs, heartbeatMs: actual.heartbeatMs, pollTimeoutMs: actual.pollTimeoutMs },
        vector.name,
      ).toEqual(vector.expected);
    }
    for (const vector of grants.durations) {
      expect(parseDuration(vector.input), vector.input).toBe(vector.expectedMs);
    }
  });

  it('consumes the frozen exact schedule and cancellation scenarios', async () => {
    for (const vector of grants.waitScenarios) {
      const policy = { ...vector.policy, progress: 'plain' as const };
      if (vector.cancelDuring === 'poll') {
        const controller = new AbortController();
        const waiting = awaitGrant(
          { access: 'pending', grantId: 'grant-fixture' },
          policy,
          {
            poll: async () => {
              controller.abort(new Error('cancelled'));
              return new Promise<CredentialAccess>(() => {});
            },
            sleep: async () => {},
            heartbeat: () => {},
            signal: controller.signal,
          },
        );
        await expect(waiting, vector.name).rejects.toThrow(vector.expectedError);
        continue;
      }
      if (vector.hangPoll) {
        const heartbeats: number[] = [];
        const result = await awaitGrant(
          { access: 'pending', grantId: 'grant-fixture' },
          policy,
          {
            poll: async () => new Promise<CredentialAccess>(() => {}),
            sleep: async () => {},
            heartbeat: (heartbeat) => { heartbeats.push(heartbeat.elapsedMs); },
          },
        );
        expect(heartbeats, vector.name).toEqual(vector.expectedHeartbeatMs);
        expect(result.access, vector.name).toBe(vector.expectedAccess);
        continue;
      }

      const sleeps: number[] = [];
      const heartbeats: number[] = [];
      const responses = (vector.responses ?? []).map(accessState);
      let pollIndex = 0;
      const result = await awaitGrant(
        { access: 'pending', grantId: 'grant-fixture' },
        policy,
        {
          poll: async () => responses[pollIndex++]!,
          sleep: async (milliseconds) => { sleeps.push(milliseconds); },
          heartbeat: (heartbeat) => { heartbeats.push(heartbeat.elapsedMs); },
        },
      );
      expect(sleeps, vector.name).toEqual(vector.expectedSleepMs);
      expect(heartbeats, vector.name).toEqual(vector.expectedHeartbeatMs);
      expect(result.access, vector.name).toBe(vector.expectedAccess);
    }
  });
});

function fixture<T>(name: string): T {
  return JSON.parse(
    readFileSync(new URL(`../../runtime/contracts/v1/${name}`, import.meta.url), 'utf8'),
  ) as T;
}

function accessState(access: string): CredentialAccess {
  if (access === 'granted') return {
    access,
    entryId: 'entry-fixture',
    label: 'Fixture',
    urlDomain: null,
    reEncryptedBlob: 'AA==',
    nonce: 'AA==',
    agentWrappedDek: 'AA==',
  };
  if (access === 'pending') return { access, grantId: 'grant-fixture' };
  if (
    access === 'unavailable' ||
    access === 'denied' ||
    access === 'revoked' ||
    access === 'expired' ||
    access === 'consumed' ||
    access === 'method-not-allowed' ||
    access === 'script-exec-only' ||
    access === 'blocked'
  ) {
    return { access };
  }
  throw new Error('unknown synthetic access state');
}
