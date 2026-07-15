import { describe, expect, it } from 'vitest';

import { aggregateShards } from '../../security/lifecycle/aggregate-shards.mjs';
import { lifecycleFixture } from './platform-lifecycle-fixture';

describe('physical lifecycle shard aggregation', () => {
  it('accepts exactly one shard for every manifest target', () => {
    const { manifest, evidence } = lifecycleFixture();
    const shards = evidence.targets.map((target) => ({
      schemaVersion: 1,
      sourceSha: evidence.sourceSha,
      manifestSha256: evidence.manifestSha256,
      runId: evidence.runId,
      runAttempt: evidence.runAttempt,
      target,
    }));
    expect(aggregateShards({
      manifest, shards, expectedSourceSha: evidence.sourceSha,
      expectedRunId: evidence.runId, expectedRunAttempt: evidence.runAttempt,
    })).toEqual(evidence);
  });

  it('rejects a missing, duplicate, or foreign-run shard', () => {
    const { manifest, evidence } = lifecycleFixture();
    const shards = evidence.targets.map((target) => ({
      schemaVersion: 1, sourceSha: evidence.sourceSha, manifestSha256: evidence.manifestSha256,
      runId: evidence.runId, runAttempt: evidence.runAttempt, target,
    }));
    expect(() => aggregateShards({
      manifest, shards: shards.slice(1), expectedSourceSha: evidence.sourceSha,
      expectedRunId: evidence.runId, expectedRunAttempt: evidence.runAttempt,
    })).toThrow('missing');
    expect(() => aggregateShards({
      manifest, shards: [...shards.slice(1), shards[1]], expectedSourceSha: evidence.sourceSha,
      expectedRunId: evidence.runId, expectedRunAttempt: evidence.runAttempt,
    })).toThrow('duplicate');
    const foreign = structuredClone(shards); foreign[0].runId = '999';
    expect(() => aggregateShards({
      manifest, shards: foreign, expectedSourceSha: evidence.sourceSha,
      expectedRunId: evidence.runId, expectedRunAttempt: evidence.runAttempt,
    })).toThrow('binding');
  });
});
