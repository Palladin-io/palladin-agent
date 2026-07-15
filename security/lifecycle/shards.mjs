import { canonicalSha256, validateManifest } from './report.mjs';

const SOURCE_SHA = /^[0-9a-f]{40}$/;
const RUN_ID = /^[1-9][0-9]*$/;

function fail(message) { throw new Error(message); }
function record(value, label) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}
function exactKeys(value, keys, label) {
  const actual = Object.keys(record(value, label)).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has an invalid shape`);
  }
}

export function aggregateShards({ manifest: manifestInput, shards, expectedSourceSha, expectedRunId, expectedRunAttempt }) {
  const manifest = validateManifest(manifestInput);
  if (!SOURCE_SHA.test(expectedSourceSha) || !RUN_ID.test(expectedRunId)
    || !Number.isSafeInteger(expectedRunAttempt) || expectedRunAttempt < 1) fail('aggregation context is invalid');
  const expectedManifestSha = canonicalSha256(manifest);
  const targetById = new Map(manifest.targets.map((target) => [target.id, target]));
  const targets = [];
  for (const [index, shardInput] of shards.entries()) {
    const label = `shards[${index}]`;
    const shard = record(shardInput, label);
    exactKeys(shard, ['schemaVersion', 'sourceSha', 'manifestSha256', 'runId', 'runAttempt', 'target'], label);
    if (shard.schemaVersion !== 1 || shard.sourceSha !== expectedSourceSha
      || shard.manifestSha256 !== expectedManifestSha || shard.runId !== expectedRunId
      || shard.runAttempt !== expectedRunAttempt) fail(`${label} binding is invalid`);
    const target = record(shard.target, `${label}.target`);
    exactKeys(target, ['targetId', 'artifacts', 'steps'], `${label}.target`);
    if (!targetById.has(target.targetId) || targets.some((item) => item.targetId === target.targetId)) {
      fail(`${label} target is unknown or duplicate`);
    }
    targets.push(target);
  }
  if (targets.length !== manifest.targets.length) fail('required physical target shard is missing');
  return {
    schemaVersion: 1,
    sourceSha: expectedSourceSha,
    manifestSha256: expectedManifestSha,
    runId: expectedRunId,
    runAttempt: expectedRunAttempt,
    targets: manifest.targets.map((target) => targets.find((item) => item.targetId === target.id)),
  };
}
