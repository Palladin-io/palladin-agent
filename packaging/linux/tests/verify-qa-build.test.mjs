import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const source = 'a'.repeat(40);
const repository = 'example/runtime';
const valid = {
  conclusion: 'success',
  event: 'workflow_dispatch',
  path: '.github/workflows/rust-runtime.yml',
  head_sha: source,
  repository: { full_name: repository },
  head_repository: { full_name: repository },
};

for (const [name, overrides, accepted] of [
  ['matching successful first-party build', {}, true],
  ['PR merge build instead of the exact dispatched revision', { event: 'pull_request' }, false],
  ['failed build', { conclusion: 'failure' }, false],
  ['another workflow', { path: '.github/workflows/other.yml' }, false],
  ['another source commit', { head_sha: 'b'.repeat(40) }, false],
  ['another repository', { repository: { full_name: 'other/runtime' } }, false],
  ['fork source', { head_repository: { full_name: 'fork/runtime' } }, false],
]) {
  test(name, () => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-qa-build-'));
    try {
      const metadata = join(directory, 'run.json');
      writeFileSync(metadata, JSON.stringify({ ...valid, ...overrides }));
      const result = spawnSync(process.execPath, [
        'packaging/linux/tests/verify-qa-build.mjs', metadata, source, repository,
      ], { encoding: 'utf8', timeout: 5000 });
      assert.equal(result.status, accepted ? 0 : 1);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
