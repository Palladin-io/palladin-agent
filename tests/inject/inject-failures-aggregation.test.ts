import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { buildFailureReport, writeFailureReport, failureReportDir } from '../../src/inject/failure-report.js';
import { expectSensitiveExcludes } from '../helpers/sensitive-assert.js';

// The review command's aggregation logic is exercised indirectly here via the stored reports,
// asserting the on-disk format round-trips and stays value-free across multiple entries.
describe('inject failure reports — aggregation source data', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
    dirs.length = 0;
  });

  function tempRoot() {
    const d = mkdtempSync(join(tmpdir(), 'cv-agg-'));
    dirs.push(d);
    return d;
  }

  it('persists multiple failures for the same domain that a reviewer can group', () => {
    const root = tempRoot();
    for (let i = 0; i < 3; i++) {
      writeFailureReport(buildFailureReport({
        reason: 'no login form detected on the current page',
        steps: [],
        vaultId: 'v1',
        entryId: `e${i}`,
        entryDomain: 'tricky-site.com',
        pageUrl: 'https://tricky-site.com/auth?token=SHOULD-NOT-PERSIST',
        html: '<div><input aria-label="Identyfikator"><input type="password"></div>',
        now: new Date('2026-06-11T10:00:00Z'),
      }), root);
    }

    const fs = require('fs') as typeof import('fs');
    const dir = failureReportDir(root);
    const files = fs.readdirSync(dir).filter((f: string) => f.endsWith('.jsonl'));
    expect(files).toHaveLength(1);

    const content = fs.readFileSync(join(dir, files[0]!), 'utf8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(3);

    // The aggregation reads entryDomain; all three share it.
    const domains = lines.map((l) => JSON.parse(l).entryDomain);
    expect(domains).toEqual(['tricky-site.com', 'tricky-site.com', 'tricky-site.com']);

    // Still value-free: the URL token never persisted, the localised aria-label structure did.
    expectSensitiveExcludes(content, 'SHOULD-NOT-PERSIST', 'aggregated failure report');
    expect(content).toContain('Identyfikator');
  });
});
