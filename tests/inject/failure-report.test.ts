import { describe, it, expect, afterEach } from 'vitest';
import { readFileSync, rmSync, readdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { mkdtempSync } from 'fs';
import {
  buildFailureReport,
  summarizeControls,
  writeFailureReport,
} from '../../src/inject/failure-report.js';
import { parseHTML } from 'linkedom';
import { expectSensitiveExcludes } from '../helpers/sensitive-assert.js';

function doc(html: string) {
  return parseHTML(html).document as unknown as Parameters<typeof summarizeControls>[0];
}

describe('summarizeControls — value-free structural snapshot', () => {
  it('captures identification attributes but NEVER the value', () => {
    const controls = summarizeControls(doc(`<form>
      <input type="text" name="username" id="u" autocomplete="username" value="alice@example.com">
      <input type="password" name="password" value="superSecret123">
      <button type="submit">Sign in</button>
    </form>`));

    const username = controls.find((c) => c.name === 'username');
    expect(username).toMatchObject({ tag: 'input', type: 'text', autocomplete: 'username', inForm: true });
    // The snapshot must not carry any value field at all.
    const serialized = JSON.stringify(controls);
    expectSensitiveExcludes(serialized, 'alice@example.com', 'structural control snapshot');
    expectSensitiveExcludes(serialized, 'superSecret123', 'structural control snapshot');
    expect(Object.keys(username!)).not.toContain('value');
  });

  it('records hidden inputs as hidden (so we know they were skipped)', () => {
    const controls = summarizeControls(doc('<form><input type="hidden" name="csrf" value="abc"></form>'));
    expect(controls[0]).toMatchObject({ name: 'csrf', hidden: true });
    expectSensitiveExcludes(JSON.stringify(controls), 'abc', 'hidden control snapshot');
  });
});

describe('buildFailureReport', () => {
  it('stores origin only, never the full URL (which may carry tokens)', () => {
    const report = buildFailureReport({
      reason: 'no login form detected on the current page',
      steps: ['origin verified: example.com'],
      vaultId: 'v1',
      entryId: 'e1',
      entryDomain: 'example.com',
      pageUrl: 'https://example.com/login?session=SECRET-TOKEN&next=/x',
      html: '<form><input type="password" name="pw" value="leak"></form>',
      now: new Date('2026-06-11T12:00:00Z'),
    });

    expect(report.pageOrigin).toBe('https://example.com');
    const serialized = JSON.stringify(report);
    expectSensitiveExcludes(serialized, 'SECRET-TOKEN', 'failure report');
    expectSensitiveExcludes(serialized, 'leak', 'failure report');
    expect(report.controls).toHaveLength(1);
    expect(report.timestamp).toBe('2026-06-11T12:00:00.000Z');
  });
});

describe('writeFailureReport', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
    dirs.length = 0;
    delete process.env['PALLADIN_NO_DIAGNOSTICS'];
  });

  function tempRoot() {
    const d = mkdtempSync(join(tmpdir(), 'cv-fail-'));
    dirs.push(d);
    return d;
  }

  it('appends one JSON line per failure', () => {
    const root = tempRoot();
    const report = buildFailureReport({
      reason: 'no login form detected on the current page',
      steps: [],
      vaultId: 'v1',
      entryId: 'e1',
      entryDomain: 'example.com',
      pageUrl: 'https://example.com/login',
      html: '<div></div>',
      now: new Date('2026-06-11T12:00:00Z'),
    });

    const path1 = writeFailureReport(report, root);
    const path2 = writeFailureReport(report, root);
    expect(path1).not.toBeNull();
    expect(path1).toBe(path2); // same day → same file

    const lines = readFileSync(path1!, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]!).reason).toContain('no login form');
  });

  it('respects the PALLADIN_NO_DIAGNOSTICS opt-out', () => {
    const root = tempRoot();
    process.env['PALLADIN_NO_DIAGNOSTICS'] = '1';
    const report = buildFailureReport({
      reason: 'x', steps: [], vaultId: 'v', entryId: 'e', entryDomain: null,
      pageUrl: 'https://x.com', html: '<div></div>',
    });
    expect(writeFailureReport(report, root)).toBeNull();
    expect(() => readdirSync(join(root, 'inject-failures'))).toThrow();
  });
});
