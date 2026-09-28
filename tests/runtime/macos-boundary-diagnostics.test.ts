import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

function report(captured: string) {
  const directory = mkdtempSync(join(tmpdir(), 'palladin-boundary-diagnostic-'));
  try {
    const error = join(directory, 'init.err');
    writeFileSync(error, captured, { mode: 0o600 });
    const summary = join(directory, 'summary.md');
    const result = spawnSync('/bin/bash', ['-c',
      'source packaging/macos/scripts/boundary-failure.sh; report_boundary_failure 7 101 "$1" initialization',
      'boundary-test', error,
    ], { encoding: 'utf8', env: { ...process.env, GITHUB_STEP_SUMMARY: summary } });
    return { ...result, summary: readFileSync(summary, 'utf8') };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe.skipIf(process.platform === 'win32')('signed boundary failure diagnostics', () => {
  it('reports a fixed secure-store category without copying captured output', () => {
    const result = report('Error: OS secure storage is unavailable; no file or environment fallback is allowed\nsynthetic-private-marker\n');
    expect(result.status).toBe(0);
    const annotationIsSafe = result.stdout.includes('::error file=packaging/macos/scripts/test-security-boundary.sh,line=101::Signed boundary test initialization failed') && !result.stdout.includes('synthetic-private-marker');
    expect(annotationIsSafe).toBe(true);
    expect(result.summary.includes('synthetic-private-marker')).toBe(false);
    const messageIsExpected = result.stderr === 'Signed boundary test initialization failed at script line 101 (exit 7); category: secure-storage-unavailable; Keychain OSStatus: unavailable; captured output withheld.\n';
    expect(messageIsExpected).toBe(true);
    expect(result.summary.startsWith('| initialization | FAIL | 101 | 7 |')).toBe(true);
  });

  it('reports only the numeric Keychain status from a complete known error', () => {
    const result = report('Error: OS secure storage operation failed: macOS Keychain operation failed (OSStatus -34018); no fallback is allowed\nsynthetic-private-marker\n');
    expect(result.status).toBe(0);
    const annotationIsSafe = result.stdout.includes('::error file=packaging/macos/scripts/test-security-boundary.sh,line=101::Signed boundary test initialization failed') && !result.stdout.includes('synthetic-private-marker');
    expect(annotationIsSafe).toBe(true);
    expect(result.summary.includes('synthetic-private-marker')).toBe(false);
    const messageIsExpected = result.stderr === 'Signed boundary test initialization failed at script line 101 (exit 7); category: secure-storage-operation-failed; Keychain OSStatus: -34018; captured output withheld.\n';
    expect(messageIsExpected).toBe(true);
    expect(result.summary.startsWith('| initialization | FAIL | 101 | 7 |')).toBe(true);
  });

  it('withholds unknown errors and does not classify a decorated message', () => {
    const result = report('Error: OS secure storage is unavailable; no file or environment fallback is allowed synthetic-private-marker\n');
    expect(result.status).toBe(0);
    const annotationIsSafe = result.stdout.includes('::error file=packaging/macos/scripts/test-security-boundary.sh,line=101::Signed boundary test initialization failed') && !result.stdout.includes('synthetic-private-marker');
    expect(annotationIsSafe).toBe(true);
    expect(result.summary.includes('synthetic-private-marker')).toBe(false);
    const messageIsExpected = result.stderr === 'Signed boundary test initialization failed at script line 101 (exit 7); category: unknown; Keychain OSStatus: unavailable; captured output withheld.\n';
    expect(messageIsExpected).toBe(true);
    expect(result.summary.startsWith('| initialization | FAIL | 101 | 7 |')).toBe(true);
  });
});
