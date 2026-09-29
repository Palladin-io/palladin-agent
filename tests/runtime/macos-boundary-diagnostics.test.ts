import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
  it.each([
    ['OR assertion', ['false || die "fixed assertion"'], 0],
    ['if assertion', ['if true; then', '  die "fixed assertion"', 'fi'], 1],
    ['library assertion', ['require_regular_file "$2" "synthetic fixture"'], 0],
  ] as const)('preserves the caller line, exit and cleanup for %s', (_name, commands, failureOffset) => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-boundary-assertion-'));
    try {
      const fixture = join(directory, 'assertion.sh');
      const captured = join(directory, 'capture.err');
      const summary = join(directory, 'summary.md');
      writeFileSync(captured, 'synthetic-private-marker\n', { mode: 0o600 });
      const setup = [
        'set -euo pipefail',
        'source packaging/macos/scripts/lib.sh',
        'boundary_script="${BASH_SOURCE[0]}"',
        'source packaging/macos/scripts/boundary-failure.sh',
        'boundary_failure_line=999',
        'capture_path="$1"',
        `trap 'failure=$?; report_boundary_failure "$failure" "$boundary_failure_line" "$capture_path" assertion; rm -f "$capture_path"' EXIT`,
      ];
      writeFileSync(fixture, [...setup, ...commands, ''].join('\n'));
      const result = spawnSync('/bin/bash', [fixture, captured, join(directory, 'missing')], {
        encoding: 'utf8', env: { ...process.env, GITHUB_STEP_SUMMARY: summary },
      });
      expect(result.status).toBe(1);
      const expectedLine = setup.length + failureOffset + 1;
      const summaryIsExpected = readFileSync(summary, 'utf8') === `| assertion | FAIL | ${expectedLine} | 1 | unknown | unavailable |\n`;
      expect(summaryIsExpected).toBe(true);
      expect(existsSync(captured)).toBe(false);
      const outputWithholdsCapture = !result.stdout.includes('synthetic-private-marker') && !result.stderr.includes('synthetic-private-marker');
      expect(outputWithholdsCapture).toBe(true);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

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
