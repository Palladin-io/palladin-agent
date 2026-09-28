import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

function report(captured: string) {
  const directory = mkdtempSync(join(tmpdir(), 'palladin-boundary-diagnostic-'));
  try {
    const error = join(directory, 'init.err');
    writeFileSync(error, captured, { mode: 0o600 });
    return spawnSync('/bin/bash', ['-c',
      'source packaging/macos/scripts/boundary-failure.sh; report_boundary_failure 7 101 "$1"',
      'boundary-test', error,
    ], { encoding: 'utf8' });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe.skipIf(process.platform === 'win32')('signed boundary failure diagnostics', () => {
  it('reports a fixed secure-store category without copying captured output', () => {
    const result = report('Error: OS secure storage is unavailable; no file or environment fallback is allowed\nsynthetic-private-marker\n');
    expect(result.status).toBe(0);
    const outputIsEmpty = result.stdout === '';
    expect(outputIsEmpty).toBe(true);
    const messageIsExpected = result.stderr === 'Signed boundary failed at script line 101 (exit 7); init category: secure-storage-unavailable; Keychain OSStatus: unavailable; captured output withheld.\n';
    expect(messageIsExpected).toBe(true);
  });

  it('reports only the numeric Keychain status from a complete known error', () => {
    const result = report('Error: OS secure storage operation failed: macOS Keychain write failed (OSStatus -34018); no fallback is allowed\nsynthetic-private-marker\n');
    expect(result.status).toBe(0);
    const outputIsEmpty = result.stdout === '';
    expect(outputIsEmpty).toBe(true);
    const messageIsExpected = result.stderr === 'Signed boundary failed at script line 101 (exit 7); init category: secure-storage-write-failed; Keychain OSStatus: -34018; captured output withheld.\n';
    expect(messageIsExpected).toBe(true);
  });

  it('withholds unknown errors and does not classify a decorated message', () => {
    const result = report('Error: OS secure storage is unavailable; no file or environment fallback is allowed synthetic-private-marker\n');
    expect(result.status).toBe(0);
    const outputIsEmpty = result.stdout === '';
    expect(outputIsEmpty).toBe(true);
    const messageIsExpected = result.stderr === 'Signed boundary failed at script line 101 (exit 7); init category: unknown; Keychain OSStatus: unavailable; captured output withheld.\n';
    expect(messageIsExpected).toBe(true);
  });
});
