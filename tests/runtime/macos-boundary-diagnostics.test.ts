import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

function report(captured: string, phase = 'initialization') {
  const directory = mkdtempSync(join(tmpdir(), 'palladin-boundary-diagnostic-'));
  try {
    const error = join(directory, 'init.err');
    writeFileSync(error, captured, { mode: 0o600 });
    const summary = join(directory, 'summary.md');
    const result = spawnSync('/bin/bash', ['-c',
      'source packaging/macos/scripts/boundary-failure.sh; report_boundary_failure 7 101 "$1" "$2"',
      'boundary-test', error, phase,
    ], { encoding: 'utf8', env: { ...process.env, GITHUB_STEP_SUMMARY: summary } });
    return { ...result, summary: readFileSync(summary, 'utf8') };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe.skipIf(process.platform === 'win32')('signed boundary failure diagnostics', () => {
  it.each([
    ['unexpected-output', 'printf "private-fixture-marker\\n" >&2'],
    ['canary-disclosure', 'printf "%s" "$PALLADIN_BOUNDARY_PRIVATE_CANARY" >&2'],
    ['capture-bound', 'printf "fresh operating-system authorization is required for this operation\\n" >&2; head -c 1048577 /dev/zero'],
  ] as const)('reports %s without exposing captured output', (reason, output) => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-probe-reason-'));
    try {
      const fakeBinary = join(directory, 'fake-runtime');
      writeFileSync(fakeBinary, `#!/bin/sh\n${output}\nexit 1\n`);
      chmodSync(fakeBinary, 0o700);
      const probe = spawnSync(process.execPath, [
        'packaging/macos/tests/signed-client-probe.mjs', fakeBinary, fakeBinary, join(directory, 'captures'),
      ], { encoding: 'utf8', env: { ...process.env, HOME: directory } });
      expect(probe.status).toBe(1);
      const diagnostic = report(probe.stderr, 'intact-copy-and-client-authorization');
      expect(diagnostic.status).toBe(0);
      expect(diagnostic.stderr.includes(`signed-client-blind-genuine-${reason}`)).toBe(true);
      expect(diagnostic.summary.includes(`signed-client-blind-genuine-${reason}`)).toBe(true);
      expect(diagnostic.stderr.includes('private-fixture-marker')).toBe(false);
      expect(diagnostic.summary.includes('private-fixture-marker')).toBe(false);
      expect(diagnostic.stderr.includes('palladin-boundary-')).toBe(false);
      expect(diagnostic.summary.includes('palladin-boundary-')).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('attributes an unexpectedly successful MCP connection to its result, not the last stage', () => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-mcp-success-diagnostic-'));
    try {
      const fakeBinary = join(directory, 'fake-runtime');
      writeFileSync(fakeBinary, [
        '#!/bin/sh',
        'case "$1" in',
        '  init) printf "fresh operating-system authorization is required for this operation\\nprivate-fixture-marker\\n" >&2; exit 1 ;;',
        '  connect) exit 1 ;;',
        '  mcp) IFS= read -r _; printf \'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}\\n\'; IFS= read -r _; IFS= read -r _; printf \'{"jsonrpc":"2.0","id":2,"result":{"content":[]}}\\n\'; exit 0 ;;',
        'esac',
      ].join('\n'));
      chmodSync(fakeBinary, 0o700);
      const probe = spawnSync(process.execPath, [
        'packaging/macos/tests/signed-client-probe.mjs', fakeBinary, fakeBinary, join(directory, 'captures'),
      ], { encoding: 'utf8', env: { ...process.env, HOME: directory } });
      expect(probe.status).toBe(1);
      const diagnostic = report(probe.stderr, 'intact-copy-and-client-authorization');
      expect(diagnostic.status).toBe(0);
      expect(diagnostic.stderr.includes('signed-client-mcp-connection-1-unexpected-success')).toBe(true);
      expect(diagnostic.summary.includes('signed-client-mcp-connection-1-unexpected-success')).toBe(true);
      expect(diagnostic.stderr.includes('private-fixture-marker')).toBe(false);
      expect(diagnostic.summary.includes('private-fixture-marker')).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects an MCP protocol error instead of accepting it as an authorized tool denial', () => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-mcp-parameters-diagnostic-'));
    try {
      const fakeBinary = join(directory, 'fake-runtime');
      writeFileSync(fakeBinary, [
        '#!/bin/sh',
        'case "$1" in',
        '  init) printf "fresh operating-system authorization is required for this operation\\n" >&2; exit 1 ;;',
        '  connect) exit 1 ;;',
        '  mcp) IFS= read -r _; printf \'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}\\n\'; IFS= read -r _; IFS= read -r _; printf \'{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"invalid parameters"}}\\n\'; sleep 3 ;;',
        'esac',
      ].join('\n'));
      chmodSync(fakeBinary, 0o700);
      const probe = spawnSync(process.execPath, [
        'packaging/macos/tests/signed-client-probe.mjs', fakeBinary, fakeBinary, join(directory, 'captures'),
      ], { encoding: 'utf8', env: { ...process.env, HOME: directory } });
      expect(probe.status).toBe(1);
      const diagnostic = report(probe.stderr, 'intact-copy-and-client-authorization');
      expect(diagnostic.stderr.includes('signed-client-mcp-connection-1-unexpected-output')).toBe(true);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('accepts a denied MCP tool call on an unconfigured synthetic profile', () => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-mcp-unconfigured-diagnostic-'));
    try {
      const fakeBinary = join(directory, 'fake-runtime');
      writeFileSync(fakeBinary, [
        '#!/bin/sh',
        'case "$1" in',
        '  init) printf "fresh operating-system authorization is required for this operation\\n" >&2; exit 1 ;;',
        '  connect) exit 1 ;;',
        '  mcp) IFS= read -r _; printf \'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}\\n\'; IFS= read -r notification; IFS= read -r _; case "$notification" in *notifications/initialized*) ;; *) exit 1 ;; esac; printf \'{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Palladin could not complete the request."}],"isError":true}}\\n\'; exit 0 ;;',
        'esac',
      ].join('\n'));
      chmodSync(fakeBinary, 0o700);
      const probe = spawnSync(process.execPath, [
        'packaging/macos/tests/signed-client-probe.mjs', fakeBinary, fakeBinary, join(directory, 'captures'),
      ], { encoding: 'utf8', env: { ...process.env, HOME: directory } });
      expect(probe.status).toBe(0);
      expect(probe.stdout.includes('failed closed')).toBe(true);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('accepts a bounded, output-free identity wait on a headless Mac', () => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-headless-authorization-'));
    try {
      const fakeBinary = join(directory, 'fake-runtime');
      writeFileSync(fakeBinary, [
        '#!/bin/sh',
        'case "$1" in',
        '  init) exec sleep 20 ;;',
        '  connect) exit 1 ;;',
        '  mcp) IFS= read -r _; printf \'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}\\n\'; IFS= read -r _; IFS= read -r _; printf \'{"jsonrpc":"2.0","id":2,"result":{"content":[],"isError":true}}\\n\'; exit 0 ;;',
        'esac',
      ].join('\n'));
      chmodSync(fakeBinary, 0o700);
      const probe = spawnSync(process.execPath, [
        'packaging/macos/tests/signed-client-probe.mjs', fakeBinary, fakeBinary, join(directory, 'captures'),
      ], { encoding: 'utf8', env: { ...process.env, HOME: directory }, timeout: 25_000 });
      expect(probe.status).toBe(0);
      expect(probe.stderr.match(/bounded-no-identity/g)).toHaveLength(2);
      expect(probe.stdout.includes('failed closed')).toBe(true);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 30_000);

  it('attributes a concurrent MCP rejection to the failing connection, not the last one started', () => {
    const diagnostic = report([
      'Palladin signed-client probe stage: mcp-first-connection',
      'Palladin signed-client probe stage: mcp-second-connection',
      'Palladin signed-client probe failure: mcp-first-connection: probe-error',
      'private-fixture-marker',
    ].join('\n'), 'intact-copy-and-client-authorization');
    expect(diagnostic.status).toBe(0);
    expect(diagnostic.stderr.includes('signed-client-mcp-first-connection-probe-error')).toBe(true);
    expect(diagnostic.summary.includes('signed-client-mcp-first-connection-probe-error')).toBe(true);
    expect(diagnostic.stderr.includes('private-fixture-marker')).toBe(false);
    expect(diagnostic.summary.includes('private-fixture-marker')).toBe(false);
  });

  it('identifies the signed client operation without exposing its child output', () => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-signed-client-diagnostic-'));
    try {
      const fakeBinary = join(directory, 'fake-runtime');
      writeFileSync(fakeBinary, '#!/bin/sh\nprintf "Error: profile does not exist; run: palladin agents create <name>\\nprivate-fixture-marker\\n" >&2\nexit 1\n');
      chmodSync(fakeBinary, 0o700);
      const probe = spawnSync(process.execPath, [
        'packaging/macos/tests/signed-client-probe.mjs', fakeBinary, fakeBinary, join(directory, 'captures'),
      ], { encoding: 'utf8', env: { ...process.env, HOME: directory } });
      expect(probe.status).toBe(1);
      const diagnostic = report(probe.stderr, 'intact-copy-and-client-authorization');
      expect(diagnostic.status).toBe(0);
      expect(diagnostic.stderr.includes('signed-client-blind-genuine-profile-not-found')).toBe(true);
      expect(diagnostic.summary.includes('signed-client-blind-genuine-profile-not-found')).toBe(true);
      expect(diagnostic.stderr.includes('private-fixture-marker')).toBe(false);
      expect(diagnostic.stdout.includes('private-fixture-marker')).toBe(false);
      expect(diagnostic.summary.includes('private-fixture-marker')).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

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
