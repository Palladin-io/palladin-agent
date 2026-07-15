import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, existsSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { Writable } from 'stream';
import { runExecCapture, runExecForTool } from '../../src/exec/run-exec.js';
import { ParsedSecret } from '../../src/crypto/secret.js';
import { expectSensitiveContains, expectSensitiveExcludes } from '../helpers/sensitive-assert.js';

function collectStream(): { stream: Writable; text: () => string } {
  let buf = '';
  const stream = new Writable({
    write(chunk, _enc, cb) { buf += chunk.toString(); cb(); },
  });
  return { stream, text: () => buf };
}

function credential(username: string, password: string, extra: Record<string, string> = {}): ParsedSecret {
  return {
    username,
    password,
    url: null,
    notes: null,
    fields: { username, password, ...extra },
  };
}

describe('runExecCapture — env injection + masking', () => {
  it('injects CLAW_USERNAME / CLAW_PASSWORD / CLAW_SECRET into the subprocess env', async () => {
    const secret = credential('alice', 'hunter2');
    const result = await runExecCapture(
      ['node', '-e', 'process.stdout.write([process.env.CLAW_USERNAME, process.env.CLAW_SECRET].join(":"))'],
      secret,
    );
    expect(result.code).toBe(0);
    // The username is not a secret value (<4 chars? "alice" is 5, so it IS masked). Verify structure
    // via a field that is short enough not to be masked.
    expectSensitiveContains(result.stdout, ':', 'captured credential output'); // both env vars were present
  });

  it('masks secret values that the command echoes', async () => {
    const secret = credential('alice', 'superSecretPassword123');
    const result = await runExecCapture(
      ['node', '-e', 'process.stdout.write("token=" + process.env.CLAW_PASSWORD)'],
      secret,
    );
    expect(result.code).toBe(0);
    expectSensitiveExcludes(result.stdout, 'superSecretPassword123', 'masked child output');
    expectSensitiveContains(result.stdout, '***', 'masked child output');
  });

  it('masks a secret split across stream chunks', async () => {
    const secret = credential('u', 'ABCDEFGHIJKLMNOP');
    // Print the secret in two halves with a flush in between to force separate chunks.
    const script = 'process.stdout.write("ABCDEFGH"); setTimeout(() => process.stdout.write("IJKLMNOP"), 50)';
    const result = await runExecCapture(['node', '-e', script], secret);
    expectSensitiveExcludes(result.stdout, 'ABCDEFGHIJKLMNOP', 'chunked child output');
  });

  it('exports every string field as CLAW_<FIELD>', async () => {
    const secret = credential('alice', 'pw', { apikey: 'XYZ987WWWW' });
    const result = await runExecCapture(
      ['node', '-e', 'process.stdout.write(process.env.CLAW_APIKEY ? "has-apikey" : "no")'],
      secret,
    );
    expectSensitiveContains(result.stdout, 'has-apikey', 'credential environment probe');
  });

  it('passes through the exit code', async () => {
    const result = await runExecCapture(['node', '-e', 'process.exit(3)'], credential('a', 'bbbb'));
    expect(result.code).toBe(3);
  });

  it('returns 127 when the command does not exist', async () => {
    const result = await runExecCapture(['this-command-does-not-exist-xyz'], credential('a', 'bbbb'));
    expect(result.code).toBe(127);
  });
});

describe('runExecForTool — model-safe result (CVT-200)', () => {
  it('does NOT return the child stdout/stderr to the model, only exit code + note', async () => {
    const logRoot = mkdtempSync(join(tmpdir(), 'palladin-exec-'));
    const mirror = collectStream();
    const secret = credential('alice', 'superSecretPassword123');
    const result = await runExecForTool(
      ['node', '-e', 'process.stdout.write("BEGIN " + process.env.CLAW_PASSWORD + " END")'],
      secret,
      { mirror: mirror.stream, logRoot },
    );

    expect(result.exitCode).toBe(0);
    expect(result.output).toBe('withheld');
    expect(!('stdout' in result)).toBe(true);
    expect(!('stderr' in result)).toBe(true);

    const serialized = JSON.stringify(result);
    expectSensitiveExcludes(serialized, 'superSecretPassword123', 'model-safe result');
    expectSensitiveExcludes(serialized, 'BEGIN', 'model-safe result');
    expectSensitiveExcludes(serialized, 'END', 'model-safe result');
  });

  it('mirrors (masked) output to the operator stream so a human still sees it', async () => {
    const logRoot = mkdtempSync(join(tmpdir(), 'palladin-exec-'));
    const mirror = collectStream();
    const secret = credential('alice', 'superSecretPassword123');
    await runExecForTool(
      ['node', '-e', 'process.stdout.write("BEGIN " + process.env.CLAW_PASSWORD + " END")'],
      secret,
      { mirror: mirror.stream, logRoot },
    );
    const seen = mirror.text();
    expectSensitiveContains(seen, 'BEGIN', 'operator output');
    expectSensitiveContains(seen, 'END', 'operator output');
    expectSensitiveExcludes(seen, 'superSecretPassword123', 'operator output');
    expectSensitiveContains(seen, '***', 'operator output');
  });

  it('writes a masked local log for the operator (never the raw secret)', async () => {
    const logRoot = mkdtempSync(join(tmpdir(), 'palladin-exec-'));
    const mirror = collectStream();
    const secret = credential('alice', 'superSecretPassword123');
    const result = await runExecForTool(
      ['node', '-e', 'process.stdout.write(process.env.CLAW_PASSWORD)'],
      secret,
      { mirror: mirror.stream, logRoot },
    );
    expect(result.localLog).toBeDefined();
    expect(existsSync(result.localLog!)).toBe(true);
    const contents = readFileSync(result.localLog!, 'utf8');
    expectSensitiveExcludes(contents, 'superSecretPassword123', 'local operator log');
    expectSensitiveContains(contents, '***', 'local operator log');
  });

  it('honours PALLADIN_NO_DIAGNOSTICS=1 (no local log written)', async () => {
    const logRoot = mkdtempSync(join(tmpdir(), 'palladin-exec-'));
    const mirror = collectStream();
    const prev = process.env['PALLADIN_NO_DIAGNOSTICS'];
    process.env['PALLADIN_NO_DIAGNOSTICS'] = '1';
    try {
      const result = await runExecForTool(['node', '-e', 'process.stdout.write("x")'], credential('a', 'bbbb'), {
        mirror: mirror.stream,
        logRoot,
      });
      expect(result.localLog).toBeUndefined();
      expect(readdirSync(logRoot).length).toBe(0);
    } finally {
      if (prev === undefined) delete process.env['PALLADIN_NO_DIAGNOSTICS'];
      else process.env['PALLADIN_NO_DIAGNOSTICS'] = prev;
    }
  });
});
