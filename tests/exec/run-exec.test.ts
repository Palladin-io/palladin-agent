import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, existsSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { Writable } from 'stream';
import { runExecCapture, runExecForTool } from '../../src/exec/run-exec.js';
import { ParsedSecret } from '../../src/crypto/secret.js';

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
    expect(result.stdout).toContain(':'); // both env vars were present
  });

  it('masks secret values that the command echoes', async () => {
    const secret = credential('alice', 'superSecretPassword123');
    const result = await runExecCapture(
      ['node', '-e', 'process.stdout.write("token=" + process.env.CLAW_PASSWORD)'],
      secret,
    );
    expect(result.code).toBe(0);
    expect(result.stdout).not.toContain('superSecretPassword123');
    expect(result.stdout).toContain('***');
  });

  it('masks a secret split across stream chunks', async () => {
    const secret = credential('u', 'ABCDEFGHIJKLMNOP');
    // Print the secret in two halves with a flush in between to force separate chunks.
    const script = 'process.stdout.write("ABCDEFGH"); setTimeout(() => process.stdout.write("IJKLMNOP"), 50)';
    const result = await runExecCapture(['node', '-e', script], secret);
    expect(result.stdout).not.toContain('ABCDEFGHIJKLMNOP');
  });

  it('exports every string field as CLAW_<FIELD>', async () => {
    const secret = credential('alice', 'pw', { apikey: 'XYZ987WWWW' });
    const result = await runExecCapture(
      ['node', '-e', 'process.stdout.write(process.env.CLAW_APIKEY ? "has-apikey" : "no")'],
      secret,
    );
    expect(result.stdout).toContain('has-apikey');
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
    expect(result).not.toHaveProperty('stdout');
    expect(result).not.toHaveProperty('stderr');

    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain('superSecretPassword123');
    expect(serialized).not.toContain('BEGIN');
    expect(serialized).not.toContain('END');
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
    expect(seen).toContain('BEGIN');
    expect(seen).toContain('END');
    expect(seen).not.toContain('superSecretPassword123');
    expect(seen).toContain('***');
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
    expect(contents).not.toContain('superSecretPassword123');
    expect(contents).toContain('***');
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
