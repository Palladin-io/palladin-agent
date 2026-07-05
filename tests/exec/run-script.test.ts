import { describe, it, expect } from 'vitest';
import { existsSync } from 'fs';
import { Writable } from 'stream';
import { runScript, assertAllowedInterpreter, ScriptError, ALLOWED_INTERPRETERS } from '../../src/exec/run-script.js';

function collectStream(): { stream: Writable; text: () => string } {
  let buf = '';
  const stream = new Writable({
    write(chunk, _enc, cb) { buf += chunk.toString(); cb(); },
  });
  return { stream, text: () => buf };
}

describe('assertAllowedInterpreter', () => {
  it('accepts the whitelisted interpreters, case/space-insensitively', () => {
    for (const bin of ALLOWED_INTERPRETERS) {
      expect(assertAllowedInterpreter(` ${bin.toUpperCase()} `)).toBe(bin);
    }
  });

  it('rejects anything else', () => {
    expect(() => assertAllowedInterpreter('ruby')).toThrow(ScriptError);
    expect(() => assertAllowedInterpreter('rm -rf /')).toThrow(ScriptError);
    expect(() => assertAllowedInterpreter('')).toThrow(ScriptError);
  });
});

describe('runScript', () => {
  it('runs the script under the interpreter with refs in the environment', async () => {
    const result = await runScript('process.stdout.write(process.env.GH_TOKEN || "none")', 'node', {
      env: { ...process.env, GH_TOKEN: 'tok-123' },
      secretValues: [],
    });
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('tok-123');
  });

  it('writes the script to a private (0600) temp file and deletes it afterwards', async () => {
    const result = await runScript(
      'const fs=require("fs");const p=process.argv[1];process.stdout.write(JSON.stringify({p,mode:fs.statSync(p).mode & 0o777}))',
      'node',
      { env: { ...process.env }, secretValues: [] },
    );
    const { p, mode } = JSON.parse(result.stdout) as { p: string; mode: number };
    expect(mode).toBe(0o600);
    expect(existsSync(p)).toBe(false); // removed in the finally
  });

  it('deletes the temp file even when the script fails', async () => {
    const result = await runScript(
      'const p=process.argv[1];process.stdout.write(p);process.exit(2)',
      'node',
      { env: { ...process.env }, secretValues: [] },
    );
    expect(result.code).toBe(2);
    expect(existsSync(result.stdout)).toBe(false);
  });

  it('masks reference values in the mirrored/captured output', async () => {
    const mirror = collectStream();
    const result = await runScript('process.stdout.write("leak=" + process.env.SECRET)', 'node', {
      env: { ...process.env, SECRET: 'superSecretRefValue' },
      secretValues: ['superSecretRefValue'],
      mirror: mirror.stream,
    });
    expect(result.stdout).not.toContain('superSecretRefValue');
    expect(result.stdout).toContain('***');
    expect(mirror.text()).not.toContain('superSecretRefValue');
  });

  it('rejects a non-whitelisted interpreter before running anything', async () => {
    await expect(runScript('echo hi', 'ruby', { env: {}, secretValues: [] })).rejects.toThrow(ScriptError);
  });
});
