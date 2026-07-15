import { describe, it, expect } from 'vitest';
import { existsSync } from 'fs';
import { Writable } from 'stream';
import { runScript, assertAllowedInterpreter, interpreterBinary, ScriptError, ALLOWED_INTERPRETERS } from '../../src/exec/run-script.js';
import { expectSensitiveContains, expectSensitiveEqual, expectSensitiveExcludes } from '../helpers/sensitive-assert.js';

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

describe('interpreterBinary', () => {
  it('runs python as python3, everything else as-is', () => {
    expect(interpreterBinary('python')).toBe('python3');
    expect(interpreterBinary('node')).toBe('node');
    expect(interpreterBinary('bash')).toBe('bash');
    expect(interpreterBinary('sh')).toBe('sh');
  });
});

describe('runScript', () => {
  it('runs the script under the interpreter with refs in the environment', async () => {
    const result = await runScript('process.stdout.write(process.env.GH_TOKEN || "none")', 'node', {
      env: { ...process.env, GH_TOKEN: 'tok-123' },
      secretValues: [],
    });
    expect(result.code).toBe(0);
    expectSensitiveEqual(result.stdout, 'tok-123', 'script credential output');
  });

  it('writes the script with private POSIX permissions and deletes it afterwards', async () => {
    const result = await runScript(
      'const fs=require("fs");const p=process.argv[1];process.stdout.write(JSON.stringify({p,mode:fs.statSync(p).mode & 0o777}))',
      'node',
      { env: { ...process.env }, secretValues: [] },
    );
    const { p, mode } = JSON.parse(result.stdout) as { p: string; mode: number };
    // Windows does not implement POSIX mode bits and reports 0666 even when
    // writeFileSync receives mode 0600. Its access boundary comes from the
    // current user's temp-directory ACL instead.
    if (process.platform !== 'win32') {
      expect(mode).toBe(0o600);
    }
    expect(existsSync(p)).toBe(false); // removed in the finally
  });

  it('deletes the temp file even when the script fails', async () => {
    const result = await runScript(
      'const p=process.argv[1];process.stdout.write(p);process.exit(2)',
      'node',
      { env: { ...process.env }, secretValues: [] },
    );
    expect(result.code).toBe(2);
    const temporaryScriptStillExists = existsSync(result.stdout);
    expect(temporaryScriptStillExists).toBe(false);
  });

  it('masks reference values in the mirrored/captured output', async () => {
    const mirror = collectStream();
    const result = await runScript('process.stdout.write("leak=" + process.env.SECRET)', 'node', {
      env: { ...process.env, SECRET: 'superSecretRefValue' },
      secretValues: ['superSecretRefValue'],
      mirror: mirror.stream,
    });
    expectSensitiveExcludes(result.stdout, 'superSecretRefValue', 'captured script output');
    expectSensitiveContains(result.stdout, '***', 'masked script output');
    expectSensitiveExcludes(mirror.text(), 'superSecretRefValue', 'mirrored script output');
  });

  it('rejects a non-whitelisted interpreter before running anything', async () => {
    await expect(runScript('echo hi', 'ruby', { env: {}, secretValues: [] })).rejects.toThrow(ScriptError);
  });
});
