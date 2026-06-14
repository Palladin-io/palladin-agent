import { spawn } from 'child_process';
import { Transform } from 'stream';
import { ParsedSecret } from '../crypto/secret.js';

/**
 * Run `command` with the credential injected into the subprocess environment (CVT-150), the `op run`
 * pattern. The secret reaches the child process but never the agent's own stdout: the child's
 * stdout/stderr are streamed through with any literal occurrence of a secret value masked, so a
 * command that accidentally echoes `$CLAW_PASSWORD` cannot leak it back into the agent's context.
 *
 * Env vars exported to the child:
 *   CLAW_SECRET            the primary secret (password for CREDENTIAL, value for KEY)
 *   CLAW_USERNAME          present for CREDENTIAL entries
 *   CLAW_PASSWORD          alias of CLAW_SECRET for CREDENTIAL entries
 *   CLAW_<FIELD>           every string field of the payload, upper-cased
 *
 * @returns the child's exit code (or 1 if it was killed by a signal).
 */
export async function runExec(command: string[], secret: ParsedSecret): Promise<number> {
  const result = await runExecCapture(command, secret, { stream: true });
  return result.code;
}

export interface ExecCaptureResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Like {@link runExec} but always captures the (masked) output and returns it. Used by the MCP
 * `exec` tool, which must return the result as text to the model rather than to a terminal. When
 * `stream` is set the masked output is also written to the parent's stdout/stderr (CLI mode).
 */
export async function runExecCapture(
  command: string[],
  secret: ParsedSecret,
  options?: { stream?: boolean },
): Promise<ExecCaptureResult> {
  const [cmd, ...args] = command;
  if (!cmd) {
    return Promise.resolve({ code: 127, stdout: '', stderr: 'Error: no command given\n' });
  }

  const env: NodeJS.ProcessEnv = { ...process.env };
  env.CLAW_SECRET = secret.password;
  if (secret.username !== null) {
    env.CLAW_USERNAME = secret.username;
    env.CLAW_PASSWORD = secret.password;
  }
  for (const [key, value] of Object.entries(secret.fields)) {
    env[`CLAW_${key.toUpperCase()}`] = value;
  }

  // Values to mask in the child's output. Mask the longest first so a value that contains another
  // (e.g. password contains username) is fully redacted.
  const secretValues = Array.from(
    new Set([secret.password, secret.username, ...Object.values(secret.fields)].filter((v): v is string => !!v && v.length >= 4)),
  ).sort((a, b) => b.length - a.length);

  return new Promise<ExecCaptureResult>((resolve) => {
    const child = spawn(cmd, args, { env, stdio: ['inherit', 'pipe', 'pipe'] as const });
    let stdout = '';
    let stderr = '';
    let exitCode = 0;

    const out = child.stdout.pipe(makeMask(secretValues));
    const err = child.stderr.pipe(makeMask(secretValues));
    out.on('data', (d: Buffer | string) => {
      stdout += d.toString();
      if (options?.stream) process.stdout.write(d);
    });
    err.on('data', (d: Buffer | string) => {
      stderr += d.toString();
      if (options?.stream) process.stderr.write(d);
    });

    // Resolve only once the child has exited AND both masked streams have fully flushed (their
    // `end` fires after the transform's flush, so the final carry — which may hold a secret split
    // across chunks — is masked before we read `stdout`/`stderr`). Resolving on the child's `close`
    // alone would race the transform flush and could surface an unmasked tail.
    let pending = 3;
    const settle = () => {
      pending -= 1;
      if (pending === 0) {
        resolve({ code: exitCode, stdout, stderr });
      }
    };

    child.on('error', (e) => {
      const line = `Error: failed to run "${cmd}": ${e.message}\n`;
      stderr += line;
      if (options?.stream) process.stderr.write(line);
      resolve({ code: 127, stdout, stderr });
    });
    child.on('close', (code, signal) => {
      exitCode = code ?? (signal ? 1 : 0);
      settle();
    });
    out.on('end', settle);
    err.on('end', settle);
  });
}

/**
 * A stream transform that replaces any occurrence of a secret value with `***`, robust to a secret
 * split across chunk boundaries. Each chunk: redact complete occurrences, then hold back only the
 * trailing characters that form a *prefix* of some secret (so the rest of that secret can still
 * arrive next chunk). Everything else is emitted immediately.
 */
function makeMask(secrets: string[]): Transform {
  if (secrets.length === 0) {
    return new Transform({ transform(chunk, _enc, cb) { cb(null, chunk); } });
  }
  let carry = '';

  const redact = (text: string): string => {
    let out = text;
    for (const secret of secrets) {
      out = out.split(secret).join('***');
    }
    return out;
  };

  // Longest suffix of `text` that is a strict prefix of some secret — the only tail that could grow
  // into a full secret on a later chunk, so it must be held back rather than emitted.
  const heldBackLength = (text: string): number => {
    let max = 0;
    for (const secret of secrets) {
      const limit = Math.min(secret.length - 1, text.length);
      for (let k = limit; k > max; k--) {
        if (secret.startsWith(text.slice(text.length - k))) {
          max = k;
          break;
        }
      }
    }
    return max;
  };

  return new Transform({
    transform(chunk, _enc, cb) {
      const redacted = redact(carry + chunk.toString('utf8'));
      const hold = heldBackLength(redacted);
      carry = redacted.slice(redacted.length - hold);
      cb(null, redacted.slice(0, redacted.length - hold));
    },
    flush(cb) {
      cb(null, redact(carry));
    },
  });
}
