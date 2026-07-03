import { spawn } from 'child_process';
import { Transform } from 'stream';
import { appendFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { ParsedSecret } from '../crypto/secret.js';
import { palladinRoot } from '../config/paths.js';

/**
 * Run `command` with the credential injected into the subprocess environment (CVT-150), the `op run`
 * pattern. The secret reaches the child process but never the agent's own stdout.
 *
 * TRUST CONTRACT (CVT-200): the child's stdout/stderr are treated as UNTRUSTED for an AI model. We
 * do NOT return them to the MCP caller. A prompt-injected agent can trivially make the command
 * re-encode the secret (base64/hex/reverse/split) to defeat any output filter, so masking can never
 * be a security guarantee. The only safe contract is to withhold child output from the model and
 * show it to the human operator instead:
 *   - CLI mode: streamed to the operator's own terminal.
 *   - MCP mode: streamed to the server's stderr (never stdout — that is the stdio protocol channel)
 *     and appended to a local, best-effort masked log. The model gets only the exit code + a note.
 *
 * The verbatim mask below is retained only as best-effort hygiene for the human-facing mirror/log;
 * it is explicitly NOT relied upon to protect the model.
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
  const result = await runExecCapture(command, secret, { mirror: 'terminal' });
  return result.code;
}

export interface ExecCaptureResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface RunExecOptions {
  /**
   * Where to mirror the child's (best-effort masked) output so a human can see it. The output is
   * never returned to an AI model regardless of this setting.
   *  - 'terminal': stdout → process.stdout, stderr → process.stderr (interactive CLI).
   *  - a WritableStream: both streams mirrored there. The MCP server passes process.stderr — the
   *    stdio JSON-RPC protocol lives on stdout, so child output must never touch it.
   *  - undefined: capture only, no mirror.
   */
  mirror?: 'terminal' | NodeJS.WritableStream;
}

/**
 * Like {@link runExec} but captures the (best-effort masked) output and returns it. Callers that
 * serve an AI model MUST NOT forward the captured stdout/stderr to the model — use
 * {@link runExecForTool}, which withholds it. This function exists so the local log/mirror can be
 * built from the captured text.
 */
export async function runExecCapture(
  command: string[],
  secret: ParsedSecret,
  options?: RunExecOptions,
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

  // Best-effort hygiene only (NOT a guarantee — see the trust contract above). Mask the longest
  // value first so a value that contains another (e.g. password contains username) is fully
  // redacted. No minimum-length floor: even a short secret value is masked in the human mirror/log.
  const secretValues = Array.from(
    new Set([secret.password, secret.username, ...Object.values(secret.fields)].filter((v): v is string => !!v)),
  ).sort((a, b) => b.length - a.length);

  const mirrorOut = options?.mirror === 'terminal' ? process.stdout : options?.mirror;
  const mirrorErr = options?.mirror === 'terminal' ? process.stderr : options?.mirror;

  return new Promise<ExecCaptureResult>((resolve) => {
    const child = spawn(cmd, args, { env, stdio: ['inherit', 'pipe', 'pipe'] as const });
    let stdout = '';
    let stderr = '';
    let exitCode = 0;

    const out = child.stdout.pipe(makeMask(secretValues));
    const err = child.stderr.pipe(makeMask(secretValues));
    out.on('data', (d: Buffer | string) => {
      stdout += d.toString();
      mirrorOut?.write(d);
    });
    err.on('data', (d: Buffer | string) => {
      stderr += d.toString();
      mirrorErr?.write(d);
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
      mirrorErr?.write(line);
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

/** Result returned to an AI model by the MCP exec tool — deliberately carries NO command output. */
export interface ExecToolResult {
  exitCode: number;
  /** Always the literal string `withheld` — the model never receives child stdout/stderr. */
  output: 'withheld';
  note: string;
  /** Path to the local, best-effort masked log tail (for the human operator), when written. */
  localLog?: string;
}

export interface RunExecForToolOptions {
  /** Where to mirror output for the human. Defaults to process.stderr (safe under stdio MCP). */
  mirror?: NodeJS.WritableStream;
  /** Root dir for the local log (tests override this). Defaults to the Palladin home. */
  logRoot?: string;
}

/**
 * Run a command for the MCP `exec_with_credential` tool and return a model-safe result. The child's
 * stdout/stderr are streamed to the operator (default: this process's stderr) and appended to a
 * local masked log — they are NEVER placed in the returned object, which the model can read.
 */
export async function runExecForTool(
  command: string[],
  secret: ParsedSecret,
  options?: RunExecForToolOptions,
): Promise<ExecToolResult> {
  const mirror = options?.mirror ?? process.stderr;
  const result = await runExecCapture(command, secret, { mirror });
  const localLog = writeExecLog(result, options?.logRoot);
  return {
    exitCode: result.code,
    output: 'withheld',
    note:
      "Command stdout/stderr were withheld from you and streamed to the operator's terminal instead. " +
      'Output is treated as untrusted (a command can be coerced into re-encoding the secret to slip it ' +
      'past any filter), so it is never returned here — judge success from the exit code. ' +
      (localLog ? `A best-effort masked tail was written to ${localLog}.` : 'A local log could not be written.'),
    ...(localLog ? { localLog } : {}),
  };
}

/** Directory where local exec logs are appended. */
export function execLogDir(root: string = palladinRoot): string {
  return join(root, 'exec-logs');
}

const EXEC_LOG_TAIL_CHARS = 4000;

/**
 * Append a best-effort, secret-masked tail of an exec result to
 * `~/.palladin/exec-logs/YYYY-MM-DD.log` (mode 0600, dir 0700). For the human operator only, never
 * the model. Best-effort: a write error never propagates. Opt out with `PALLADIN_NO_DIAGNOSTICS=1`.
 */
export function writeExecLog(result: ExecCaptureResult, root?: string): string | null {
  if (process.env['PALLADIN_NO_DIAGNOSTICS'] === '1') {
    return null;
  }
  try {
    const dir = execLogDir(root);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const ts = new Date().toISOString();
    const file = join(dir, `${ts.slice(0, 10)}.log`);
    const tail = (s: string) => (s.length > EXEC_LOG_TAIL_CHARS ? `…${s.slice(s.length - EXEC_LOG_TAIL_CHARS)}` : s);
    const block =
      `--- ${ts} exit=${result.code} (output masked best-effort; withheld from model) ---\n` +
      `[stdout]\n${tail(result.stdout)}\n[stderr]\n${tail(result.stderr)}\n`;
    appendFileSync(file, block, { encoding: 'utf8', mode: 0o600 });
    return file;
  } catch {
    return null;
  }
}

/**
 * A stream transform that replaces any occurrence of a secret value with `***`, robust to a secret
 * split across chunk boundaries. Each chunk: redact complete occurrences, then hold back only the
 * trailing characters that form a *prefix* of some secret (so the rest of that secret can still
 * arrive next chunk). Everything else is emitted immediately. Best-effort hygiene for the human
 * mirror/log only — NOT a security boundary (see the trust contract on runExec).
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
