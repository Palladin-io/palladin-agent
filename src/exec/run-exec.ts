import { spawn } from 'child_process';
import { Transform } from 'stream';
import { appendFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { ParsedSecret } from '../crypto/secret.js';
import { palladinRoot } from '../config/paths.js';

/**
 * Run `command` with the credential injected into the subprocess environment (the `op run` pattern).
 *
 * Child stdout/stderr are untrusted for a model: a prompt-injected agent can make the command
 * re-encode the secret to defeat any mask, so output is withheld from the MCP caller and shown to
 * the human instead. MCP mode streams it to stderr, never stdout (the stdio protocol channel).
 *
 * Env vars exported to the child:
 *   CLAW_SECRET            the primary secret (password for CREDENTIAL, value for KEY)
 *   CLAW_USERNAME          present for CREDENTIAL entries
 *   CLAW_PASSWORD          alias of CLAW_SECRET for CREDENTIAL entries
 *   CLAW_<FIELD>           every string field of the payload, upper-cased
 *
 * @returns the child's exit code (or 1 if it was killed by a signal).
 */
export async function runExec(command: string[], secret: ParsedSecret, options?: RunExecOptions): Promise<number> {
  const result = await runExecCapture(command, secret, { ...options, mirror: 'terminal' });
  return result.code;
}

export interface ExecCaptureResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Where to mirror a child's masked output for a human; never returned to a model. */
export type ExecMirror = 'terminal' | NodeJS.WritableStream;

export interface RunExecOptions {
  /**
   * 'terminal' → process.stdout/stderr; a WritableStream → both there (MCP passes process.stderr,
   * since stdio JSON-RPC owns stdout); undefined → capture only.
   */
  mirror?: ExecMirror;
  /** Extra env vars merged over the `CLAW_*` set (e.g. `--env NAME=field` mappings). */
  extraEnv?: Record<string, string>;
  /** Extra values to redact from the mirrored output (the `extraEnv` values). */
  extraSecretValues?: string[];
}

/** Env vars + extra values to redact for a masked run. */
export interface MaskedRunInput {
  env: NodeJS.ProcessEnv;
  /** Values redacted (`***`) in the mirrored output. */
  secretValues: string[];
  mirror?: ExecMirror;
}

/**
 * Like {@link runExec} but captures the masked output and returns it. Callers serving a model MUST
 * NOT forward the captured stdout/stderr to it — use {@link runExecForTool}, which withholds it.
 */
export async function runExecCapture(
  command: string[],
  secret: ParsedSecret,
  options?: RunExecOptions,
): Promise<ExecCaptureResult> {
  return runMasked(command, {
    env: { ...buildCredentialEnv(secret), ...options?.extraEnv },
    secretValues: [...credentialSecretValues(secret), ...(options?.extraSecretValues ?? [])],
    mirror: options?.mirror,
  });
}

/**
 * Spawn `command` with a fully-prepared environment, masking every value in `secretValues` from the
 * mirrored (human-facing) output. This is the shared core behind credential `exec` and Script `exec`.
 */
export function runMasked(command: string[], input: MaskedRunInput): Promise<ExecCaptureResult> {
  const [cmd, ...args] = command;
  if (!cmd) {
    return Promise.resolve({ code: 127, stdout: '', stderr: 'Error: no command given\n' });
  }

  // Mask longest value first so a value containing another (password contains username) is redacted.
  const secretValues = Array.from(new Set(input.secretValues.filter((v): v is string => !!v))).sort(
    (a, b) => b.length - a.length,
  );

  const mirrorOut = input.mirror === 'terminal' ? process.stdout : input.mirror;
  const mirrorErr = input.mirror === 'terminal' ? process.stderr : input.mirror;

  return new Promise<ExecCaptureResult>((resolve) => {
    const child = spawn(cmd, args, { env: input.env, stdio: ['inherit', 'pipe', 'pipe'] as const });
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

/** Build the `CLAW_*` environment for a credential exec. */
function buildCredentialEnv(secret: ParsedSecret): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  env.CLAW_SECRET = secret.password;
  if (secret.username !== null) {
    env.CLAW_USERNAME = secret.username;
    env.CLAW_PASSWORD = secret.password;
  }
  for (const [key, value] of Object.entries(secret.fields)) {
    env[`CLAW_${key.toUpperCase()}`] = value;
  }
  return env;
}

/** Every plaintext value of a credential, for output masking. */
function credentialSecretValues(secret: ParsedSecret): string[] {
  return [secret.password, secret.username, ...Object.values(secret.fields)].filter((v): v is string => !!v);
}

/** Result returned to a model by the MCP exec tool — carries NO command output. */
export interface ExecToolResult {
  exitCode: number;
  output: 'withheld';
  note: string;
  localLog?: string;
}

export interface RunExecForToolOptions {
  mirror?: NodeJS.WritableStream;
  /** Root dir for the local log (tests override this). Defaults to the Palladin home. */
  logRoot?: string;
}

/** Run a command for the MCP `exec_with_credential` tool and return a model-safe result. */
export async function runExecForTool(
  command: string[],
  secret: ParsedSecret,
  options?: RunExecForToolOptions,
): Promise<ExecToolResult> {
  const mirror = options?.mirror ?? process.stderr;
  const result = await runExecCapture(command, secret, { mirror });
  return toWithheldResult(result, options?.logRoot);
}

/**
 * Turn a captured result into the model-safe shape the MCP tools return: exit code + a note, output
 * withheld, with a best-effort masked tail written to a local operator log. Shared by exec + script.
 */
export function toWithheldResult(result: ExecCaptureResult, logRoot?: string): ExecToolResult {
  const localLog = writeExecLog(result, logRoot);
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
 * Append a masked tail of an exec result to `~/.palladin/exec-logs/YYYY-MM-DD.log` for the operator.
 * Best-effort: write errors never propagate. Opt out with `PALLADIN_NO_DIAGNOSTICS=1`.
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
