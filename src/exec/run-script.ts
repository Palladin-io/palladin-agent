import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  ExecCaptureResult,
  ExecMirror,
  ExecToolResult,
  runMasked,
  toWithheldResult,
} from './run-exec.js';

/**
 * The only interpreters a Script entry may declare (spec §5). An arbitrary command is never run —
 * the blob names an interpreter from this fixed set and the script body is fed to it, nothing else.
 */
export const ALLOWED_INTERPRETERS = ['bash', 'sh', 'node', 'python'] as const;
export type Interpreter = (typeof ALLOWED_INTERPRETERS)[number];

export class ScriptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScriptError';
  }
}

/** Validate and normalise a declared interpreter, or throw if it is not whitelisted. */
export function assertAllowedInterpreter(interpreter: string): Interpreter {
  const normalised = interpreter.trim().toLowerCase();
  if (!(ALLOWED_INTERPRETERS as readonly string[]).includes(normalised)) {
    throw new ScriptError(
      `unsupported interpreter "${interpreter}" — a Script entry may only use: ${ALLOWED_INTERPRETERS.join(', ')}.`,
    );
  }
  return normalised as Interpreter;
}

export interface RunScriptInput {
  /** The referenced-entry values, exported to the child under their declared env-var names. */
  env: NodeJS.ProcessEnv;
  /** Values redacted (`***`) in the mirrored output — every injected reference value. */
  secretValues: string[];
  mirror?: ExecMirror;
}

/**
 * Execute a Script entry's body with the given interpreter and environment.
 *
 * The script is written to a private (mode 0600) temp file so the interpreter can read it, then the
 * file is removed unconditionally — even on failure — so the plaintext never lingers on disk. Output
 * is masked and mirrored for a human; the caller decides whether to withhold it from a model.
 */
export async function runScript(script: string, interpreter: string, input: RunScriptInput): Promise<ExecCaptureResult> {
  const bin = assertAllowedInterpreter(interpreter);

  const dir = mkdtempSync(join(tmpdir(), 'palladin-script-'));
  const file = join(dir, 'script');
  try {
    writeFileSync(file, script, { encoding: 'utf8', mode: 0o600 });
    return await runMasked([bin, file], input);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Run a Script entry for the MCP `exec_with_credential` tool and return a model-safe result. */
export async function runScriptForTool(
  script: string,
  interpreter: string,
  input: Omit<RunScriptInput, 'mirror'> & { mirror?: NodeJS.WritableStream; logRoot?: string },
): Promise<ExecToolResult> {
  const mirror = input.mirror ?? process.stderr;
  const result = await runScript(script, interpreter, { env: input.env, secretValues: input.secretValues, mirror });
  return toWithheldResult(result, input.logRoot);
}
