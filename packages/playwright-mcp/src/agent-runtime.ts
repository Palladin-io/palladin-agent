import { spawn, type ChildProcess } from 'node:child_process';
import type { Readable } from 'node:stream';
import { accessSync, constants as fsConstants, readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative } from 'node:path';

const AGENT_PACKAGE = '@palladin/agent';
const AGENT_VERSION = '0.1.0';

export interface AgentRuntimeLocation {
  packageRoot?: string;
  launcher?: string;
}

/**
 * The gateway may use NODE_EXTRA_CA_CERTS for its own HTTP client. Palladin's
 * signed native runtime rejects loader/TLS override variables at its trust
 * boundary, so never inherit this variable into the provider child. Keep the
 * rest of the environment intact: PATH, HOME and explicitly configured
 * Palladin variables are required for local development and profile lookup.
 */
export function providerRuntimeEnvironment(
  parent: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const environment = { ...parent };
  delete environment.NODE_EXTRA_CA_CERTS;
  return environment;
}

const MAX_RUNTIME_STDERR_BYTES = 64 * 1024;

export interface RuntimeStderrCapture {
  readonly done: Promise<string>;
}

/** Drain stderr immediately so a noisy rejected runtime cannot deadlock. */
export function captureRuntimeStderr(stream: Readable): RuntimeStderrCapture {
  let buffer = Buffer.alloc(0);
  let settled = false;
  let resolveDone: (value: string) => void = () => undefined;
  const done = new Promise<string>((resolve) => { resolveDone = resolve; });
  const finish = (): void => {
    if (settled) return;
    settled = true;
    const value = buffer.toString('utf8');
    buffer.fill(0);
    buffer = Buffer.alloc(0);
    resolveDone(value);
  };
  stream.on('data', (chunk: Buffer | string) => {
    if (buffer.length >= MAX_RUNTIME_STDERR_BYTES) return;
    const next = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const remaining = MAX_RUNTIME_STDERR_BYTES - buffer.length;
    buffer = Buffer.concat([buffer, next.subarray(0, remaining)]);
  });
  stream.once('end', finish);
  stream.once('close', finish);
  stream.once('error', finish);
  return { done };
}

/**
 * Start the installed, exact-version Palladin launcher with private provider pipes.
 * The launcher performs the signed native-runtime verification; this provider never
 * resolves a runtime executable or accepts an environment/PATH override itself.
 */
export function spawnAgentRuntime(
  args: readonly string[],
  location: AgentRuntimeLocation = {},
): ChildProcess {
  const require = createRequire(import.meta.url);
  const configuredLauncher = location.launcher?.trim()
    || process.env.PALLADIN_AGENT_LAUNCHER?.trim();
  const configuredRoot = location.packageRoot?.trim()
    || process.env.PALLADIN_AGENT_PACKAGE_ROOT?.trim();
  const manifestPath = realpathSync(configuredRoot === undefined
    ? require.resolve(`${AGENT_PACKAGE}/package.json`)
    : join(configuredRoot, 'package.json'));
  const packageRoot = dirname(manifestPath);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as unknown;
  if (!isRecord(manifest) || manifest.name !== AGENT_PACKAGE || manifest.version !== AGENT_VERSION) {
    throw new Error('Palladin Agent package identity is invalid');
  }
  const launcher = realpathSync(configuredLauncher ?? join(packageRoot, 'dist', 'bin', 'palladin.js'));
  const pathFromPackage = relative(packageRoot, launcher);
  if (pathFromPackage === '' || pathFromPackage === '..'
    || pathFromPackage.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)) {
    throw new Error('Palladin Agent launcher resolved outside its package');
  }
  accessSync(launcher, fsConstants.R_OK);
  const child = spawn(process.execPath, [launcher, ...args], {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
    env: providerRuntimeEnvironment(),
  });
  if (child.stdin === null || child.stdout === null) {
    child.kill();
    throw new Error('Palladin Agent provider pipes are unavailable');
  }
  return child;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
