import { spawn, type ChildProcess } from 'node:child_process';
import { accessSync, constants as fsConstants, readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, relative } from 'node:path';

const AGENT_PACKAGE = '@palladin/agent';
const AGENT_VERSION = '0.1.0';

export function spawnAgentRuntime(args: readonly string[]): ChildProcess {
  const require = createRequire(import.meta.url);
  const configuredLauncher = process.env.PALLADIN_AGENT_LAUNCHER?.trim();
  const configuredRoot = process.env.PALLADIN_AGENT_PACKAGE_ROOT?.trim();
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
    || pathFromPackage.startsWith('../') || pathFromPackage.startsWith('..\\')
    || isAbsolute(pathFromPackage)) {
    throw new Error('Palladin Agent launcher resolved outside its package');
  }
  accessSync(launcher, fsConstants.R_OK);
  const child = spawn(process.execPath, [launcher, ...args], {
    shell: false,
    stdio: ['pipe', 'pipe', 'inherit'],
    windowsHide: true,
    env: process.env,
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
