import { spawn, spawnSync } from 'node:child_process';

const [timeoutText, command, ...args] = process.argv.slice(2);
const timeoutSeconds = Number(timeoutText);

if (!Number.isSafeInteger(timeoutSeconds)
  || timeoutSeconds < 1
  || timeoutSeconds > 900
  || !command) {
  process.stderr.write('usage: node run-bounded.mjs SECONDS COMMAND [ARG ...]\n');
  process.exit(64);
}

const detached = process.platform !== 'win32';
const child = spawn(command, args, {
  detached,
  shell: false,
  stdio: 'inherit',
});

let timedOut = false;

function terminate(signal) {
  if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) return;
  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
    return;
  }
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (!(error instanceof Error) || !('code' in error) || error.code !== 'ESRCH') throw error;
  }
}

const timeout = setTimeout(() => {
  timedOut = true;
  process.stderr.write(`bounded command exceeded ${timeoutSeconds} seconds\n`);
  terminate('SIGKILL');
}, timeoutSeconds * 1_000);

const result = await new Promise((resolve, reject) => {
  child.once('error', reject);
  child.once('exit', (code, signal) => resolve({ code, signal }));
});

clearTimeout(timeout);
if (timedOut) process.exit(124);
if (result.signal !== null || result.code === null) process.exit(1);
process.exit(result.code);
