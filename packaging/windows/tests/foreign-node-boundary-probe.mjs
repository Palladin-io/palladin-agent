import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const pipeName = String.raw`\\.\pipe\LOCAL\Palladin.Runtime.v1`;
const maximumCaptureBytes = 64 * 1024;
const helloDenial = 'Windows Hello is unavailable or consent was not granted';

function classifyBoundaryErrorCode(code) {
  if (code === 'EACCES' || code === 'EPERM') return 'access-denied';
  if (code === 'ENOENT') return 'missing';
  return 'unavailable';
}

if (process.argv[2] === '--classify-boundary-error') {
  process.stdout.write(`${classifyBoundaryErrorCode(process.argv[3])}\n`);
  process.exit(0);
}

if (process.argv[2] === '--pipe-open-attempt') {
  try {
    const descriptor = openSync(pipeName, 'r+');
    closeSync(descriptor);
    process.exit(10);
  } catch (error) {
    const classification = classifyBoundaryErrorCode(error?.code);
    if (classification === 'access-denied') process.exit(0);
    if (classification === 'missing') process.exit(20);
    process.exit(21);
  }
}

const [
  mode,
  clientInput,
  cacheModuleInput,
  workDirectoryInput,
  programDataProfileInput,
  packageName,
  packageVersion,
  publisher,
  thumbprint,
  profilePresence,
] = process.argv.slice(2);
if (!['hosted', 'dedicated-hardware'].includes(mode)
  || !clientInput || !cacheModuleInput || !workDirectoryInput || !programDataProfileInput
  || !packageName || !packageVersion || !publisher || !thumbprint
  || !['present', 'missing'].includes(profilePresence)) {
  process.stderr.write(
    'usage: foreign-node-boundary-probe.mjs MODE CLIENT CACHE_MODULE WORK_DIRECTORY PROGRAMDATA_PROFILE PACKAGE VERSION PUBLISHER THUMBPRINT PROFILE_PRESENCE\n',
  );
  process.exit(64);
}

const client = realpathSync(clientInput);
const cacheModule = realpathSync(cacheModuleInput);
for (const candidate of [client, cacheModule]) {
  const metadata = lstatSync(candidate);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error('foreign Node probe requires regular, non-link inputs');
  }
}

mkdirSync(workDirectoryInput, { recursive: true });
const workDirectory = realpathSync(workDirectoryInput);

async function runBounded(executable, arguments_, timeoutMs = 10_000) {
  const child = spawn(executable, arguments_, {
    shell: false,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  let capturedBytes = 0;
  let exceededCapture = false;
  let timedOut = false;
  const collect = (target) => (chunk) => {
    capturedBytes += chunk.length;
    if (capturedBytes > maximumCaptureBytes) {
      exceededCapture = true;
      child.kill();
      return;
    }
    target.push(Buffer.from(chunk));
  };
  child.stdout.on('data', collect(stdout));
  child.stderr.on('data', collect(stderr));
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill();
  }, timeoutMs);
  const result = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer);
  if (timedOut) throw new Error('foreign Node child exceeded its time bound');
  if (exceededCapture) throw new Error('foreign Node child exceeded its capture bound');
  return {
    ...result,
    output: Buffer.concat([...stdout, ...stderr]).toString('utf8'),
  };
}

const hello = await runBounded(client, ['init']);
if (hello.code === 0 || !hello.output.includes(helloDenial)) {
  throw new Error('blindly spawned signed client did not require fresh Windows Hello consent');
}

const completed = ['fresh-consent'];
const limitations = [];
const pipeAttempt = await runBounded(process.execPath, [realpathSync(process.argv[1]), '--pipe-open-attempt'], 3_000);
if (pipeAttempt.code === 0) {
  completed.push('named-pipe-access-denied');
} else if (pipeAttempt.code === 10) {
  throw new Error('foreign Node process opened the broker named pipe');
} else if (mode === 'hosted') {
  limitations.push(pipeAttempt.code === 20 ? 'named-pipe-missing' : 'named-pipe-readiness-unavailable');
} else {
  throw new Error('dedicated named-pipe probe did not receive ACCESS_DENIED');
}

if (profilePresence === 'missing') {
  if (mode === 'dedicated-hardware') {
    throw new Error('dedicated ProgramData probe requires a trusted preflight-confirmed real profile');
  }
  limitations.push('programdata-profile-missing');
} else {
  try {
    lstatSync(programDataProfileInput);
    throw new Error('foreign Node process inspected the broker-owned ProgramData profile');
  } catch (error) {
    if (error instanceof Error && error.message.includes('broker-owned ProgramData profile')) throw error;
    const classification = classifyBoundaryErrorCode(error?.code);
    if (classification === 'access-denied') {
      completed.push('programdata-access-denied');
    } else if (mode === 'hosted') {
      limitations.push(classification === 'missing'
        ? 'programdata-profile-preflight-raced'
        : 'programdata-readiness-unavailable');
    } else {
      throw new Error('dedicated ProgramData probe did not receive ACCESS_DENIED');
    }
  }
}

const tamperedClient = join(workDirectory, 'palladin-client-modified.exe');
copyFileSync(client, tamperedClient);
const original = readFileSync(tamperedClient);
if (original.length < 2) throw new Error('signed client is unexpectedly empty');
const modified = Buffer.from(original);
modified[modified.length - 1] ^= 1;
writeFileSync(tamperedClient, modified, { flag: 'w' });
modified.fill(0);
const executableSha256 = createHash('sha256').update(original).digest('hex');
original.fill(0);

const imported = await import(pathToFileURL(cacheModule));
if (typeof imported.prepareWindowsRuntimeCache !== 'function') {
  throw new Error('trusted Windows cache verifier is unavailable');
}
let rejected = false;
try {
  imported.prepareWindowsRuntimeCache({
    packageName,
    version: packageVersion,
    executable: tamperedClient,
  }, {
    packageName,
    version: packageVersion,
    executableSha256,
    sourceSha: '0'.repeat(40),
    runtimeAllowed: true,
    authenticodePublisher: publisher,
    authenticodeThumbprint: thumbprint.replaceAll(' ', '').toUpperCase(),
    envelopeBase64: 'not-used-by-the-cache-verifier',
  }, {
    cacheRoot: join(workDirectory, 'cache'),
  });
} catch {
  rejected = true;
}
rmSync(tamperedClient, { force: true });
if (!rejected) throw new Error('modified signed client passed the exact dispatcher verifier');
completed.push('modified-client-rejected');

if (mode === 'hosted' && limitations.length === 0) {
  limitations.push('dedicated-hardware-attacker-token-not-exercised');
}
for (const item of completed) process.stdout.write(`evidence-complete: ${item}\n`);
for (const item of limitations) process.stdout.write(`hosted-limitation: ${item}\n`);
process.stdout.write(limitations.length === 0
  ? 'evidence-status: complete-dedicated-boundaries\n'
  : 'evidence-status: incomplete-hosted-boundaries\n');
