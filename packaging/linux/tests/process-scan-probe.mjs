import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from 'node:fs';
import { join } from 'node:path';

const [mode, ...arguments_] = process.argv.slice(2);
if (!['--process', '--tree'].includes(mode)) process.exit(64);
if (mode === '--process' && (arguments_.length !== 2 || !/^[1-9]\d*$/.test(arguments_[0])
  || !arguments_[1]?.startsWith('/'))) process.exit(64);
if (mode === '--tree' && (arguments_.length === 0 || arguments_.some((root) => !root.startsWith('/')))) {
  process.exit(64);
}

const chunks = [];
let canarySize = 0;
for await (const chunk of process.stdin) {
  canarySize += chunk.length;
  if (canarySize > 128) process.exit(64);
  chunks.push(Buffer.from(chunk));
}
const canary = Buffer.concat(chunks);
for (const chunk of chunks) chunk.fill(0);
if (canary.length < 32) process.exit(64);

function assertAbsent(bytes, label) {
  if (bytes.length > 4 * 1024 * 1024) throw new Error(`${label} exceeded the scan bound`);
  if (bytes.includes(canary)) throw new Error(`${label} contained the stdin canary`);
}

function readOpenedRegular(path, expectedMetadata, label) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || (expectedMetadata !== undefined
      && (opened.dev !== expectedMetadata.dev || opened.ino !== expectedMetadata.ino))) {
      throw new Error(`${label} changed during the bounded scan`);
    }
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

if (mode === '--process') {
  const [pid, expectedExecutable] = arguments_;
  if (realpathSync(`/proc/${pid}/exe`) !== realpathSync(expectedExecutable)) {
    throw new Error('process scan target is not the exact installed client');
  }
  assertAbsent(readOpenedRegular(`/proc/${pid}/cmdline`, undefined, 'client argv'), 'client argv');
  assertAbsent(readOpenedRegular(`/proc/${pid}/environ`, undefined, 'client environment'), 'client environment');
} else {
  const pending = [...arguments_];
  let total = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) throw new Error('public-state scan state is invalid');
    const metadata = lstatSync(current);
    if (metadata.isSymbolicLink()) throw new Error('public state contains a symbolic link');
    if (metadata.isDirectory()) {
      for (const entry of readdirSync(current)) pending.push(join(current, entry));
    } else if (metadata.isFile()) {
      total += metadata.size;
      if (total > 4 * 1024 * 1024) throw new Error('public state exceeded the scan bound');
      assertAbsent(readOpenedRegular(current, metadata, 'public state'), 'public state');
    } else throw new Error('public state contains an unsupported file type');
  }
}

canary.fill(0);
process.stdout.write(mode === '--process'
  ? 'argv-environment=stdin-canary-absent exact-client=verified\n'
  : 'public-config-and-output=stdin-canary-absent\n');
