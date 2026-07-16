import { openSync, readFileSync, readdirSync, closeSync } from 'node:fs';

const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index];
  const value = process.argv[index + 1];
  if (!name?.startsWith('--') || value === undefined || values.has(name)) process.exit(64);
  values.set(name, value);
}
const root = values.get('--broker-root');
const state = values.get('--agent-state');
const brokerPid = values.get('--broker-pid');
if (!root?.startsWith('/') || !state?.startsWith(`${root}/`) || !/^[1-9]\d*$/.test(brokerPid ?? '')) {
  process.exit(64);
}

function denied(operation, label) {
  try {
    operation();
  } catch (error) {
    if (error?.code === 'EACCES' || error?.code === 'EPERM') return;
    throw new Error(`${label} failed with an unexpected error class`);
  }
  throw new Error(`${label} unexpectedly succeeded`);
}

denied(() => readdirSync(root), 'foreign Node broker-root enumeration');
denied(() => readFileSync(`${root}/master.key`), 'foreign Node master-key read');
denied(() => readdirSync(state), 'foreign Node Agent-state enumeration');
denied(() => readFileSync(`/proc/${brokerPid}/environ`), 'foreign Node broker environment read');
denied(() => {
  const descriptor = openSync(`/proc/${brokerPid}/mem`, 'r');
  closeSync(descriptor);
}, 'foreign Node broker memory read');

process.stdout.write('foreign-node-storage-and-process-read=denied\n');
