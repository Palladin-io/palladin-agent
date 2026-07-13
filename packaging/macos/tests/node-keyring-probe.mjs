import { Entry } from '@napi-rs/keyring';

const [service, account] = process.argv.slice(2);
if (!service || !account) {
  process.stderr.write('usage: node-keyring-probe.mjs SERVICE ACCOUNT\n');
  process.exit(64);
}

try {
  const value = new Entry(service, account).getPassword();
  if (value !== null && value !== undefined) {
    process.stderr.write('untrusted Node process unexpectedly read a native identity slot\n');
    process.exit(1);
  }
} catch {
  // A storage error is also a valid fail-closed outcome for this untrusted process.
}

process.stdout.write('Homebrew Node could not read the native identity slot.\n');
