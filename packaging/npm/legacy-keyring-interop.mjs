import { Entry } from '@napi-rs/keyring';

const services = ['palladin', 'claw-vault'];
const suffixes = ['private-key', 'signing-key'];
const [operation, profile] = process.argv.slice(2);

if (!['seed', 'assert-missing', 'cleanup'].includes(operation)
  || !profile
  || profile.length > 64
  || !/^[A-Za-z0-9_-]+$/.test(profile)) {
  process.stderr.write('usage: node legacy-keyring-interop.mjs seed|assert-missing|cleanup PROFILE\n');
  process.exit(64);
}

const entries = services.flatMap((service) => suffixes.map((suffix) => ({
  entry: new Entry(service, `${profile}:${suffix}`),
  service,
  suffix,
})));

if (operation === 'seed') {
  for (const { entry, service, suffix } of entries) {
    const synthetic = `cvt332-synthetic-${service}-${suffix}`;
    entry.setPassword(synthetic);
    if (entry.getPassword() !== synthetic) {
      throw new Error('the synthetic legacy credential was not persisted');
    }
  }
  process.stdout.write(`seeded ${entries.length} synthetic legacy credential references\n`);
} else if (operation === 'assert-missing') {
  for (const { entry } of entries) {
    if (entry.getPassword() !== null) {
      throw new Error('a synthetic legacy credential still exists');
    }
  }
  process.stdout.write(`verified deletion of ${entries.length} legacy credential references\n`);
} else {
  for (const { entry } of entries) {
    try {
      entry.deletePassword();
    } catch {
      // Best-effort cleanup is used only by CI traps after a failed interop assertion.
    }
  }
}
