import { readFileSync } from 'node:fs';

const [metadata, source, repository] = process.argv.slice(2);
try {
  if (process.argv.length !== 5 || !/^[0-9a-f]{40}$/.test(source) || !repository) {
    throw new Error('Invalid expected QA build authority');
  }
  const run = JSON.parse(readFileSync(metadata, 'utf8'));
  if (run.conclusion !== 'success'
    || run.event !== 'workflow_dispatch'
    || run.path !== '.github/workflows/rust-runtime.yml'
    || run.head_sha !== source
    || run.repository?.full_name !== repository
    || run.head_repository?.full_name !== repository) {
    throw new Error('QA package must come from the expected successful first-party Rust build');
  }
} catch {
  process.stderr.write('QA build source verification failed; package installation refused\n');
  process.exitCode = 1;
}
