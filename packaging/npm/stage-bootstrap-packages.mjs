#!/usr/bin/env node
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PUBLIC_PACKAGE_NAMES, fail, parseArguments } from './release-policy.mjs';

const BOOTSTRAP_VERSION = '0.0.0-bootstrap';

function directoryName(packageName) {
  return packageName.slice('@palladin/'.length);
}

try {
  const values = parseArguments(process.argv.slice(2), ['output-dir']);
  const output = resolve(values.get('output-dir'));
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  const legalFiles = ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md'];
  try {
    mkdirSync(output, { mode: 0o755 });
  } catch {
    fail('output directory must not already exist and its parent must exist');
  }
  for (const name of PUBLIC_PACKAGE_NAMES) {
    const packageDirectory = join(output, directoryName(name));
    mkdirSync(packageDirectory, { mode: 0o755 });
    const manifest = {
      name,
      version: BOOTSTRAP_VERSION,
      description: 'Inert bootstrap package for Palladin trusted publishing setup',
      license: 'Apache-2.0',
      repository: { type: 'git', url: 'git+https://github.com/Palladin-io/palladin-agent.git' },
      files: legalFiles,
      publishConfig: { access: 'public', provenance: true },
    };
    writeFileSync(join(packageDirectory, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
    for (const file of legalFiles) copyFileSync(join(root, file), join(packageDirectory, file));
  }
} catch (error) {
  process.stderr.write(`Error: ${error instanceof Error ? error.message : 'unknown bootstrap staging failure'}\n`);
  process.exitCode = 1;
}
