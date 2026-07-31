#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const args = process.argv.slice(2);
const check = args.length === 1 && args[0] === '--check';
if (args.length > 0 && !check) throw new Error('usage: generate-oss-metadata.mjs [--check]');

const manifest = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const cargo = JSON.parse(execFileSync('cargo', [
  'metadata', '--manifest-path', resolve(root, 'runtime/Cargo.toml'), '--locked',
  '--format-version', '1',
], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }));

const externalPackages = cargo.packages
  .filter((pkg) => pkg.source !== null)
  .sort((left, right) => `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`));
for (const pkg of externalPackages) {
  if (typeof pkg.license !== 'string' || pkg.license.length === 0) {
    throw new Error(`third-party package has no declared license: ${pkg.name}@${pkg.version}`);
  }
}

const licenseGroups = new Map();
for (const pkg of externalPackages) {
  const group = licenseGroups.get(pkg.license) ?? [];
  group.push(pkg);
  licenseGroups.set(pkg.license, group);
}

const notice = [
  '# Third-Party Notices',
  '',
  'Palladin Agent includes the Rust dependencies listed below. This inventory is',
  'generated from the locked Cargo dependency graph. Package names, versions,',
  'declared SPDX license expressions, and upstream project links are provided for',
  'attribution and license-compliance review.',
  '',
  'The applicable license texts and copyright notices remain those supplied by',
  'each upstream project. SPDX license texts are available at',
  'https://spdx.org/licenses/. Release workflows also generate and attest an',
  'artifact-specific SPDX SBOM for every published native package.',
  '',
];
for (const [license, packages] of [...licenseGroups].sort(([left], [right]) => left.localeCompare(right))) {
  notice.push(`## ${license}`, '');
  for (const pkg of packages) {
    const url = pkg.repository ?? pkg.homepage ?? `https://crates.io/crates/${pkg.name}`;
    notice.push(`- [${pkg.name} ${pkg.version}](${url})`);
  }
  notice.push('');
}

function cargoComponent(pkg) {
  const purl = `pkg:cargo/${encodeURIComponent(pkg.name)}@${pkg.version}`;
  const component = { 'bom-ref': purl, type: 'library', name: pkg.name, version: pkg.version, purl };
  if (pkg.license) component.licenses = [{ expression: pkg.license }];
  if (pkg.checksum) component.hashes = [{ alg: 'SHA-256', content: pkg.checksum }];
  const references = [];
  if (pkg.repository) references.push({ type: 'vcs', url: pkg.repository });
  if (pkg.homepage) references.push({ type: 'website', url: pkg.homepage });
  if (references.length > 0) component.externalReferences = references;
  if (pkg.source) component.properties = [{ name: 'palladin:cargo-source', value: pkg.source }];
  return component;
}

const platformComponents = Object.keys(manifest.optionalDependencies).sort().map((dependency) => {
  const version = manifest.optionalDependencies[dependency];
  const purl = `pkg:npm/${encodeURIComponent(dependency)}@${version}`;
  return {
    'bom-ref': purl,
    type: 'application',
    name: dependency,
    version,
    purl,
    licenses: [{ license: { id: 'Apache-2.0' } }],
  };
});

const sbom = {
  '$schema': 'https://cyclonedx.org/schema/bom-1.6.schema.json',
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  version: 1,
  metadata: {
    lifecycles: [{ phase: 'pre-build' }],
    component: {
      'bom-ref': `pkg:npm/%40palladin/agent@${manifest.version}`,
      type: 'application',
      group: '@palladin',
      name: 'agent',
      version: manifest.version,
      purl: `pkg:npm/%40palladin/agent@${manifest.version}`,
      licenses: [{ license: { id: 'Apache-2.0' } }],
    },
    properties: [{
      name: 'palladin:inventory-scope',
      value: 'All-target locked source inventory; release artifacts receive separate attested SPDX SBOMs.',
    }],
  },
  components: [...cargo.packages.map(cargoComponent), ...platformComponents]
    .sort((left, right) => left['bom-ref'].localeCompare(right['bom-ref'])),
};

const outputs = new Map([
  [resolve(root, 'THIRD_PARTY_NOTICES.md'), notice.join('\n')],
  [resolve(root, 'SBOM.cdx.json'), `${JSON.stringify(sbom, null, 2)}\n`],
]);
for (const [path, expected] of outputs) {
  if (check) {
    if (readFileSync(path, 'utf8') !== expected) {
      throw new Error(`${path} is stale; run npm run oss:generate`);
    }
  } else {
    writeFileSync(path, expected, { mode: 0o644 });
  }
}
