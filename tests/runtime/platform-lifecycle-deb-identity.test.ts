import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';

it.each([
  ['0.0.11-1\tamd64\tii ', 'x64', true],
  ['0.0.11-1\tarm64\tii ', 'arm64', true],
  ['0.0.11\tamd64\tii ', 'x64', false],
  ['0.0.11-2\tamd64\tii ', 'x64', false],
  ['0.0.11-1\tarm64\tii ', 'x64', false],
  ['0.0.11-1\tamd64\tiU ', 'x64', false],
])('validates installed DEB identity %s for %s', (stdout, arch, accepted) => {
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    import { readFileSync } from 'node:fs';
    const { assertInstalledDebIdentity } = await import(process.argv[1]);
    const input = JSON.parse(readFileSync(0, 'utf8'));
    assertInstalledDebIdentity(input, '0.0.11', input.arch);
  `, pathToFileURL(resolve('security/lifecycle/run-physical-target.mjs')).href], {
    input: JSON.stringify({ stdout, stderr: '', arch }), encoding: 'utf8', timeout: 10000,
  });
  expect(result.status === 0).toBe(accepted);
});
