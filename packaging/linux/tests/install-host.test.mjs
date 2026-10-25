import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import test from 'node:test';

const installer = resolve('packaging/linux/scripts/install-hardened.sh');
function check(...args) {
  return spawnSync('bash', ['-c', 'source "$1"; shift; supported_platform "$@"', '_', installer, ...args], { encoding: 'utf8' });
}
for (const [os, version, format] of [['ubuntu', '24.04', 'deb'], ['debian', '13', 'deb'], ['fedora', '44', 'rpm'], ['rocky', '9.6', 'rpm']]) {
  for (const architecture of ['x86_64', 'aarch64']) {
    test(`accepts ${os} ${version} on ${architecture} with systemd`, () => {
      const result = check(os, version, '252', architecture, 'systemd', 'none');
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout.trim(), format);
    });
  }
}
for (const args of [
  ['alpine', '3.22', '252', 'x86_64', 'openrc', 'none'],
  ['ubuntu', '22.04', '249', 'x86_64', 'systemd', 'none'],
  ['ubuntu', '24.04', '251', 'x86_64', 'systemd', 'none'],
  ['ubuntu', '24.04', '252', 'armv7l', 'systemd', 'none'],
  ['ubuntu', '24.04', '252', 'x86_64', 'bash', 'none'],
  ['ubuntu', '24.04', '252', 'x86_64', 'systemd', 'docker'],
]) {
  test(`rejects unsupported host ${args.join('/')}`, () => assert.notEqual(check(...args).status, 0));
}
