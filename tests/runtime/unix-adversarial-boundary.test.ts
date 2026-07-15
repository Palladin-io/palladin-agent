import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const read = (path: string): string => readFileSync(path, 'utf8').replace(/\r\n/g, '\n');

describe('macOS adversarial boundary wiring', () => {
  it('scans stdin canaries without placing them in probe arguments or output', () => {
    const script = read('packaging/macos/scripts/test-security-boundary.sh');
    const processProbe = read('packaging/macos/tests/process-arguments-probe.c');
    const signedClientProbe = read('packaging/macos/tests/signed-client-probe.mjs');
    const workflow = read('.github/workflows/rust-runtime.yml');

    expect(script).toContain('process-arguments-probe.c');
    expect(script).toContain('printf \'%s\' "$process_canary" | "$process_arguments_probe" "$target_pid"');
    expect(script).toContain('canary-tree-probe.mjs');
    expect(processProbe).toContain('read(STDIN_FILENO, canary');
    expect(processProbe).toContain('KERN_PROCARGS2');
    expect(processProbe).not.toContain('printf("%s", canary');
    expect(signedClientProbe).toContain('maximumScannedFileBytes');
    expect(signedClientProbe).toContain('persisted the private boundary canary');
    expect(workflow).toContain('process-arguments-probe.c');
  });

  it.runIf(process.platform !== 'win32')('bounded tree scanner rejects a symlink root and never echoes the canary', () => {
    const parent = mkdtempSync(join(tmpdir(), 'palladin-canary-tree-'));
    const root = join(parent, 'state');
    const link = join(parent, 'state-link');
    const canary = `palladin-stdin-${'b'.repeat(64)}`;
    try {
      writeFileSync(root, 'public-only', { mode: 0o600 });
      const safe = execFileSync(process.execPath, [
        'packaging/macos/tests/canary-tree-probe.mjs',
        root,
      ], { input: canary, encoding: 'utf8' });
      expect(safe).toContain('stdin-canary-absent');

      symlinkSync(root, link);
      let output = '';
      try {
        execFileSync(process.execPath, [
          'packaging/macos/tests/canary-tree-probe.mjs',
          link,
        ], { input: canary, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (error) {
        const failure = error as { stdout?: string; stderr?: string };
        output = `${failure.stdout ?? ''}${failure.stderr ?? ''}`;
      }
      expect(output).toContain('rejected a symbolic link');
      expect(output).not.toContain(canary);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });
});

describe('Linux adversarial boundary wiring', () => {
  it('tests the exact launcher and two foreign-Node principals', () => {
    const convenience = read('packaging/linux/tests/test-convenience-boundary.sh');
    const hardened = read('packaging/linux/tests/test-hardened-boundary.sh');
    const foreignNode = read('packaging/linux/tests/foreign-node-probe.mjs');
    const processScan = read('packaging/linux/tests/process-scan-probe.mjs');
    const workflow = read('.github/workflows/rust-runtime.yml');

    expect(convenience).toContain('node "$launcher" doctor');
    expect(convenience).toContain('[[ -f $root/node.hit ]]');
    expect(convenience).toContain('[[ -f $root/client.hit ]]');
    expect(convenience).toContain('[[ ! -e $root/worker.hit ]]');
    expect(hardened).toContain('for user in "$agent" "$attacker"; do');
    expect(hardened).toContain('foreign-node-probe.mjs');
    expect(hardened).toContain('process-scan-probe.mjs');
    expect(hardened).toContain('--tree \\');
    expect(foreignNode).toContain('/master.key');
    expect(foreignNode).toContain('/environ');
    expect(foreignNode).toContain('/mem');
    expect(processScan).toContain('canary.fill(0)');
    expect(workflow).toContain('--launcher-root "$RUNNER_TEMP/alpine-launcher"');
  });

  it.runIf(process.platform === 'linux')('detects a live environment disclosure and never echoes the canary', () => {
    const root = mkdtempSync(join(tmpdir(), 'palladin-process-scan-'));
    const canary = `palladin-stdin-${'a'.repeat(64)}`;
    writeFileSync(join(root, 'public.txt'), 'public-only', { mode: 0o600 });
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
      env: { ...process.env, PALLADIN_SYNTHETIC_CANARY: canary },
      stdio: 'ignore',
    });
    try {
      expect(child.pid).toBeTypeOf('number');
      let output = '';
      try {
        execFileSync(process.execPath, [
          'packaging/linux/tests/process-scan-probe.mjs',
          '--process',
          String(child.pid),
          process.execPath,
        ], { input: canary, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (error) {
        const failure = error as { stdout?: string; stderr?: string };
        output = `${failure.stdout ?? ''}${failure.stderr ?? ''}`;
      }
      expect(output).toContain('client environment contained the stdin canary');
      expect(output).not.toContain(canary);
    } finally {
      child.kill('SIGKILL');
      rmSync(root, { recursive: true, force: true });
    }
  });
});
