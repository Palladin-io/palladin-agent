import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

function read(path: string): string {
  return readFileSync(path, 'utf8');
}

describe('Linux hardened package boundary', () => {
  it('stages the Linux npm package from the repository template', () => {
    const temporary = mkdtempSync(join(tmpdir(), 'palladin-linux-stage-'));
    try {
      const binaries = join(temporary, 'bin');
      const output = join(temporary, 'out');
      mkdirSync(binaries);
      for (const name of ['palladin-linux-client', 'palladin-worker']) {
        const path = join(binaries, name);
        writeFileSync(path, '#!/bin/sh\nexit 0\n');
        chmodSync(path, 0o755);
      }
      execFileSync('bash', [
        'packaging/linux/scripts/stage-npm-platform-package.sh',
        '--architecture', 'arm64',
        '--binaries', binaries,
        '--output', output,
      ]);
      const manifest = JSON.parse(readFileSync(join(output, 'package.json'), 'utf8')) as {
        name: string;
        libc: string[];
      };
      expect(manifest.name).toBe('@palladin/runtime-linux-arm64-gnu');
      expect(manifest.libc).toEqual(['glibc']);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });

  it('runs the secret-bearing broker under a dedicated non-root UID', () => {
    const unit = read('packaging/linux/systemd/palladin-runtime.service');
    expect(unit).toContain('User=palladin-runtime');
    expect(unit).toContain('Group=palladin-runtime');
    expect(unit).toContain('SupplementaryGroups=palladin-executor');
    expect(unit).toContain('NoNewPrivileges=yes');
    expect(unit).toContain('ProtectProc=invisible');
    expect(unit).toContain('CapabilityBoundingSet=\n');
    expect(unit).toContain('LimitCORE=0');
    expect(unit).toContain('UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT');
    expect(unit).not.toContain('User=root');
  });

  it('uses a root-owned socket and a fresh executor UID for each credential execution', () => {
    const socket = read('packaging/linux/systemd/palladin-executor.socket');
    const executor = read('packaging/linux/systemd/palladin-executor@.service');
    expect(socket).toContain('SocketUser=root');
    expect(socket).toContain('SocketGroup=palladin-executor');
    expect(socket).toContain('SocketMode=0660');
    expect(socket).toContain('Accept=yes');
    expect(executor).toContain('DynamicUser=yes');
    expect(executor).toContain('User=plx-%i');
    expect(executor).toContain('StandardInput=socket');
    expect(executor).toContain('StandardOutput=socket');
    expect(executor).toContain('ProtectProc=invisible');
    expect(executor).not.toContain('User=palladin-runtime');

    const sysusers = read('packaging/linux/sysusers.d/palladin-runtime.conf');
    expect(sysusers).toContain('g palladin-executor -');
    expect(sysusers).not.toContain('m palladin-runtime palladin-executor');
  });

  it('authenticates the broker UID again at the executor socket boundary', () => {
    const executor = read('runtime/crates/palladin-linux-executor/src/bin/executor.rs');
    const marker = read('packaging/linux/scripts/configure-package.sh');
    const hardened = read('packaging/linux/tests/test-hardened-boundary.sh');
    expect(executor).toContain('sockopt::PeerCredentials');
    expect(executor).toContain('authorize_broker_uid(credentials.uid(), expected_uid)');
    expect(marker).toContain('executor_gid=%s');
    expect(hardened).toContain('executor-peer=root-rejected-by-so-peercred');
    expect(hardened).toContain('executor-peer=broker-uid-accepted');
  });

  it('authenticates the kernel UID and a root-owned one-profile mapping', () => {
    const peer = read('runtime/crates/palladin-linux-broker/src/peer.rs');
    const service = read('runtime/crates/palladin-linux-broker/src/bin/service.rs');
    expect(peer).toContain('stream.peer_cred()');
    expect(peer).toContain('/etc/palladin/agents.d');
    expect(peer).toContain('metadata.uid() != 0');
    expect(peer).toContain('metadata.nlink() != 1');
    expect(peer).toContain('principal_id');
    expect(peer).toContain('status == "revoked"');
    expect(peer).toContain('state_root.join("agents")');
    expect(service).toContain('arguments.insert(0, peer.profile)');
    expect(service).toContain('arguments.insert(0, "--id".to_owned())');
    expect(service).not.toContain('get_api_key');
    expect(service).not.toContain('read_private_key');
  });

  it('keeps privileged installation explicit and outside npm', () => {
    const root = JSON.parse(read('package.json')) as { scripts?: Record<string, string> };
    for (const lifecycle of ['preinstall', 'install', 'postinstall', 'prepare']) {
      expect(root.scripts?.[lifecycle]).toBeUndefined();
    }
    const policy = read('packaging/linux/polkit/io.palladin.runtime.policy');
    expect(policy).toContain('io.palladin.runtime.manage-agent-uid');
    expect(policy).toContain('/usr/lib/palladin/runtime/palladin-manage-agent-uid');
    expect(policy).toContain('<allow_inactive>no</allow_inactive>');
    expect(policy).toContain('<allow_active>auth_admin</allow_active>');
    expect(policy).not.toContain('auth_admin_keep');
    const helper = read('packaging/linux/scripts/manage-agent-uid.sh');
    expect(helper).toContain('/etc/palladin/agents.d/$uid');
    expect(helper).not.toContain('master.key');
    expect(helper).not.toContain('palladin-linux-service');
    expect(helper).toContain('status=revoked');
    expect(helper).toContain('--dedicated');
    expect(helper).toContain('the Agent account password must be locked');
    const authorize = helper.slice(helper.indexOf('  authorize)\n'), helper.indexOf('  revoke)\n'));
    expect(authorize.indexOf('restart_broker')).toBeLessThan(
      authorize.indexOf('mv -T "$temporary" "$mapping"'),
    );
  });

  it('builds and tests glibc packages on native x64 and arm64 Linux runners', () => {
    const workflow = read('.github/workflows/rust-runtime.yml');
    expect(workflow).toContain('runner: ubuntu-24.04\n            gnu_target: x86_64-unknown-linux-gnu');
    expect(workflow).toContain('runner: ubuntu-24.04-arm\n            gnu_target: aarch64-unknown-linux-gnu');
    expect(workflow).toContain('packaging/linux/deb/build-deb.sh');
    expect(workflow).toContain('packaging/linux/rpm/build-rpm.sh');
    expect(workflow).toContain('test-hardened-boundary.sh');
    expect(workflow).toContain('test-package-family.sh debian');
    expect(workflow).toContain('test-package-family.sh fedora');
    expect(workflow).toContain('--example package_state_fixture');
    expect(workflow).toContain('Install, upgrade, roll back, and reinstall');
    expect(workflow).toContain('kernel.yama.ptrace_scope=0');

    const lifecycle = read('packaging/linux/tests/test-package-family.sh');
    const fixture = read(
      'runtime/crates/palladin-linux-broker/examples/package_state_fixture.rs',
    );
    expect(lifecycle).toContain('/state-fixture seed');
    expect(lifecycle).toContain('/state-fixture verify');
    expect(fixture).toContain('SecretSlot::OrganizationApiKey');
    expect(fixture).not.toContain('env::var');
  });

  it('tests same-UID, ptrace, process_vm_readv, proc, loader, and peer rejection', () => {
    const convenience = read('packaging/linux/tests/test-convenience-boundary.sh');
    const hardened = read('packaging/linux/tests/test-hardened-boundary.sh');
    const probe = read('packaging/linux/tests/security-boundary-probe.c');
    expect(convenience).toContain('same-uid-file-read=success');
    expect(convenience).toContain('LD_PRELOAD=');
    expect(hardened).toContain('unauthorized-peer');
    expect(hardened).toContain('ld-preload=removed-before-broker-start');
    expect(probe).toContain('PTRACE_ATTACH');
    expect(probe).toContain('process_vm_readv');
    expect(probe).toContain('/proc/%ld/%s');
  });
});
