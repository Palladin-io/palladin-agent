import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const nodeProbePath = 'packaging/windows/tests/foreign-node-boundary-probe.mjs';
const read = (path: string): string => readFileSync(path, 'utf8').replace(/\r\n/g, '\n');

describe('Windows signed-runtime adversarial boundary', () => {
  it('classifies access denial separately from missing and unavailable resources', () => {
    const classify = (code: string): string => {
      const result = spawnSync(process.execPath, [nodeProbePath, '--classify-boundary-error', code], {
        encoding: 'utf8',
        shell: false,
      });
      expect(result.status).toBe(0);
      expect(result.stderr).toBe('');
      return result.stdout.trim();
    };

    expect(classify('EACCES')).toBe('access-denied');
    expect(classify('EPERM')).toBe('access-denied');
    expect(classify('ENOENT')).toBe('missing');
    expect(classify('EBUSY')).toBe('unavailable');
  });

  it('keeps hosted limitations distinct from dedicated process evidence', () => {
    const workflow = read('.github/workflows/windows-signed-runtime.yml');
    const nodeProbe = read(nodeProbePath);
    const nativeProbe = read('packaging/windows/tests/Palladin.AdversarialProbe/Program.cs');
    const documentation = read('packaging/windows/tests/README.md');
    const ignore = read('.gitignore');

    expect(workflow).toContain(nodeProbePath);
    expect(workflow).toContain('Palladin.AdversarialProbe.csproj');
    expect(workflow).toContain("--target \"service:$($service.ProcessId)\"");
    expect(workflow).toContain('windows-2025');
    expect(workflow).toContain('windows-11-arm');
    expect(workflow).toContain('evidence-status: incomplete-hosted-boundaries');
    expect(workflow).toContain('evidence-status: incomplete-hosted-(elevated|partial)');
    expect(workflow).toContain('$profilePresence');
    expect(workflow).toContain('remain mandatory');

    expect(nodeProbe).toContain('maximumCaptureBytes');
    expect(nodeProbe).toContain("['hosted', 'dedicated-hardware']");
    expect(nodeProbe).toContain("['present', 'missing']");
    expect(nodeProbe).toContain('trusted preflight-confirmed real profile');
    expect(nodeProbe).toContain('did not receive ACCESS_DENIED');
    expect(nodeProbe).toContain('named-pipe-missing');
    expect(nodeProbe).toContain('programdata-profile-missing');
    expect(nodeProbe).toContain('dedicated-hardware-attacker-token-not-exercised');
    expect(nodeProbe).toContain('shell: false');
    expect(nodeProbe).toContain("['init']");
    expect(nodeProbe).toContain('Windows Hello is unavailable or consent was not granted');
    expect(nodeProbe).toContain(String.raw`\\.\pipe\LOCAL\Palladin.Runtime.v1`);
    expect(nodeProbe).toContain('prepareWindowsRuntimeCache');

    expect(nativeProbe).toContain('QueryFullProcessImageName(');
    expect(nativeProbe).toContain('AssertExpectedPackagedImage(');
    expect(nativeProbe).toContain('AssertExpectedToken(');
    expect(nativeProbe).toContain('AssertStillActive(');
    expect(nativeProbe).toContain('RequireAccessDenied(');
    expect(nativeProbe).toContain('ErrorAccessDenied = 5');
    expect(nativeProbe).toContain('evidence-status: incomplete-hosted-elevated');
    expect(nativeProbe).toContain('evidence-status: complete-dedicated-hardware');
    expect(nativeProbe).toContain('public-client: VM_READ handle obtainable');
    expect(nativeProbe).not.toContain('ReadProcessMemory(');
    expect(nativeProbe).not.toContain('MiniDumpWriteDump(');
    expect(nativeProbe).not.toContain('FileOptions.DeleteOnClose');

    expect(documentation).toContain('dedicated physical Windows 11 x64 and ARM64 devices');
    expect(documentation).toContain('manual release-report cells remain mandatory');
    expect(documentation).toContain('No probe seeds an identity');
    expect(documentation).toContain('never claimed by hosted');
    expect(ignore).toContain('packaging/windows/tests/**/bin/');
    expect(ignore).toContain('packaging/windows/tests/**/obj/');
  });
});
