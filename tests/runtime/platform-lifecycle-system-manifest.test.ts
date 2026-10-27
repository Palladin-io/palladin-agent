import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

function loadPhase(contract: unknown, target: unknown, phase: string) {
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    import { readFileSync } from 'node:fs';
    const { loadPhase } = await import(process.argv[1]);
    const { contract, target, phase } = JSON.parse(readFileSync(0, 'utf8'));
    try { process.stdout.write(JSON.stringify(loadPhase(contract, target, phase))); }
    catch (error) { process.stderr.write(error.message); process.exitCode = 1; }
  `, pathToFileURL(resolve('security/lifecycle/run-physical-target.mjs')).href], {
    input: JSON.stringify({ contract, target, phase }), encoding: 'utf8', timeout: 10000,
  });
  if (result.status !== 0) throw new Error(result.stderr || 'physical loader failed');
  return JSON.parse(result.stdout) as { artifacts: Array<{ role: string; filename: string; sha256: string }> };
}

const sourceSha = 'a'.repeat(40);
const version = '0.0.11';

describe('physical lifecycle system manifest loading', () => {
  it('loads the DEB from its separate source-bound manifest and rejects tampering', () => {
    const directory = mkdtempSync(join(tmpdir(), 'palladin-system-manifest-'));
    try {
      const file = (filename: string) => {
        writeFileSync(join(directory, filename), filename);
        return { filename, sha256: createHash('sha256').update(filename).digest('hex') };
      };
      const manifest = (name: string, artifacts: ReturnType<typeof file>[], sha = sourceSha) =>
        writeFileSync(join(directory, name), JSON.stringify({ version, sourceSha: sha, artifacts }));
      manifest('release-manifest.json', [file(`palladin-runtime-linux-x64-gnu-${version}.tgz`)]);
      manifest('release-manifest-agent.json', [file(`palladin-cli-${version}.tgz`)]);
      const deb = file(`palladin-runtime_${version}-1_amd64.deb`);
      const systemName = 'release-manifest-linux-system-x64.json';
      manifest(systemName, [deb]);
      const contract = { phases: { candidate: { version, sourceSha, directory } } };
      const target = { os: 'linux', arch: 'x64', distribution: 'ubuntu-24.04', libc: 'gnu' };
      expect(loadPhase(contract, target, 'candidate').artifacts.find((item: { role: string }) => item.role === 'deb'))
        .toMatchObject({ filename: deb.filename, sha256: deb.sha256 });
      manifest(systemName, [deb], 'b'.repeat(40));
      expect(() => loadPhase(contract, target, 'candidate')).toThrow('manifest binding is invalid');
      manifest(systemName, [deb]);
      writeFileSync(join(directory, deb.filename), 'modified');
      expect(() => loadPhase(contract, target, 'candidate')).toThrow('artifact digest is invalid');
      rmSync(join(directory, systemName));
      expect(() => loadPhase(contract, target, 'candidate')).toThrow();
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
});
