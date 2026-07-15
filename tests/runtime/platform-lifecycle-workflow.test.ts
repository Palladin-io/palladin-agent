import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const workflow = readFileSync('.github/workflows/platform-lifecycle.yml', 'utf8');
const runner = readFileSync('security/lifecycle/run-physical-target.mjs', 'utf8');
const release = readFileSync('.github/workflows/release-meta.yml', 'utf8');

describe('owner-only physical lifecycle workflow', () => {
  it('has one manual owner-only entry point and twelve fixed native targets', () => {
    expect(workflow).toContain("if: github.actor == 'patryk-roguszewski'");
    expect(workflow).toContain("github.ref == 'refs/heads/main'");
    expect(workflow).toContain('ref: ${{ github.sha }}');
    expect(workflow).toContain("test \"$GITHUB_REF\" = refs/heads/main");
    expect(workflow).toContain('test "$CANDIDATE_SHA" = "$GITHUB_SHA"');
    expect(workflow).toContain('test "$(git rev-parse "$tag^{commit}")" = "$source"');
    expect(workflow).not.toContain("with: { ref: '${{ inputs.candidate_source_sha }}'");
    expect(workflow).not.toContain("with: { ref: '${{ needs.authorize.outputs.source_sha }}'");
    expect(workflow).toContain('test "$GITHUB_EVENT_NAME" = workflow_dispatch');
    expect(workflow).not.toMatch(/^\s{2}(push|pull_request|schedule|workflow_run):/m);
    expect(workflow.match(/- target: macos-/g)).toHaveLength(2);
    expect(workflow.match(/- target: windows-/g)).toHaveLength(2);
    expect(workflow.match(/- \{ target: (?:ubuntu|debian|fedora|alpine)-/g)).toHaveLength(8);
    expect(workflow).toContain('environment: lifecycle-qa');
    expect(workflow).toContain('Require native interactive macOS hardware');
    expect(workflow).toContain('Require native interactive Windows 11 hardware');
    expect(workflow).toContain('Require exact native Linux VM');
  });

  it('streams the organization QA key through inherited stdin and aggregates exactly twelve shards', () => {
    expect(workflow).toContain("gcloud secrets versions access latest --secret='");
    expect(workflow).toContain('| node security/lifecycle/run-physical-target.mjs');
    expect(workflow).toContain("--vault-id '${{ vars.PALLADIN_LIFECYCLE_QA_VAULT_ID }}'");
    expect(workflow).toContain("--entry-id '${{ vars.PALLADIN_LIFECYCLE_QA_ENTRY_ID }}'");
    expect(workflow).not.toMatch(/PALLADIN_(?:API_KEY|LIFECYCLE_QA_SECRET):\s*\$\{\{\s*secrets\./);
    expect(workflow).toContain("= 12");
    expect(workflow).toContain('name: physical-release-sets-${{ steps.verify.outputs.source_sha }}');
    expect(workflow).toContain("name: 'physical-release-sets-${{ needs.authorize.outputs.source_sha }}'");
    expect(workflow).not.toContain('name: lifecycle-release-sets-${{ inputs.candidate_source_sha }}');
    expect(workflow).toContain("pattern: 'lifecycle-*'");
    expect(workflow).toContain('aggregate-shards.mjs');
    expect(workflow).toContain('report.mjs generate');
    expect(workflow).toContain('gh release upload');
  });

  it('binds real identity/grant continuity, repair, downgrade rejection, and purge without secret argv or env', () => {
    expect(runner).toContain("['connect', '--api-key-stdin', '--host', contract.apiHost]");
    expect(runner).toContain("stdio: ['inherit', 'pipe', 'pipe']");
    expect(runner).toContain('assertNoApiKeyEmission([connect.stdout, connect.stderr]');
    expect(runner).toContain("join(home, '.palladin', 'registry.json')");
    expect(runner).toContain("operation: 'exec_with_credential'");
    expect(runner).toContain("body.output !== 'withheld'");
    expect(runner).toContain('concurrent MCP grant binding changed');
    expect(runner).toContain('npm reinstall did not repair the missing runtime');
    expect(runner).toContain('literal downgrade did not produce the exact signed-policy rejection');
    expect(runner).toContain("rejected.stderr !== 'Error: Palladin native runtime version is blocked by signed version policy\\n'");
    expect(runner).toContain("rollbackMode: 'forward-rebuild'");
    expect(runner).toContain("['purge', '--confirm']");
    expect(runner).toContain("purgeStdout !== 'Native Palladin profiles and secret slots purged.\\n'");
    expect(runner).toContain("existsSync(join(home, '.palladin'))");
    expect(runner).not.toContain('if (purged.status === 0)');
    expect(runner).toContain('npm uninstall left the Agent launcher installed');
    expect(runner).toContain("repositoryScript('packaging/macos/scripts/verify-bundle.sh'), '--app', app, '--architecture', 'universal'");
    expect(runner).toContain('verifyMacBundle(packagedApp, phase, env)');
    expect(runner).toContain("bounded('/usr/bin/ditto'");
    expect(runner).toContain("bounded('/bin/bash'");
    expect(runner).not.toContain('/usr/local/bin');
    expect(runner).toContain('const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));');
    expect(runner).toContain("mkdtempSync(join(SCRIPT_DIRECTORY, '.palladin-physical-'))");
    expect(runner).not.toContain('dirname(resolve(contract.output))');
    expect(runner).toContain('dirname(outputPath) !== dirname(contractPath)');
    expect(runner).toContain('basename(outputPath) !== `lifecycle-${contract.targetId}.json`');
    expect(runner).toContain("return join(dirname(process.execPath), process.platform === 'win32' ? 'npm.cmd' : 'npm');");
    expect(runner).not.toContain("function npmExecutable() { return process.platform === 'win32' ? 'npm.cmd' : 'npm'; }");
    expect(runner).toContain("version.stdout.trim() !== '11.18.0'");
    expect(runner).toContain('npm package runtime does not match the verified signed macOS runtime');
    expect(runner).toContain("Remove-AppxPackage -AllUsers -Package $package.PackageFullName");
    expect(runner).toContain("['--non-interactive', 'apt-get', 'purge', '--yes', 'palladin-runtime']");
    expect(runner).toContain("['--non-interactive', 'dnf', 'remove', '--assumeyes', 'palladin-runtime']");
    expect(runner).toContain("Get-AppxPackage -AllUsers -PackageTypeFilter Main -Name $name");
    expect(runner.indexOf('Palladin.Runtime.Companion')).toBeLessThan(runner.indexOf('Palladin.Runtime.Broker'));
    expect(runner).toContain(String.raw`Get-CimInstance Win32_Service -Filter \"Name='PalladinRuntime'\"`);
    expect(runner).toContain("['--show', 'palladin-runtime']");
    expect(runner).toContain("['--query', '--quiet', 'palladin-runtime']");
    expect(runner).toContain("result.stdout.trim() !== 'not-found'");
    expect(runner).toContain("'/run/palladin-runtime/broker.sock'");
    expect(runner).toContain('uninstallNativeExtra(target, rollback, env)');
    expect(runner.indexOf('uninstallNativeExtra(target, rollback, env)'))
      .toBeLessThan(runner.indexOf("run.steps.push(step(run, 'uninstall'"));
    expect(runner).toContain('shellCompatibilityCheck(prefix, env, baseline.version)');
    expect(runner).not.toMatch(/readFileSync\(0\)|secretBundle|environment\.apiKey|env\.apiKey|--api-key',/);
  });

  it('keeps package-mode tests and both owner-approved reports in the release gate', () => {
    expect(release).toContain('- run: npm test');
    expect(release).toContain('node security/adversarial/operator-approval.mjs verify');
    expect(release).toContain('node security/lifecycle/operator-approval.mjs verify');
    expect(release).toContain('needs: [authorize, prepare-meta, publish-policy, approve-adversarial, approve-lifecycle]');
  });
});
