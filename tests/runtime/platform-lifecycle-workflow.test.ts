import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const workflow = readFileSync('.github/workflows/platform-lifecycle.yml', 'utf8');
const runner = readFileSync('security/lifecycle/run-physical-target.mjs', 'utf8');
const release = readFileSync('.github/workflows/release-meta.yml', 'utf8');

describe('owner-only physical lifecycle workflow', () => {
  it('has one manual owner-only entry point and twelve fixed native targets', () => {
    expect(workflow).toContain("if: github.actor == 'patryk-roguszewski'");
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
    expect(workflow).toContain('name: physical-release-sets-${{ inputs.candidate_source_sha }}');
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
    expect(runner).toContain('npm uninstall left the Agent launcher installed');
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
