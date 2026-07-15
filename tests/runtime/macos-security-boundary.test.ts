import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string): string => readFileSync(path, 'utf8').replace(/\r\n/g, '\n');

describe('macOS authenticated signed-runtime boundary', () => {
  it('cannot bypass the exact signed boundary in the release pipeline', () => {
    const workflow = read('.github/workflows/macos-signed-runtime.yml');
    const signedJob = workflow.split('\n  smoke-signed:\n')[1]?.split('\n  macos-signed-gate:\n')[0];
    expect(signedJob).toBeDefined();
    expect(workflow).toContain("if: github.actor == 'patryk-roguszewski'");
    expect(workflow).not.toContain('pull_request:');
    expect(workflow).not.toContain('if: inputs.release_pipeline != true');
    expect(workflow).not.toContain("if [[ '${{ inputs.release_pipeline }}' != true ]]");
    expect(signedJob).toContain('runner: macos-15\n');
    expect(signedJob).toContain('architecture: arm64');
    expect(signedJob).toContain('runner: macos-15-intel');
    expect(signedJob).toContain('architecture: x86_64');
    expect(signedJob).toContain('palladin-runtime-darwin-${{ matrix.npm_architecture }}-*.tgz');
    expect(signedJob).toContain('npm install --prefix "$smoke" --ignore-scripts --no-save');
    expect(signedJob).toContain('test-security-boundary.sh');
    expect(signedJob).toContain("--architecture '${{ matrix.architecture }}'");
    expect(workflow.match(/test-security-boundary\.sh/g)).toHaveLength(1);
    expect(workflow).toContain('needs: [authorize, build-native, sign-universal, smoke-signed]');
    expect(workflow).toContain('SIGNED_BOUNDARY: ${{ needs.smoke-signed.result }}');
    expect(workflow).toContain('test "$SIGNED_BOUNDARY" = success');
  });

  it('keeps packaging probes in lockstep with the Rust session-v2 storage contract', () => {
    const helpers = read('packaging/macos/scripts/lib.sh');
    const harness = read('packaging/macos/scripts/test-security-boundary.sh');
    const store = read('runtime/crates/palladin-platform/src/macos_hardened_store.rs');
    const slots = read('runtime/crates/palladin-platform/src/secure_store.rs');
    const contract = {
      identityService: 'io.palladin.runtime.session-v2.identity',
      stateService: 'io.palladin.runtime.session-v2.state',
      accessGroupSuffix: '.io.palladin.runtime.session-v2',
      organization: 'organization-api-key-v3',
      x25519: 'x25519-private-key-v3',
      ed25519: 'ed25519-secret-key-v3',
      invocation: 'invocation-authorization-seed-v2',
    };

    for (const value of Object.values(contract)) expect(helpers).toContain(`"${value}"`);
    expect(store).toContain(`const IDENTITY_SERVICE_V2: &str = "${contract.identityService}";`);
    expect(store).toContain(`const STATE_SERVICE_V2: &str = "${contract.stateService}";`);
    expect(store).toContain(`const ACCESS_GROUP_SUFFIX: &str = "${contract.accessGroupSuffix}";`);
    for (const value of [contract.organization, contract.x25519, contract.ed25519, contract.invocation]) {
      expect(slots).toContain(`"${value}"`);
      expect(harness).not.toContain(value);
    }
    expect(harness).not.toContain(contract.identityService);
    expect(harness).not.toContain(contract.stateService);
    expect(harness).toContain('$PALLADIN_IDENTITY_KEYCHAIN_SERVICE');
    expect(harness).toContain('$PALLADIN_INVOCATION_SLOT_SUFFIX');
    expect(helpers).toContain('assert_binary_session_contract()');
    expect(read('packaging/macos/scripts/build-bundle.sh')).toContain('assert_binary_session_contract "$binary"');
    expect(read('packaging/macos/scripts/verify-bundle.sh')).toContain('assert_binary_session_contract "$binary"');
  });

  it('runs bounded blind-client and local process attack probes without printing captures', () => {
    const harness = read('packaging/macos/scripts/test-security-boundary.sh');
    const client = read('packaging/macos/tests/signed-client-probe.mjs');
    for (const evidence of [
      'PalladinCopied.app',
      'palladin-unsigned',
      'PalladinFork.app',
      'PalladinModified.app',
      'DYLD_INSERT_LIBRARIES',
      'task-port-probe',
      'lldb --batch --attach-pid',
      'process save-core',
    ]) expect(harness, evidence).toContain(evidence);
    expect(client).toContain("shell: false");
    expect(client).toContain("child.kill('SIGKILL')");
    expect(client).toContain("child.kill('SIGINT')");
    expect(client).toContain('maximumCaptureBytes');
    expect(client).toContain('private boundary canary');
    expect(client).toContain("['get', vault, entry");
    expect(client).toContain("['connect', '--api-key-stdin']");
    expect(client).toContain("['mcp', 'serve']");
    expect(client).toContain('mcp-first-connection');
    expect(client).toContain('mcp-second-connection');
    expect(client).toContain('`${initialize}\\n${toolCall}\\n${toolCall}\\n`');
    expect(harness).not.toContain('cat "$work_dir');
    expect(harness).not.toContain('set -x');
  });

  it('binds operations to semantic arguments, process, connection, sequence, epoch, and expiry', () => {
    const runtime = read('runtime/crates/palladin-runtime/src/lib.rs');
    const platform = read('runtime/crates/palladin-platform/src/secure_store.rs');
    for (const marker of [
      'OPERATION_BINDING_DOMAIN',
      'OPERATION_TTL_MS',
      'request_digest',
      'connection_nonce',
      'sequence',
      'lifecycle_epoch',
      'process_id',
      'not_after_unix_ms',
      'GetCredential {',
      'ExecWithCredential {',
      'InvocationSurface::Mcp',
      'CredentialOutputPolicy::McpSecretResponse',
    ]) expect(runtime, marker).toContain(marker);
    expect(runtime.match(/\.authorize_operation\(/g)?.length ?? 0).toBeGreaterThanOrEqual(2);
    expect(runtime.match(/\.get_authorized\(/g)?.length ?? 0).toBeGreaterThanOrEqual(3);
    expect(platform).toContain('pub struct OperationAuthorization');
    expect(platform).not.toContain('impl Clone for OperationAuthorization');
    const mcp = read('runtime/crates/palladin-mcp/src/lib.rs');
    expect(mcp).toContain('notifications/cancelled');
    expect(mcp).toContain('cancellation.cancel()');
  });

  it('allows exactly the four required entitlements and documents hardware-only evidence', () => {
    const template = read('packaging/macos/PalladinRuntime.entitlements.in');
    const helpers = read('packaging/macos/scripts/lib.sh');
    const session = read('packaging/macos/scripts/test-session-transitions.sh');
    const documentation = read('packaging/macos/README.md');
    const keys = [...template.matchAll(/<key>([^<]+)<\/key>/g)].map((match) => match[1]);
    expect(keys).toEqual([
      'com.apple.application-identifier',
      'com.apple.developer.team-identifier',
      'keychain-access-groups',
      'com.apple.security.get-task-allow',
    ]);
    expect(helpers).toContain('assert_exact_entitlement_allowlist()');
    for (const forbidden of [
      'com.apple.security.cs.disable-library-validation',
      'com.apple.security.cs.allow-dyld-environment-variables',
      'com.apple.security.cs.disable-executable-page-protection',
      'com.apple.security.cs.allow-unsigned-executable-memory',
    ]) expect(template).not.toContain(forbidden);
    expect(session).toContain('"dedicated-test-account"');
    expect(session).toContain('--id PROFILE');
    expect(session).toContain('hardware-only acceptance hook, not hosted CI evidence');
    expect(documentation).toContain('cannot be honestly automated on GitHub-hosted runners');
    expect(documentation).toContain('ordinary release gate does not claim them');
  });
});
