# macOS development and release boundary

## Local source development

Source builds use the Login Keychain Convenience tier. A normal Rust debug build
is linker-signed ad hoc, so its Designated Requirement is a changing `CDHash`.
macOS consequently asks again before a rebuilt binary may read an existing
Palladin Keychain item.

Use the development runtime script instead of executing `target/debug/palladin`
directly:

```bash
./packaging/macos/scripts/development-runtime.sh bootstrap
./packaging/macos/scripts/development-runtime.sh run -- doctor
./packaging/macos/scripts/development-runtime.sh install-launcher ~/.local/bin/palladin
```

For an HTTP loopback API, enable only the reviewed source-development feature
through the same signed route:

```bash
./packaging/macos/scripts/development-runtime.sh run --local-development -- connect --host http://127.0.0.1:5000
# Or after install-launcher:
palladin --local-development connect --host http://127.0.0.1:5000
```

The flag must appear before the `--` separator (or first in the installed
launcher). Arbitrary Cargo features and arguments are not accepted.

The bootstrap is offline and idempotent. It creates a self-signed,
code-signing-only certificate named `Palladin Local Development` in a dedicated
per-user Keychain. macOS may ask for one approval when that certificate is first
trusted for code signing. The private key is non-extractable, and its ACL admits
`/usr/bin/codesign`; it is not shared with release workflows. The Keychain has
an empty password so a local build can unlock it after login or restart without
operator presence. This does not expand Palladin's security claim: source builds
still trust the complete same-user domain and report
`Convenience - macOS Login Keychain`.

The signed debug executable has the fixed identifier
`io.palladin.runtime.development`, no Team ID, no entitlements and no Hardened
Runtime flag. Current macOS releases still partition Login Keychain access for a
non-Apple development signer by `CDHash`, even when its Designated Requirement
is stable. Therefore the changing CLI executable never reads Login Keychain
items directly. The first signed build installs
`~/.palladin/development/palladin-keychain-helper-v1`, an owner-only (`0500`)
helper that is deliberately not replaced by later CLI builds. Only this stable
helper touches the fixed `io.palladin.agent` service. Its bounded binary protocol
accepts only known secret slots and opaque owners; secret bytes travel through
anonymous pipes, never argv, environment variables, files or logs.

After upgrading an existing development installation, bind its current Palladin
items to the helper once:

```bash
./packaging/macos/scripts/development-runtime.sh build --local-development
./packaging/macos/scripts/development-runtime.sh migrate-keychain-access
```

The migration installs the pinned stable helper when absent, refuses to replace
a different helper implementation under the same version, and enumerates only
account metadata for the exact legacy Palladin service. macOS can show one
dialog per existing item. After the operator approves each one-time read, the
helper copies
the value in memory to its versioned `io.palladin.agent.development-helper-v1`
service and immediately drops the in-memory secret. A separate noninteractive
helper process verifies every migrated copy. The original items remain untouched
as rollback state. The migration never prints or passes secret values through
arguments, environment variables or files.

New items are created by that same stable helper, and updates preserve their
ACL. Normal rebuilds and different worktrees never replace the installed helper,
so they do not need renewed access. A later helper implementation change must
bump both the helper filename and its versioned Keychain service before another
explicit migration; replacing a released helper in place would invalidate its
saved `CDHash` access.

`install-launcher` refuses to overwrite an existing file unless `--force` is
provided. `reset --confirm` refuses to proceed while the versioned helper owns
any Login Keychain items, because removing that exact binary would orphan their
ACL. After local Agent state is explicitly purged, reset removes only the
dedicated development certificate, trust setting, signing Keychain and matching
local helper. Never replace this mechanism with an identifier-only ad hoc
requirement, a wildcard Keychain ACL or a path that moves secret values through
process arguments.

## Release boundary

The release workflow builds native arm64 and x86_64 slices, combines them into one universal executable, embeds it in `PalladinRuntime.app`, signs it with Developer ID, submits it to Apple notarization, staples the ticket, and packs the verified app into the platform npm package.

The protected GitHub environment is `macos-signing`. Configure these non-secret variables:

- `PALLADIN_MACOS_APPLICATION_IDENTIFIER` - exact `TEAMID.io.palladin.runtime`
- `PALLADIN_MACOS_KEYCHAIN_ACCESS_GROUP` - exact `TEAMID.io.palladin.runtime.session-v2` using the same Team ID

Configure these environment secrets:

- `APPLE_DEVELOPER_ID_CERTIFICATE_BASE64`
- `APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD`
- `APPLE_DEVELOPER_ID_APPLICATION_IDENTITY`
- `APPLE_DEVELOPER_ID_PROVISIONING_PROFILE_BASE64`
- `APPLE_NOTARYTOOL_KEY_BASE64`
- `APPLE_NOTARYTOOL_KEY_ID`
- `APPLE_NOTARYTOOL_ISSUER_ID`

Only `patryk-roguszewski` can dispatch `.github/workflows/macos-signed-runtime.yml`. The workflow checks out an explicit 40-character commit SHA and never publishes to npm. It produces short-lived, verified tarballs for the later atomic release task.

`test-security-boundary.sh` runs only when the workflow supplies `PALLADIN_RUNNER_ENVIRONMENT=github-hosted` and `PALLADIN_SECURITY_TEST_CONFIRM=github-hosted-ephemeral-runner`. It refuses an account with existing Palladin state. The owner-only signed workflow installs the exact arm64 and x64 npm tarballs natively and runs the same noninteractive harness on fresh GitHub-hosted VMs. It probes the authenticated-session v2 Data Protection Keychain namespace with Homebrew Node and unentitled Security.framework, blindly spawns the genuine and copied signed clients, exercises CLI/MCP cancellation and a second connection, and rejects unsigned, modified, ad-hoc, DYLD-injected, task-port and debugger/core access. Captured child output stays in a private temporary directory and is deleted rather than uploaded. Neither negative storage probe creates a Login Keychain item, and Security.framework authentication UI is disabled. The synthetic Data Protection Keychain state cannot be purged headlessly because purge itself requires LocalAuthentication; it exists only in the disposable VM and is destroyed with that entire GitHub-hosted VM after the job. The harness does not claim in-process cleanup. Single-use replay is enforced by native runtime tests; a positive LocalAuthentication replay check remains part of the physical-Mac procedure because a hosted runner cannot honestly approve the first request.

Fresh approval and lock, sleep, and logout transitions cannot be honestly automated on GitHub-hosted runners. Before accepting a release boundary, run `test-session-transitions.sh` on dedicated interactive arm64 and Intel Macs with `PALLADIN_SESSION_TEST_CONFIRM=dedicated-test-account` and a connected synthetic profile. The operator must confirm that the fixed prompt names the intended status operation, cancel once to prove fail-closed behavior, then approve. In MCP, approve one synthetic tool call and repeat the exact call; the second call must display a fresh prompt, proving the first approval was not replayed. The `lock` and `sleep` modes verify denial while the session is unavailable and require a new approval after unlock. For logout, run `logout-prepare`, log out normally, sign in, then run `logout-verify` with the same exact signed app and profile. Finally run `palladin purge --confirm` and remove the synthetic staging Agent. These are explicit hardware-only acceptance results; the ordinary release gate does not claim them.
