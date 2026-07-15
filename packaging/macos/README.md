# macOS release boundary

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

`test-security-boundary.sh` runs only with `PALLADIN_SECURITY_TEST_CONFIRM=ephemeral-runner`. The owner-only signed workflow installs the exact arm64 and x64 npm tarballs natively and runs the same noninteractive harness on both. It probes the authenticated-session v2 Data Protection Keychain namespace with Homebrew Node and unentitled Security.framework, blindly spawns the genuine and copied signed clients, exercises CLI/MCP cancellation and a second connection, and rejects unsigned, modified, ad-hoc, DYLD-injected, task-port and debugger/core access. Captured child output stays in a private temporary directory and is deleted rather than uploaded. Neither negative storage probe creates a Login Keychain item, and Security.framework authentication UI is disabled. Single-use replay is enforced by native runtime tests; a positive LocalAuthentication replay check remains part of the physical-Mac procedure because a hosted runner cannot honestly approve the first request.

Fresh approval and lock, sleep, and logout transitions cannot be honestly automated on GitHub-hosted runners. Before accepting a release boundary, run `test-session-transitions.sh` on dedicated interactive arm64 and Intel Macs with `PALLADIN_SESSION_TEST_CONFIRM=dedicated-test-account` and a connected synthetic profile. The operator must confirm that the fixed prompt names the intended status operation, cancel once to prove fail-closed behavior, then approve. In MCP, approve one synthetic tool call and repeat the exact call; the second call must display a fresh prompt, proving the first approval was not replayed. The `lock` and `sleep` modes verify denial while the session is unavailable and require a new approval after unlock. For logout, run `logout-prepare`, log out normally, sign in, then run `logout-verify` with the same exact signed app and profile. Finally run `palladin purge --confirm` and remove the synthetic staging Agent. These are explicit hardware-only acceptance results; the ordinary release gate does not claim them.
