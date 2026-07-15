# macOS release boundary

The release workflow builds native arm64 and x86_64 slices, combines them into one universal executable, embeds it in `PalladinRuntime.app`, signs it with Developer ID, submits it to Apple notarization, staples the ticket, and packs the verified app into the platform npm package.

The protected GitHub environment is `macos-signing`. Configure these non-secret variables:

- `PALLADIN_MACOS_APPLICATION_IDENTIFIER` - exact `TEAMID.io.palladin.runtime`
- `PALLADIN_MACOS_KEYCHAIN_ACCESS_GROUP` - the same exact value

Configure these environment secrets:

- `APPLE_DEVELOPER_ID_CERTIFICATE_BASE64`
- `APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD`
- `APPLE_DEVELOPER_ID_APPLICATION_IDENTITY`
- `APPLE_DEVELOPER_ID_PROVISIONING_PROFILE_BASE64`
- `APPLE_NOTARYTOOL_KEY_BASE64`
- `APPLE_NOTARYTOOL_KEY_ID`
- `APPLE_NOTARYTOOL_ISSUER_ID`

Only `patryk-roguszewski` can dispatch `.github/workflows/macos-signed-runtime.yml`. The workflow checks out an explicit 40-character commit SHA and never publishes to npm. It produces short-lived, verified tarballs for the later atomic release task.

`test-security-boundary.sh` runs only with `PALLADIN_SECURITY_TEST_CONFIRM=ephemeral-runner`. It proves that Homebrew Node, an unentitled Data Protection Keychain query, an unsigned clone, a modified app, and a differently signed fork cannot open the synthetic identity. It also proves same-Team update compatibility and profile rename/delete behavior. Neither negative probe creates a Login Keychain item, and the Security.framework probe disables authentication UI.

Lock, sleep, and logout need a physical interactive Mac. Run `test-session-transitions.sh` only from a dedicated OS test account with `PALLADIN_SESSION_TEST_CONFIRM=dedicated-test-account`. The `lock` and `sleep` modes schedule a noninteractive read while the session is unavailable and verify access after unlock. Run `logout-prepare`, log out normally, sign in, and then run `logout-verify`.
