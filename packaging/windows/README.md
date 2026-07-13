# Windows signed runtime packaging

The public npm packages contain only an Authenticode-signed `palladin-client.exe`. They have no lifecycle scripts and cannot install, update, or remove the privileged runtime. The client activates only the fixed `palladin-runtime-companion.exe` alias; that package is explicitly AppContainer and has no `runFullTrust` capability. The separately installed MSIX broker runs as `LocalService` with the stable restricted service SID `NT SERVICE\PalladinRuntime`.

Secure mode must fail closed when the broker is missing, unsigned, modified, below the configured security floor, or registered under a different account/SID type. npm removal never deletes identities. Downgrades are forbidden: a rollback ships the previous source as a new, higher version above the security floor.

The Windows Secure threat boundary covers unprivileged processes in the interactive user's session, including arbitrary Node applications. Local administrators, SYSTEM, kernel compromise, and a compromised Palladin signing identity are outside this boundary and require separate operating-system and release-security controls.

The `packagedServices` restricted capability requires Microsoft approval for Store distribution. Until that approval exists, the owner-signed packages are intended for controlled sideloading/enterprise deployment. This is a release prerequisite, not a condition that may trigger a weaker fallback.

Release order:

1. Build native x64 and arm64 client, broker, worker, and companion executables on matching hardware.
2. Sign and RFC3161-timestamp every PE file.
3. Build the broker (service + worker) and companion MSIX packages, combine x64/arm64 into `.msixbundle` files, then sign/timestamp them.
4. Stage the exact Windows npm package from the signed client.
5. Build and sign the self-contained one-UAC bootstrapper. It embeds both verified MSIX packages and its in-memory installation payload, then stages packages under `Program Files` to prevent same-user TOCTOU replacement.
6. Run `Verify-Release.ps1`, rollback policy tests, install/update tests, and hostile same-user boundary tests on clean VMs.
7. Publish only from the protected owner-dispatched environment.

The protected `windows-signing` environment must define `PALLADIN_WINDOWS_PUBLISHER`, `PALLADIN_WINDOWS_COMPANION_PFN`, `PALLADIN_WINDOWS_SIGNER_THUMBPRINT`, and `PALLADIN_WINDOWS_TIMESTAMP_URL`, plus the signing-certificate secrets. The workflow derives the PFN again from the package name and publisher and refuses to build when it differs from the protected value.

The organization API key remains one organization credential that multiple Agent profiles may reference. Each Agent retains its own `agentId`, X25519 keypair, and Ed25519 keypair inside the broker-owned identity boundary.
