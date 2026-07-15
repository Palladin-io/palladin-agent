# Windows signed runtime packaging

The public npm packages contain only an Authenticode-signed `palladin-client.exe`. They have no lifecycle scripts and cannot install, update, or remove the privileged runtime. The client activates only the fixed `palladin-runtime-companion.exe` alias; that package is explicitly AppContainer and has no `runFullTrust` capability. The separately installed MSIX broker runs as `LocalService` with the stable restricted service SID `NT SERVICE\PalladinRuntime`.

Hardened mode must fail closed when the broker is missing, unsigned, modified, below the configured security floor, or registered under a different account/SID type. npm removal never deletes identities. Downgrades are forbidden: a rollback ships the previous source as a new, higher version above the security floor.

The Node dispatcher never executes the npm copy of `palladin-client.exe` for an identity-bearing command. It checks the package version and SHA-256 against signed release policy, verifies the pinned Authenticode publisher, thumbprint, and timestamp, then atomically copies the public client into `%LOCALAPPDATA%\Palladin\RuntimeCache\v1` under its exact version and hash. Immediately before spawn, a trusted system PowerShell process opens the cached file with sharing limited to read, hashes that open handle, repeats Authenticode verification, starts the exact path without a shell, and keeps the handle until the child exits. A child-PID lease retains an active version while npm installs N+1; later launches select N+1 and garbage collection removes only entries without a live lease or Windows image lock. Uninstall leaves this public cache and every native identity untouched.

LocalAppData is writable by the interactive user, so this cache is not a security boundary. It contains no API key, Agent key, profile, or credential. Signed policy binds the public client hash and the separately packaged worker hash; Authenticode and the MSIX identity bind their publisher and protected installation origin. The worker verifies its own policy hash before opening identity, while the packaged companion and broker remain the authoritative Hardened boundary. Any cache verification failure is terminal; there is no direct-package, PATH, download, or unsigned fallback for an identity-bearing command.

The Windows Hardened threat boundary covers unprivileged processes in the interactive user's session, including arbitrary Node applications. Local administrators, SYSTEM, kernel compromise, and a compromised Palladin signing identity are outside this boundary and require separate operating-system and release-security controls.

The initial Windows Hello signature for `mcp serve` authorizes only creation of the bounded transport. It never authorizes later Agent operations. Every `search_entries`, `get_credential`, `exec_with_credential`, and `report_credential_stale` message is held inside the LocalService broker until a new Windows Hello signature is verified. The signature is single-use and binds the exact message bytes, selected profile, tool, batch position, broker-generated connection nonce, Windows logon session, lifecycle epoch, and monotonic sequence. Unknown MCP methods and tools fail closed. The companion sends one complete message at a time and waits for the broker acknowledgement, so queued stdin cannot race ahead of a pending consent challenge.

Before each signature, the packaged companion opens the native Windows user-consent dialog with a fixed operation label and a sanitized profile hint. Control characters and bidi markers are removed, and long profile hints use prefix-and-suffix shortening. The signed challenge remains the broker-verifiable proof; text received from Node is never rendered directly in the trusted prompt.

Lock, logoff, console or remote disconnect, session termination, suspend, and resume revoke the in-memory lifecycle epoch and kill active workers. A service restart discards every pending nonce. No MCP consent is cached, exported to Node, or reusable across another message, profile, connection, Windows session, or service lifetime.

The `packagedServices` restricted capability requires Microsoft approval for Store distribution. Until that approval exists, the owner-signed packages are intended for controlled sideloading/enterprise deployment. This is a release prerequisite, not a condition that may trigger a weaker fallback.

Release order:

1. Build native x64 and arm64 client, broker, worker, executor, and companion executables on matching hardware.
2. Sign and RFC3161-timestamp every PE file.
3. Build the broker (service + worker + one-shot AppContainer executor) and companion MSIX packages, combine x64/arm64 into `.msixbundle` files, then sign/timestamp them.
4. Stage the exact Windows npm package from the signed client.
5. Build and sign the self-contained one-UAC bootstrapper. It embeds both verified MSIX packages and its in-memory installation payload, then stages packages under `Program Files` to prevent same-user TOCTOU replacement.
6. Run `Verify-Release.ps1`, rollback policy tests, install/update tests, and hostile same-user boundary tests on clean VMs.
7. Publish only from the protected owner-dispatched environment.

The protected `windows-signing` environment must define `PALLADIN_WINDOWS_PUBLISHER`, `PALLADIN_WINDOWS_COMPANION_PFN`, `PALLADIN_WINDOWS_SIGNER_THUMBPRINT`, and `PALLADIN_WINDOWS_TIMESTAMP_URL`, plus the signing-certificate secrets. The workflow derives the PFN again from the package name and publisher and refuses to build when it differs from the protected value.

The organization API key remains one organization credential that multiple Agent profiles may reference. Each Agent retains its own `agentId`, X25519 keypair, and Ed25519 keypair inside the broker-owned identity boundary.

The executor is activated only by the trusted worker from the immutable package directory. It receives one scoped credential over bounded stdin, never receives the organization API key or Agent private keys, and launches the selected executable in a fixed AppContainer. The AppContainer receives null stdin, executor-owned output pipes only, and a kill-on-close Job Object. There is no second Windows service or extra installation step.
