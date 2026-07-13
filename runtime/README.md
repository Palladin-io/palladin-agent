# Palladin native runtime

The Rust runtime is the client-side security boundary for Agent identities. It does not change the backend authentication protocol.

## Identity ownership

- The API key belongs to an organization. Multiple Agent profiles may reference the same organization credential.
- Every Agent has a separate stable identity ID and separate X25519 and Ed25519 keys.
- Profile names are aliases. Renaming an alias never renames or copies a secret slot.
- Public files contain only the host, opaque credential references, Agent ID, public keys, signatures, and integrity commitments.
- A cross-process transaction lock serializes recovery, keychain mutation, and public commits for all profiles.
- The secure store holds a small registry trust root. Registry and config digests plus an Agent Ed25519 binding signature are verified before any private identity or organization credential is read.

## Secret input and storage

`palladin connect` reads the organization API key from a masked prompt. Automation must use a protected pipe:

```sh
secret-provider | palladin --id build connect --api-key-stdin
```

API keys are rejected in command-line arguments and environment variables. Convenience builds use the operating-system credential store. Windows Secure runs only behind the authenticated AppContainer/LocalService broker and stores DPAPI-protected blobs under a restricted service-SID ACL. There is no fallback to a plaintext file or environment variable.

The standalone native build reports this as the Convenience tier. Login Keychain, Windows Credential Manager, and Linux Secret Service protect data at rest but do not provide a universal boundary against every process running as the same OS user or UID.

The `macos-hardened` build is a separate, fail-closed delivery tier. It is compiled with one fixed Keychain access group, placed in a provisioned and signed `PalladinRuntime.app`, and uses only the Data Protection Keychain. All items are non-synchronizable and `WhenUnlockedThisDeviceOnly`; the shared organization credential additionally requires user presence. Missing entitlements or authorization are errors. There is no fallback to Login Keychain, a file, an environment variable, or the Convenience store.

The organization API key remains organization-wide in both tiers. User presence gates use of that shared credential; it does not turn it into a per-Agent key. X25519 and Ed25519 slots remain distinct for each Agent identity.

`PALLADIN_HOME` is rejected by identity-opening commands. Tests inject an explicit temporary `ProfileRepository` instead of redirecting production state with an environment variable.

## Removal

`palladin purge --confirm` explicitly schedules recoverable removal of native profiles and their known secret slots. A public integrity journal is inert by itself: its exact digest must be pinned in the secure trust state before it can authorize idempotent cleanup. The operation only reports success after the authenticated transition, trust root, journal, and public profile root are gone. It is never invoked by an npm lifecycle hook.

Pre-production schema v2 state is migrated only by `palladin security upgrade`. The migration derives and verifies public keys from legacy private identities, accepts only the origin policy compiled into the binary, writes signed schema v3 configs, rotates every secret into a versioned v3 slot behind an authenticated recovery plan, commits the transition, and then removes legacy slots. Release builds accept only `https://api.palladin.io`; literal loopback HTTP requires the explicit `local-development` source-build feature. Restoring v2 public files after the upgrade cannot recover the deleted legacy slots.

## Credential execution

Native `exec` starts programs without an implicit shell, rebuilds the child environment from a positive allowlist, supplies null stdin, contains the process tree, and never passes the organization API key or Agent identity keys to the child. MCP discards command output and returns only the exit status. CLI may stream output directly to the operator's terminal.

Script entries resolve an allowlisted interpreter and all credential references before starting. Temporary script files use a private directory and explicit cleanup on every handled completion, error, and cancellation path.

These controls are defense in depth inside the selected platform tier. The precise residual risks and the separate cross-platform boundary requirements are recorded in [ADR 0002](docs/adr/0002-exec-process-boundary.md).

## Browser injection

Browser injection is currently unavailable on macOS, Windows, and Linux for Chrome, Edge, Brave, Chromium, Firefox, and Safari. The CLI fails before opening an Agent profile. MCP may already have an Agent session open in order to serve other tools, but `inject_credential` never contacts a browser endpoint, requests a credential, or decrypts one.

Caller-provided CDP endpoints are never contacted. CDP cannot attest the browser or page origin: a fake endpoint can report an allowed URL and then receive the plaintext fill operation. The decision, support matrix, and requirements for a future authenticated browser component are recorded in [ADR 0003](docs/adr/0003-browser-injection-boundary.md).
