# Palladin native runtime

The Rust runtime is the client-side security boundary for Agent identities. It does not change the backend authentication protocol.

## Vault protocol 2 crypto boundary

Vault protocol 2 parsing and cryptographic operations live in the native
`palladin-crypto` crate. The crate rejects unknown protocol/suite values and
stale revision, key-version, or Member-generation checkpoints before opening a
payload. It constructs the registered binary AAD internally, derives projection
keys with HKDF-SHA-256, opens XChaCha20-Poly1305 and libsodium sealed-box
payloads, and verifies domain-separated Ed25519 signatures.

Secret outputs use redacted, zeroizing buffers. The public Node launcher neither
imports this crate nor receives its keys or plaintext. Canonical fixtures are
vendored under `runtime/contracts/vault-v2/fixtures/v2` from a pinned Palladin
root-repository commit; tests verify the fixture manifest and every file digest
before exercising all positive and corruption vectors.

### Agent Discovery authorization snapshots

The native runtime accepts Vault manifests only from the strict
`{ agentAccessEpoch, items }` response. The non-zero epoch must match every
integrity-bound local Vault anchor before any item is applied. It validates the
complete canonical-descriptor manifest/envelope batch, including first-use
public Vault trust anchors, in memory; only a fully valid batch can produce one
signed atomic profile update. Discovery pages are decrypted into a cloned local
index and replace the live index only after every Vault finishes and the anchor
batch is durably committed.

Snapshot or delta `409 { "outcome": "sync-state-changed" }` responses discard
the complete working attempt. The runtime repeats the operation from a fresh
manifest authorization read at most three times with bounded linear backoff.
Other conflicts are not retried, retry exhaustion fails closed, and response
bodies, ciphertext, credentials, and private identity material are never added
to errors or diagnostics. Inject obtains its authenticated URL and field
metadata through the same atomic Discovery synchronization path.

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

API keys are rejected in command-line arguments and environment variables. Convenience builds use the operating-system credential store. Windows Hardened runs only behind the authenticated AppContainer/LocalService broker and stores DPAPI-protected blobs under a restricted service-SID ACL. Linux Hardened runs only for a root-authorized dedicated Agent UID, stores authenticated ciphertext under a separate broker UID, and uses a one-shot systemd `DynamicUser` executor. There is no fallback to a plaintext file or environment variable.

The standalone native build reports this as the Convenience tier. Login Keychain, Windows Credential Manager, and Linux Secret Service protect data at rest but do not provide a universal boundary against every process running as the same OS user or UID.

The `macos-hardened` build is a separate, fail-closed delivery tier. It is compiled with one fixed Keychain access group, placed in a provisioned and signed `PalladinRuntime.app`, and uses only the Data Protection Keychain. All items are non-synchronizable and `WhenUnlockedThisDeviceOnly`; the shared organization credential additionally requires user presence. Missing entitlements or authorization are errors. There is no fallback to Login Keychain, a file, an environment variable, or the Convenience store.

The organization API key remains organization-wide in both tiers. User presence gates use of that shared credential; it does not turn it into a per-Agent key. X25519 and Ed25519 slots remain distinct for each Agent identity.

On Linux, PolKit is limited to one-shot authorization of changes to the root-owned dedicated-principal record. Interactive npm use remains Convenience. The record binds a locked nologin account and UID to a random non-reusable principal namespace, fixed profile, and root-approved origin; revoke leaves a fail-closed tombstone. A dedicated Agent UID is the complete workload trust domain, and an incomplete Hardened installation returns an error instead of opening Secret Service. The broker and one-shot executor run under distinct UIDs and communicate through a broker-only socket with peer-UID verification, so credential-bearing target processes cannot read broker state or memory through same-UID `/proc`, `ptrace`, or `process_vm_readv` access.

Linux musl x64/arm64 is a separate static Convenience build and is exercised on Alpine 3.22 without glibc compatibility libraries. Alpine/OpenRC Hardened is explicitly unsupported in the MVP and no APK is published. Secret-bearing operations require a compatible Secret Service; absence of D-Bus or that service is an error without a file or environment fallback.

`PALLADIN_HOME` is rejected by identity-opening commands. Tests inject an explicit temporary `ProfileRepository` instead of redirecting production state with an environment variable.

## Removal

`palladin purge --confirm` explicitly schedules recoverable removal of native profiles and their known secret slots. A public integrity journal is inert by itself: its exact digest must be pinned in the secure trust state before it can authorize idempotent cleanup. The operation only reports success after the authenticated transition, trust root, journal, and public profile root are gone. It is never invoked by an npm lifecycle hook.

Pre-production schema v2 state is migrated only by `palladin security upgrade`. The migration derives and verifies public keys from legacy private identities, accepts only the origin policy compiled into the binary, writes signed schema v3 configs, rotates every secret into a versioned v3 slot behind an authenticated recovery plan, commits the transition, and then removes legacy slots. Release builds accept only the exact production and staging origins; literal loopback HTTP requires the explicit `local-development` source-build feature. Restoring v2 public files after the upgrade cannot recover the deleted legacy slots.

The older TypeScript client uses a separate destructive workflow and is never handled by `security upgrade`. `palladin security legacy-cutover --confirm-pre-production-reset` is a dev-only command that reads only registry and filesystem metadata, freezes `.palladin` or `.claw-vault` behind a same-filesystem rename, and generates fresh X25519/Ed25519 identities with preplanned opaque IDs. It never opens TypeScript `config.json`, old key files, old OS credential values, or legacy environment-variable values. Re-running the command completes any missing native profile without replacing an already committed fresh identity.

After the operator supplies a new organization API key through the existing masked prompt or `--api-key-stdin`, the current backend protocol creates a new pending Agent for each fresh profile. Multiple Agents may intentionally share that one organization key. `palladin security legacy-cleanup <cutoverId> --confirm` remains blocked until every planned profile has a newly returned backend `agentId`. Cleanup uses a delete-only adapter for the exact historical `palladin` and `claw-vault` service/account names, then removes only preflighted legacy files. Missing items are idempotent; unknown files, links, or a deletion error preserve the archive for retry. No npm lifecycle hook runs cutover or cleanup.

The operator must then revoke the old shared organization API key and deactivate the old backend Agents in the existing panel. Local cleanup cannot revoke remote state, erase backups or SSD snapshots, or unset variables in a parent shell. Windows/Linux Hardened workloads refuse this user-root workflow; perform the pre-production cutover before hardened broker enrollment.

Linux package lifecycle tests preserve and reopen the encrypted Agent identity and organization API-key slots across upgrade, rollback, uninstall, and reinstall. Test credentials are synthetic, compiled into a test-only fixture, and are never passed through argv, environment variables, or logs.

## Credential execution

Native `exec` starts programs without an implicit shell, rebuilds the child environment from a positive allowlist, supplies null stdin, contains the process tree, and never passes the organization API key or Agent identity keys to the child. MCP discards command output and returns only the exit status. CLI may stream output directly to the operator's terminal.

Script entries resolve an allowlisted interpreter and all credential references before starting. Temporary script files use a private directory and explicit cleanup on every handled completion, error, and cancellation path.

These controls are defense in depth inside the selected platform tier. The precise residual risks and the separate cross-platform boundary requirements are recorded in [ADR 0002](docs/adr/0002-exec-process-boundary.md).

## Browser injection

The provider-neutral form and origin-validation contract is implemented. The macOS Rust runtime now
has a code-enabled, one-shot Chrome Native Messaging route with explicit out-of-band key pinning, a
signed ephemeral extension session, mutually authenticated local CLI-to-host IPC, lifecycle
revocation, and directional XChaCha20-Poly1305 frames. It accepts only the compiled Chromium origin
and the exact schemas in [`contracts/inject-provider/v1`](contracts/inject-provider/v1/README.md).
The legacy Node extension socket remains unshipped and is never a fallback.

This code-enabled branch is not by itself a production acceptance claim. Release readiness remains
blocked until the exact signed/notarized packaged binary passes a real Chrome Native Messaging E2E
with the paired extension, including wrong-pin, revocation, expiry, and disconnect negatives. Source
and synthetic process tests do not replace that browser gate. Platforms without a completed native
host adapter fail closed before profile, grant, or credential access.

AgentBrowser Inject remains unavailable in every build because version 0.33.2 cannot atomically bind
secret text insertion to the attested element; its MCP package returns before grant, runtime, or
secret-bearing daemon access. AgentBrowser support requires both an upstream session-owned
authenticated channel and an atomic element-bound fill primitive. These requirements cannot be
bypassed by selecting a provider ID or hidden flag.

Caller-provided CDP endpoints, remote-debugging ports, Playwright WebSocket endpoints, and unmanaged
browser targets are never contacted. They cannot attest the browser or page origin: a fake endpoint
can report an allowed URL and then receive the plaintext fill operation. The hidden historical
`--provider-transport-stdio` flag is rejected before profile, grant, or credential access; the
unshipped Node and Playwright wrappers that still name it are disabled fixtures, not supported
transports or fallbacks. The rejected legacy path is recorded in
[ADR 0003](docs/adr/0003-browser-injection-boundary.md). ADR 0005 records the earlier contract design;
the only code-enabled production direction is the authenticated Chrome extension route above.
