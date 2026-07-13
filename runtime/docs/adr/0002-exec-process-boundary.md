# ADR 0002: Credential execution process boundary

- Status: Accepted
- Issues: CVT-314, CVT-319, CVT-337
- Date: 2026-07-13

## Context

The native runtime can execute a caller-selected program with one delivered credential, or execute a Script entry after delivering all of its references. This feature must not expose Palladin identity material to the child process or claim a stronger operating-system boundary than the standalone package provides.

The API key is an organization credential. Multiple Agents may use the same API key. An Agent's identity is its stable `agentId` and its X25519 and Ed25519 key pairs. CVT-314 does not change this ownership model or the backend protocol.

The standalone runtime retains identity keys and the organization API key in its parent process while serving CLI or MCP requests. Operating-system credential stores protect these values at rest, but do not universally prevent another process under the same user or UID from debugging the runtime, reading its memory, or invoking the same credential-store interface. Therefore native execution in the standalone npm distribution is a Convenience-tier feature.

## Decision

The standalone runtime applies the following defense-in-depth controls:

- It starts the selected executable directly. It never inserts an implicit shell. Windows `.bat` and `.cmd` files are rejected unless the caller explicitly starts a shell.
- Script entries use only the allowlisted `bash`, `sh`, `node`, and `python` interpreters. The executable is resolved and validated as an absolute canonical path to a regular executable before any referenced credential is delivered. This prevents a Script entry from supplying its own path or arguments, but it is not a same-user `PATH` integrity boundary.
- All Script references are validated and delivered before the script starts. One denied or invalid reference aborts execution.
- The child environment is cleared and rebuilt from a small positive allowlist plus explicitly scoped credential variables. Palladin identity keys, the organization API key, loader variables, and unrelated parent variables are not inherited.
- Child standard input is null, so an MCP child cannot consume JSON-RPC traffic and a CLI child cannot obtain additional terminal input through this path.
- MCP discards child stdout and stderr and returns only an exit status. Output is not persisted and exact-value masking is not treated as a security boundary. CLI output may be inherited by the human operator's terminal.
- The parent drops and zeroizes scoped credential values immediately after a successful spawn. The child receives only the environment copy required by the operating system.
- A POSIX process group or Windows Job Object owns the complete child process tree. Cancellation terminates the group.
- Script files are created in a private temporary directory, with mode `0600` on Unix. Normal completion, spawn failure, execution failure, and cancellation perform explicit cleanup, with RAII cleanup as a fallback.

Deletion cannot be guaranteed after an uncatchable process termination, kernel failure, power loss, or storage failure. Hardened packaging must add startup scavenging of stale private script directories. This residual limitation must not be hidden by product copy.

## Hardened tier

No implementation may label credential execution Hardened merely because it uses Keychain, Windows Credential Manager, or Secret Service.

Hardened execution must fail closed unless a platform component provides a boundary from ordinary processes running as the interactive user. The organization API key remains organization-wide; the boundary protects access to it and to each Agent's identity keys rather than changing their ownership.

Required platform directions are:

- macOS: a signed and provisioned broker with scoped Data Protection Keychain access, a hardened runtime or sandboxed executor, authenticated IPC, and negative tests for Keychain access, broker-oracle abuse, and `task_for_pid` or equivalent memory inspection.
- Windows: a broker running under a dedicated service SID, a restricted-token or AppContainer executor, authenticated IPC, Job Object containment, and negative tests proving the interactive user process cannot open or read broker and executor process memory.
- Linux: a broker UID distinct from the executor UID, or an equivalent container or sandbox boundary, authenticated Unix-domain IPC, and negative tests for `ptrace`, `/proc`, and `process_vm_readv` access.

The platform executor must expose a narrow operation protocol, not raw secret retrieval. A package without the appropriate broker and passing negative tests reports Convenience and never silently downgrades a requested Hardened operation.

### Windows implementation (CVT-337)

The signed Broker MSIX contains a one-shot `palladin-executor.exe`; it is not a second service. The restricted `LocalService` worker sends only one already-approved command and its scoped credential environment through the executor's bounded stdin. API key, DEK, X25519 and Ed25519 material remain in the worker.

The executor creates the selected process inside a fixed AppContainer with outbound Internet client capability. The child is created suspended with an exact inherited-handle list containing only null stdin and executor-owned stdout/stderr pipes, assigned to a kill-on-close Job Object, and only then resumed. The selected executable is canonicalized, opened without write/delete sharing, rejected when the final handle is a reparse point, and kept pinned across `CreateProcessW` to prevent same-user replacement after consent. Script files live only in the AppContainer profile and are removed on every handled exit path.

AppContainer is intentionally a security boundary and not a transparent user-session token. Commands cannot read arbitrary user files, broker storage, Windows Hello pins, machine-DPAPI ciphertexts, or another process's memory unless a future reviewed capability explicitly grants such access. CVT-337 does not add `broadFileSystemAccess`, a LocalSystem launcher, or a plaintext fallback.

### Linux glibc implementation (CVT-319)

Interactive npm use remains Convenience. Secret Service, PolKit, an executable path, and a Unix group cannot distinguish trusted Palladin JavaScript from other code running under the same UID. PolKit is used only for the narrow administrative action that creates or revokes a root-owned mapping between a dedicated Agent UID and one local profile.

Linux Hardened requires systemd 252 or newer, the signed DEB or RPM, plus a locked nologin OS account or an equivalent dedicated container. The systemd broker runs as `palladin-runtime`; `SO_PEERCRED` supplies the connecting UID, and a root-owned record binds that UID and account to a random immutable principal namespace, fixed profile, and approved API origin. Revocation retains a tombstone and terminates authenticated sessions. Reauthorization refuses a numeric UID while any process with that UID is alive; later safe UID reuse receives a new principal namespace. The complete dedicated Agent UID is the workload trust domain. Ordinary interactive UIDs and an unmapped UID cannot use the broker even if they can reach its socket.

The broker is non-dumpable. Its fixed root-owned worker therefore does not rely on `/proc/<parent>/exe`, which the kernel intentionally hides from the child. Worker admission instead requires the installed root-owned single-link executable, the broker marker, the dedicated non-root broker UID, and a broker-owned mode-0700 root under the selected immutable principal. An Agent UID cannot forge those ownership checks. Any arbitrary process already running as `palladin-runtime` is inside the broker trust domain because that UID can read the master key directly.

The broker owns public state and authenticated secret ciphertext in `/var/lib/palladin-runtime/v1`. Its device key and state are inaccessible to the Agent UID. The npm client has no secret operation and an authorized UID never falls back to the Convenience worker, Secret Service, a file, or an environment variable after a broker failure.

Credential execution crosses a second boundary. A root-owned socket assigned to a broker-only group starts one executor instance with a fresh `DynamicUser` UID for one request. The executor also checks `SO_PEERCRED` for the installed broker UID and requires a matching versioned protocol envelope. The broker sends only the already-approved command and scoped credential environment. The executor never receives the organization API key, X25519 or Ed25519 private key, or DEK. Broker and executor units clear loader variables and use `NoNewPrivileges`, `ProtectProc`, an empty capability set, and a core-dump prohibition. Native negative tests set the permissive Yama baseline and still require `ptrace`, `/proc`, and `process_vm_readv` access from the Agent UID to fail.

## Consequences

CVT-314 materially reduces accidental leakage, environment inheritance, output exfiltration through MCP, temporary-file residue on handled paths, and orphaned subprocesses. The standalone tier still does not defend against effective same-user debugging or memory reads. Windows Secure adds the AppContainer boundary described above. Linux Hardened adds the dedicated Agent UID, broker UID, and one-shot executor UID boundary described above. macOS retains its separately documented execution-boundary requirement.
