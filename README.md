# @palladin/agent

Public npm launcher and native CLI/MCP runtime for Palladin Agent.

> [!WARNING]
> Palladin Agent is pre-production software and has not been published to npm. Do not use development builds with production credentials.

## Security boundary

The npm package is a small Node.js dispatcher. It never reads, receives, or stores an API key or an Agent private key. On macOS it directly starts the signed universal executable from the exact x64 or arm64 npm package. On Windows it verifies the exact Authenticode-signed `palladin-client.exe` against signed release policy, copies only that public executable into a version-and-hash-specific per-user cache, opens and re-verifies the cached file under a non-write/non-delete handle, and keeps that handle until the child exits. The child is started without a shell. This avoids locking `node_modules` while an MCP session remains active. The client activates the fixed `palladin-runtime-companion.exe` AppContainer alias and the companion talks to the packaged LocalService broker. On Linux the dispatcher reads only the `PT_INTERP` header of its own Node executable and selects the exact x64 or arm64 glibc or musl package; unknown libc loaders fail before package resolution. There is no TypeScript credential implementation, `PATH`, runtime download, cross-libc, or plaintext fallback.

The native runtime keeps these concepts separate:

- an API key belongs to the organization and may be shared by multiple Agents;
- every Agent has its own `agentId`, X25519 private key, and Ed25519 private key;
- public profile files contain only the API host, opaque secret references, Agent ID, public keys, and integrity commitments/signatures.

A small trust state in OS secure storage commits the complete public registry. Each profile config is committed by the registry and signed by that Agent's Ed25519 identity. The runtime verifies this chain before reading any Agent private key or organization API key. Public recovery metadata cannot authorize a secret deletion unless its digest is pinned by an in-progress secure-store transition.

The macOS Hardened build uses a provisioned Data Protection Keychain access group. Items are non-synchronizable and `WhenUnlockedThisDeviceOnly`; access to the shared organization credential requires user presence. Homebrew Node, an unsigned clone, and a differently signed fork do not have the entitlement. An unsigned development binary fails closed and does not fall back to Login Keychain, a file, or an environment variable.

The Windows Hardened tier is installed separately with the owner-signed one-UAC bootstrapper. It registers `PalladinRuntime` as packaged `LocalService`, sets a restricted service SID, and protects `C:\ProgramData\Palladin\Runtime\v1` so only SYSTEM, Administrators, and `NT SERVICE\PalladinRuntime` have access. The npm package never performs privileged installation. A source build using Windows Credential Manager outside this broker boundary reports `Convenience`, never `Hardened`.

Linux Secret Service is always Convenience because it cannot distinguish two processes under the same UID. Linux Hardened is an optional DEB/RPM system package: a dedicated Agent account is bound by root-owned configuration to a random immutable principal namespace, fixed profile, and approved origin. The broker owns context-bound encrypted state under a separate UID, and each credential execution uses a broker-only socket plus a one-shot systemd `DynamicUser` executor. PolKit authorizes only management of this record; it is not presented as process isolation. See [the Linux runbook](packaging/linux/README.md).

| Linux target | npm Convenience | Hardened |
|---|---|---|
| glibc x64/arm64 + systemd 252+ | Supported | Supported through the separate DEB/RPM |
| musl x64/arm64, including Alpine 3.22 | Supported when a compatible Secret Service is available; otherwise secret operations fail closed | Unsupported in the MVP; no APK is published |

## Installation

Once the release packages are available:

```bash
npm install --global @palladin/agent
palladin doctor
```

On Windows, install the matching signed Palladin Runtime bootstrapper once before using Hardened mode. npm installation remains script-free and does not prompt for elevation. If the service or companion is unavailable or invalid, the client fails closed instead of falling back to the current-user credential store.

On glibc Linux with systemd 252 or newer, npm alone installs the Convenience tier. Install the matching signed `palladin-runtime` DEB or RPM only for a dedicated headless Agent UID. An authorized UID fails closed when the broker, executor socket, root-owned mapping, or permissions are invalid; it never falls back to the npm worker or Secret Service. Workload purge is blocked; permanent deletion requires the root-owned `palladin-manage-agent-uid revoke-purge USER --confirm-purge` operation, which retains the UID-reuse tombstone. Alpine/OpenRC has no Hardened package in the MVP because it lacks an equivalent fresh per-request UID and executor sandbox.

No package uses `preinstall`, `install`, `postinstall`, `preprepare`, `prepare`, or `postprepare`. npm installs the matching prebuilt platform package; it does not download or compile a binary during installation.

### npm installation policy

- A global install is the recommended stable CLI setup: `npm install --global @palladin/agent@<exact-version>`.
- A project-local exact dependency is supported; invoke it with `npm exec -- palladin doctor` or the project script runner.
- `npx` is supported only with an explicit immutable version, for example `npx --yes @palladin/agent@<exact-version> -- doctor`. Do not use an unpinned tag for a credential-handling tool.
- `--omit=optional` is unsupported because the native runtime is an optional platform dependency. Offline installs require the launcher and its matching platform tarball to exist in the configured npm cache or proxy.

All three modes run the same script-free launcher and exact platform package. They do not change where native public state or OS-protected secrets live.

An active MCP process keeps the native version it started with. Updating npm changes only subsequent launches; the next launch requires the exact new platform package and its signed, unexpired version policy. The policy binds both the public npm client and the native credential-bearing worker; the worker hashes its own executable before opening identity. On Windows the public runtime cache may outlive npm uninstall so a loaded process is not interrupted. It contains no identity, API key, private key, profile, or credential. A signed policy can block a bad version before any identity-bearing command starts. Exact `doctor`, help, and version diagnostics remain available during a dynamic policy outage because they do not open identity, but they still require the release-bundled signed artifact binding, exact hash, and Windows Authenticode checks. Adding any other argument restores the current policy requirement.

Node.js 20.5 or newer and npm 9.7.1 or newer are required. Older npm versions do not reliably enforce the Linux `libc` package filter and are unsupported because they may install both glibc and musl optional packages. npm 9.7.0 is excluded because that release shipped an invalid executable manifest.

For source development, run the Rust CLI directly:

```bash
cd runtime
cargo run -p palladin-cli -- doctor
```

The npm dispatcher is not a fallback development runtime. It intentionally fails if its signed platform package is absent.

### macOS Keychain prompt

If macOS says that `node` wants to access confidential information in Keychain, stop the process. A legacy development build is running. A supported package invokes the signed `PalladinRuntime.app`; Node itself must never request Keychain access. Run `palladin doctor` from an exact-version installation and verify the reported runtime before connecting an Agent.

## Connect an Agent

Create a local Agent identity:

```bash
palladin init
```

Release builds are pinned to the exact Palladin production and staging API origins. Connect using the organization API key from a masked prompt:

```bash
palladin connect --host https://api.palladin.io
```

Literal HTTP loopback origins are available only in an explicitly compiled source-development build:

```bash
cd runtime
cargo run -p palladin-cli --features local-development -- connect --host http://127.0.0.1:5000
```

Automation must pass the key through protected standard input:

```bash
secret-provider | palladin --id build connect --api-key-stdin --host https://api.palladin.io
```

API keys in argv or environment variables are rejected. Connecting a second profile with the same organization API key reuses one organization credential while preserving distinct Agent keypairs.

## Commands

| Command | Description |
|---|---|
| `palladin init` | Create the default local Agent identity. |
| `palladin connect` | Connect using a masked organization API-key prompt. |
| `palladin status` | Show the selected Agent registration state. |
| `palladin doctor` | Report platform, storage boundary, and unsafe environment state without opening identity. |
| `palladin agents list` | List local Agent profile aliases. |
| `palladin agents create <name>` | Create another local Agent identity. |
| `palladin agents rename <old> <new>` | Rename an alias without moving secret slots. |
| `palladin agents delete <name>` | Delete an identity; retain a shared organization credential while another Agent references it. |
| `palladin --id <name> disconnect --purge --confirm` | Explicitly remove one Agent identity and retain its shared organization credential while another Agent references it. |
| `palladin search <query>` | Search metadata visible to the Agent. |
| `palladin get <vaultId> <entryId>` | Intentionally return a granted credential to the operator. |
| `palladin exec <vaultId> <entryId> -- <program>` | Run an allowlisted program with delivered values in a sanitized child environment. |
| `palladin inject ...` | Fail closed until an authenticated browser boundary exists. |
| `palladin mcp serve` | Serve Palladin tools over MCP stdio. |
| `palladin security upgrade` | Explicitly migrate pre-production schema v2 state and secret slots to integrity-bound schema v3. |
| `palladin security legacy-status` | Inspect legacy TypeScript state without opening config or private-key contents. |
| `palladin security legacy-cutover --confirm-pre-production-reset` | In a dev build, archive legacy TypeScript profiles and generate fresh native X25519/Ed25519 identities. |
| `palladin security legacy-cleanup <cutoverId> --confirm` | In a dev build, delete the archived TypeScript files and exact legacy OS credential entries after every fresh Agent is enrolled. |
| `palladin purge --confirm` | Explicitly remove native profiles and their known secret slots in standalone tiers; Linux Hardened requires the root-owned administrative purge. |

## Pre-production TypeScript cutover

Legacy TypeScript builds stored an organization API key in plaintext `config.json` and could store exportable Agent keys in Login Keychain, Credential Manager, Secret Service, environment variables, or `0600` files. Treat every identity and organization key used by those builds as potentially exposed.

The native cutover does not import any old private key, API key, `agentId`, host, grant, or config value. It reads only bounded registry metadata and filesystem metadata, atomically archives `.palladin` or the earlier `.claw-vault` root, and creates a fresh X25519/Ed25519 identity for every validated profile alias. Unknown files, links, unsafe permissions, ambiguous roots, malformed registries, and alias collisions fail before cleanup.

This workflow is intentionally available only in pre-production/dev builds:

```bash
palladin doctor
palladin security legacy-status
palladin security legacy-cutover --confirm-pre-production-reset

# Create one new organization API key in the existing Palladin panel, then repeat for every profile.
new-key-provider | palladin --id <profile> connect --api-key-stdin --host https://api.palladin.io

# After every fresh Agent is approved, use the exact ID printed by legacy-cutover.
palladin security legacy-cleanup <cutoverId> --confirm
```

Cleanup uses a deletion-only OS credential adapter for the historical `palladin` and `claw-vault` services. It has no API that can read secret bytes. If deletion is interrupted, the archive remains and the same command resumes idempotently. Cleanup is refused until every planned fresh profile has a new backend `agentId`.

Finally, revoke the old shared organization API key and deactivate the old Agents in the existing panel. Local deletion cannot revoke backend Agents or guarantee erasure from SSD snapshots, backups, or a parent shell. Legacy environment-variable names are reported by `doctor`; their values are never read or printed, and the operator must unset them manually. No migration or cleanup runs from npm installation, update, uninstall, or any lifecycle hook.

## MCP configuration

```json
{
  "mcpServers": {
    "palladin": {
      "command": "palladin",
      "args": ["mcp", "serve"]
    }
  }
}
```

The Agent must be active before credential tools work.

| Tool | Behavior |
|---|---|
| `search_entries` | Search metadata without returning secret values. |
| `get_credential` | Intentionally return a granted value; TOTP fields return only the current code. |
| `exec_with_credential` | Execute without returning child stdout/stderr to the model. |
| `inject_credential` | Fail closed without contacting CDP or requesting a credential. |
| `report_credential_stale` | Report a stale credential without sending its value. |

## Security notes

- Release origins are pinned to exactly `https://api.palladin.io` and `https://api.stage.palladin.io`; development HTTP accepts only literal `127.0.0.1` or `[::1]` with an explicit port.
- Native secret storage has no file or environment fallback.
- The organization API key and private keys are never child-process environment variables.
- `exec` uses no implicit shell, rebuilds the child environment from an allowlist, and supplies null stdin.
- Browser injection is disabled because a caller-controlled CDP endpoint cannot attest the browser or page origin.
- The npm launcher has no third-party JavaScript runtime dependencies. Its only production dependency is the exact-version platform package.
- Removing the npm package never deletes identity. Purge is always an explicit native command.

## Public local state

Convenience public state lives under `~/.palladin`. Linux Hardened public state lives in a broker-owned random principal namespace that is never derived from a reusable numeric UID. Both contain only profile aliases, opaque identity/organization references, host, Agent ID, public keys, signatures, and SHA-256 commitments. Secret values and the small registry trust root remain in the selected secure store. `PALLADIN_HOME` is rejected by identity-opening commands.

## Development

```bash
npm ci --ignore-scripts --workspaces=false
npm run lint
npm run build
npm test

cd runtime
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

cd ..
dotnet restore --locked-mode runtime/contracts/dotnet/Palladin.ContractGate/Palladin.ContractGate.csproj
dotnet run --no-restore --project runtime/contracts/dotnet/Palladin.ContractGate/Palladin.ContractGate.csproj -- runtime/contracts/v1
```

Every pull request runs two stable required contexts:

- `CI Gate` aggregates the Node.js matrix, minimum supported npm selection tests, Rust formatting and linting, the full Rust workspace, and the frozen TypeScript/Rust/.NET contract consumers.
- `Native Platform Gate` aggregates native Apple Silicon, Intel macOS, Windows x64, Windows ARM64, Linux glibc x64/arm64, and Linux musl x64/arm64 builds and smoke tests. A supported target cannot be skipped by a path filter.

The repository is public under Apache-2.0. Signed release artifacts are not produced by public pull requests. `macOS Signed Release Gate` and `Windows Signed Release Gate` are separate owner-dispatched workflows that sign only an exact commit already reachable from `main`, then install and execute the resulting artifacts on native CPU runners. They must be green for a signed release, but are not pull-request branch-protection contexts.
