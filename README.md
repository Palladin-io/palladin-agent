# @palladin/agent

Public npm launcher and native CLI/MCP runtime for Palladin Agent.

> [!WARNING]
> Palladin Agent is pre-production software and has not been published to npm. Do not use development builds with production credentials.

The repository contains the current native runtime and release engineering,
but no public npm release is available yet. Installation commands below describe
the intended signed release and will not work until the packages are published.

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

An active MCP process keeps the native version it started with. Updating npm changes only subsequent launches; the next launch requires the exact new platform package and its signed, unexpired version policy. The public launcher forwards that owner-signed envelope to the native process, which binds the image actually opened by the OS before opening identity. Linux measures `/proc/self/exe`; macOS additionally requires the running code's exact Developer ID, identifier, and Data Protection Keychain entitlements. Linux Hardened independently verifies the root-owned system worker with broker-owned anti-rollback state, hashes an open descriptor, and executes that same descriptor. On Windows the public runtime cache may outlive npm uninstall so a loaded process is not interrupted. It contains no identity, API key, private key, profile, or credential. A signed policy can block a bad version before any identity-bearing command starts. Exact `doctor`, help, and version diagnostics remain available during a dynamic policy outage because they do not open identity, but they still require the release-bundled signed artifact binding, exact hash, and Windows Authenticode checks. Adding any other argument restores the current policy requirement.

Node.js 20.5 or newer and npm 9.7.1 or newer are required. Older npm versions do not reliably enforce the Linux `libc` package filter and are unsupported because they may install both glibc and musl optional packages. npm 9.7.0 is excluded because that release shipped an invalid executable manifest.

For source development, run the Rust CLI directly:

```bash
cd runtime
cargo run -p palladin-cli -- doctor
```

On macOS, use the repository development launcher for commands that open local
Agent state. Its one-time offline bootstrap creates a local-only code-signing
identity; macOS may request approval for that trust setting once. The first build
also installs an owner-only helper with a stable binary hash. Changing debug
runtimes use that unchanged helper for Login Keychain access because current
macOS versions do not track a non-Apple signer by its stable Designated
Requirement. Every later run verifies both signatures before it starts:

```bash
./packaging/macos/scripts/development-runtime.sh run -- doctor
./packaging/macos/scripts/development-runtime.sh install-launcher ~/.local/bin/palladin
```

An existing source installation needs one explicit ACL migration after the first
helper build. It changes only the exact Palladin service ACL and asks for the
Login Keychain password once:

```bash
./packaging/macos/scripts/development-runtime.sh migrate-keychain-access
```

Pass `--force` to `install-launcher` only after reviewing an existing launcher.
The identity remains Convenience-tier and is deliberately rejected by the
Developer ID release/notarization path. See [the macOS packaging runbook](packaging/macos/README.md).

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
./packaging/macos/scripts/development-runtime.sh run --local-development -- connect --host http://127.0.0.1:5000
# Or, after install-launcher on macOS:
palladin --local-development connect --host http://127.0.0.1:5000

# On other development platforms:
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
| `palladin inject <vaultId> <entryId> --provider extension --target-tab-id <id> --page-url <URL> --form-json <JSON>` | Use the code-enabled authenticated Chrome extension route on macOS and bind a framework-prepared operation to one exact WebExtensions tab. Other providers and platforms fail closed before profile, grant, or credential access. Release acceptance remains gated on the signed/notarized package and real Chrome E2E. |
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
| `inject_credential` | Invoke the same native Inject service as the CLI, through the authenticated extension provider, without returning the credential to the model. MCP contract v1.1 adds the paired `targetTabId`/`targetUrl` routing hints. |
| `report_credential_stale` | Report a stale credential without sending its value. |

## Credential delivery methods

`get`, `exec`, and `inject` are three grant-controlled ways to deliver one approved Entry. They use
the same request, approval, expiry, usage-limit, and audit lifecycle, but have different output
contracts. The approving user chooses which methods a grant allows; the runtime cannot silently
substitute a method that was not granted.

GRANULAR delivery opens one exact per-Entry grant envelope. FULL delivery instead receives one
`AgentWrappedVaultKey` for the grant together with the requested Entry's current encrypted key and
MemberSecret. The complete 32-byte Vault key is sealed to this Agent's X25519 identity and bound to
the Organization, Vault, Grant, Agent access epoch, recipient key version/fingerprint and Vault-key
version. It is opened only inside the native Rust crypto boundary, zeroized after deriving the Entry
key, and never crosses into the Node launcher, MCP result, child process or browser extension.

### `get`: return an approved value

Use `get` when the caller genuinely needs the selected value rather than only the result of an
operation performed with it:

```bash
palladin get <vaultId> <entryId>
palladin get <vaultId> <entryId> --field password
palladin get <vaultId> <entryId> --field-id <publicFieldId>
```

The CLI writes a secret-bearing JSON result to stdout. Without a selector it returns the granted
credential payload; `--field` selects a field by label and `--field-id` selects a custom field by
its public identifier. A selected TOTP field returns only the current short-lived code and expiry,
never the TOTP seed. The equivalent MCP tool is `get_credential`.

This is an intentional plaintext output boundary. CLI prints a warning to stderr unless `--quiet`
is set; `--quiet` suppresses only the warning and does not change the secret-bearing stdout result.
An MCP result becomes available to the calling Agent and may enter its model context, provider
retention, session transcript, or observability tooling. Do not send `get` output to logs, shell
history, command-line arguments, temporary files, analytics, or an untrusted caller. Prefer `exec`
or `inject` when the workflow needs to use a credential but does not need to receive its value.

`get` still requires an active grant that includes the `Get` method, observes the grant's expiry and
remaining-use limit, and records successful delivery in the audit trail. Script Entries remain
`exec`-only and payment-card Entries remain `inject`-only regardless of the requested grant flags.

### `exec` and `inject`: use without returning the value

- `exec` maps approved fields into a sanitized child process. Over MCP, child stdout and stderr are
  withheld and the tool returns only the exit status.
- `inject` sends approved fields to an authenticated provider and returns a value-free outcome.
  Unsupported or unauthenticated provider paths fail before credential delivery.

## Security notes

- Release origins are pinned to exactly `https://api.palladin.io` and `https://api.stage.palladin.io`; development HTTP accepts only literal `127.0.0.1` or `[::1]` with an explicit port.
- Native secret storage has no file or environment fallback.
- The organization API key and private keys are never child-process environment variables.
- `exec` uses no implicit shell, rebuilds the child environment from an allowlist, and supplies null stdin.
- Browser injection never accepts a caller-controlled CDP endpoint, executable script, arbitrary browser command, or secret-bearing argument. The Rust runtime resolves a verified global Form Discovery Map for MCP; only an explicit CLI `--form-json` caller may supply a bounded, value-free fallback definition. A browser framework passes a WebExtensions `targetTabId` together with its exact HTTPS URL snapshot; these are untrusted routing hints, not authorization. The macOS Chrome extension route authenticates both encrypted transport hops, resolves and pins that exact tab/document before the runtime requests a grant or decrypts a credential, then re-checks the same tab/document, HTTPS and the encrypted Entry domain before delivery.
- The npm launcher has no third-party JavaScript runtime dependencies. Its only production dependency is the exact-version platform package.
- Removing the npm package never deletes identity. Purge is always an explicit native command.

## Browser providers

`Inject` has an Open/Closed provider boundary. The native runtime owns grant delivery and
credential decryption; provider adapters own only browser navigation/fill and return a value-free
outcome. Adding another agent browser does not change the grant, crypto, CLI, or MCP core.

| Provider | Receiver | Extension required | Secret transport |
|---|---|---:|---|
| `extension` | The existing Palladin Chrome extension | Yes — the same user-autofill extension | Two authenticated encrypted hops: CLI↔Rust host and Native Messaging host↔extension |
| `playwright` | Disabled historical development wrapper | No | None — its old private-pipe flag is rejected before profile, grant, or credential access |
| `agent-browser` | `@palladin/agent-browser-mcp` public navigation proxy | No | None — `inject_credential` fails closed before grant/runtime/secret-bearing daemon commands |

The extension provider uses the same Palladin extension rather than a provider-specific extension.
On macOS, `palladin browser install` provisions the host identity in OS secure storage, installs
`io.palladin.browser_bridge` for Google Chrome, and prints the shortened fingerprint. The extension
automatically discovers the host's public identity through a challenge-bound, value-free Native
Messaging exchange; compare the shortened fingerprint shown in both surfaces and choose
**Trust and pair**. Discovery never writes or replaces the extension-owned pin.
`palladin browser status` reports the host manifest and provisioned host identity without claiming
that the separately extension-owned pin is present. The authenticated channel is verified when
Inject begins.

`palladin browser unpair --confirm` revokes the OS-secured lifecycle token before deleting the host
key and manifest. Browser forwards hold a shared cross-process lease from the final token check
through the value-free response, while unpair holds the exclusive lease through cleanup, so no
loaded session can finish after unpair reports success. The post-prepare wait is derived from the
canonical five-minute grant window plus a 30-second margin; secret-bearing browser round trips stay
bounded to 60 seconds. The local AEAD payload also binds the minimum operation-lease/grant expiry as
a canonical `CLOCK_MONOTONIC` not-after; the host rechecks it under the shared lifecycle lease
immediately before writing to the extension, so queued socket ciphertext cannot outlive its grant.
The host allowlist contains only the compiled extension origin
`chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/`.

The local socket is only a rendezvous point. The CLI signs a fresh ephemeral handshake with the
OS-secured host identity, the host signs its response, and both derive independent directional
XChaCha20-Poly1305 keys. The host also dynamically validates that Google-signed Chrome launched it
before loading the identity. Windows, Linux, other Chromium browsers, Firefox, and Safari fail
closed until their platform-specific launch attestation and installation paths are implemented.

Codex, Claude, and other MCP clients are callers, not browser providers. They never receive a
dedicated extension or the credential value. The unshipped Node/Playwright adapters are disabled
fixtures: their hidden `--provider-transport-stdio` invocation is rejected by the Rust CLI in every
build. Provider identifiers are an open namespace rather than a catalog allowlist; execution fails
closed until the matching separately reviewed authenticated transport is registered. The CLI/MCP input never accepts a CDP URL,
remote-debugging port, Playwright WebSocket endpoint, unmanaged browser target, or plaintext pipe.

### Verified and Agent-defined form execution

The native Rust runtime first looks up a verified Form Discovery Map for the authenticated Entry
domain and selected provider. The catalog is global; candidate and observed maps are never executed.
A returned map is accepted only when its fingerprint, bounded action contract, provider identifier,
domain, and exact HTTPS origin validate locally. Login paths are data and may represent any locale or
site route; the contract contains no list of known URLs. Persisted login URLs omit query and fragment
data so one-time flow state or tokens cannot enter the catalog. When no verified map
applies, a CLI caller may prepare the public login surface with ordinary browser tools, inspect it,
and pass a complete, versioned, value-free form definition to `palladin inject --form-json` as a
fallback. MCP 1.1 `inject_credential` adds only exact-tab routing hints; it has no form argument and never accepts this
fallback.
The definition is an ordered list of one or more steps mapping schema-valid Entry field IDs to public
control locators, with a bounded click or press-Enter action and an optional next-step transition
expectation.

After a fallback form completes every declared Inject step, the native Runtime submits that
value-free definition to the global API as a `candidate`. The request uses the authenticated Agent
identity as provenance, strips query and fragment state from the current HTTPS URL, and never
contains field values. Candidate recording is best-effort after the completed Inject, is idempotent
for the same fingerprint, and cannot make the map executable; only the trusted catalog process may
promote it to `verified`.

The version 1 shape is `{"version":1,"steps":[...]}`. A verified map may use any schema-valid Entry
field identifier needed by the login flow. The runtime resolves only fields from the already
authorized credential and checks their value kind against the declared control before delivery.
Every step declares one `click` or `press-enter` submit action; every intermediate
step also declares `waitFor`. `--form-json` is a value-free CLI fallback; MCP 1.1 preserves the
backend-provided verified form map boundary and adds only the optional paired `targetTabId` and
`targetUrl` routing hints. Credential values are
retrieved, decrypted and forwarded only inside the native runtime.

The native runtime retrieves and decrypts only the approved values after the grant is active. The
selected provider validates each declared control, re-checks HTTPS and the authenticated Entry domain
before every fill/submit and after every transition, injects the values, and performs the declared
actions. It returns only a bounded result and leaves the authenticated browser session available to
the Agent. Missing, stale, ambiguous, hidden, or semantically invalid definitions fail closed; the
provider never guesses another form. A failed declared selector, control attestation, submit selector,
or transition invalidates that cached map and asks the API for a fresh revision for the next request.
If the API still returns the rejected version and fingerprint, a public rejection tombstone keeps
that exact revision unavailable while later requests continue checking for a replacement; a
concurrently stored higher version is neither removed nor overwritten by a delayed
response. Cache invalidation/refresh persistence failures are reported to the operator. A separately
validated CLI fallback form remains
available during transient map lookup transport/5xx failures, while invalid payloads, authentication,
and unsafe local cache/configuration errors still fail closed.
Origin mismatch and provider transport/browser failures keep their specific outcome and do not evict
a valid map. Palladin never retries a partially filled or submitted login automatically.

### Form Discovery Map cache

Verified maps are public and value-free. The native runtime stores them in
`~/.palladin/form-map-cache.json` with owner-only permissions and an LRU key scoped by API origin,
domain, and provider. Global maps are shared by local Agent profiles connected to the same
API origin. The default maximum is 100 entries. Configure it with the
owner-only `~/.palladin/runtime-config.json` file:

```json
{
  "formMapCache": {
    "maxEntries": 100
  }
}
```

`maxEntries` must be an integer from 1 through 500. Unknown properties, unsafe permissions, symbolic
links, malformed maps, or an out-of-range limit fail closed. Every cache read/update/invalidation is
serialized with the cross-process profile transaction lock. Active maps and rejection tombstones
share the same LRU capacity. Neither file contains credential values,
cookies, API keys, private keys, or decrypted vault data. Explicit full-runtime purge recognizes and
removes both files.

See [ADR 0005](runtime/docs/adr/0005-authenticated-inject-form-contract.md) for the contract and test
requirements. Caller-controlled CDP remains disabled under [ADR 0003](runtime/docs/adr/0003-browser-injection-boundary.md).

## Public local state

Convenience public state lives under `~/.palladin`. Linux Hardened public state lives in a broker-owned random principal namespace that is never derived from a reusable numeric UID. Both contain only profile aliases, opaque identity/organization references, host, Agent ID, public keys, signatures, SHA-256 commitments, public runtime configuration, and verified value-free Form Discovery Maps. Secret values and the small registry trust root remain in the selected secure store. `PALLADIN_HOME` is rejected by identity-opening commands.

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

The repository is public under [Apache-2.0](LICENSE). See [NOTICE](NOTICE),
[third-party notices](THIRD_PARTY_NOTICES.md), and the
[trademark policy](TRADEMARKS.md). Signed release artifacts are not produced by
public pull requests. `macOS Signed Release Gate` and `Windows Signed Release
Gate` are separate owner-dispatched workflows that sign only an exact commit
already reachable from `main`, then install and execute the resulting artifacts
on native CPU runners. They must be green for a signed release, but are not
pull-request branch-protection contexts.
