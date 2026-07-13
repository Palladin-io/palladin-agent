# @palladin/agent

Public npm launcher and native CLI/MCP runtime for Palladin Agent.

> [!WARNING]
> Palladin Agent is pre-production software and has not been published to npm. Do not use development builds with production credentials.

## Security boundary

The npm package is a small Node.js dispatcher. It never reads, receives, or stores an API key or an Agent private key. On macOS it directly starts the signed universal executable inside `@palladin/runtime-darwin-universal/PalladinRuntime.app`. On Windows it starts only the Authenticode-signed `palladin-client.exe` from the exact x64 or arm64 package; that client activates the fixed `palladin-runtime-companion.exe` AppContainer alias and the companion talks to the packaged LocalService broker. There is no TypeScript, `PATH`, download, or plaintext fallback.

The native runtime keeps these concepts separate:

- an API key belongs to the organization and may be shared by multiple Agents;
- every Agent has its own `agentId`, X25519 private key, and Ed25519 private key;
- public profile files contain only the API host, opaque secret references, Agent ID, public keys, and integrity commitments/signatures.

A small trust state in OS secure storage commits the complete public registry. Each profile config is committed by the registry and signed by that Agent's Ed25519 identity. The runtime verifies this chain before reading any Agent private key or organization API key. Public recovery metadata cannot authorize a secret deletion unless its digest is pinned by an in-progress secure-store transition.

The macOS Hardened build uses a provisioned Data Protection Keychain access group. Items are non-synchronizable and `WhenUnlockedThisDeviceOnly`; access to the shared organization credential requires user presence. Homebrew Node, an unsigned clone, and a differently signed fork do not have the entitlement. An unsigned development binary fails closed and does not fall back to Login Keychain, a file, or an environment variable.

The Windows Secure tier is installed separately with the owner-signed one-UAC bootstrapper. It registers `PalladinRuntime` as packaged `LocalService`, sets a restricted service SID, and protects `C:\ProgramData\Palladin\Runtime\v1` so only SYSTEM, Administrators, and `NT SERVICE\PalladinRuntime` have access. The npm package never performs privileged installation. A source build using Windows Credential Manager outside this broker boundary reports `Convenience`, never `Hardened`. Linux remains a separate epic task.

## Installation

Once the release packages are available:

```bash
npm install --global @palladin/agent
palladin doctor
```

On Windows, install the matching signed Palladin Runtime bootstrapper once before using Secure mode. npm installation remains script-free and does not prompt for elevation. If the service or companion is unavailable or invalid, the client fails closed instead of falling back to the current-user credential store.

No package uses `preinstall`, `install`, `postinstall`, or `prepare`. npm installs the matching prebuilt platform package; it does not download or compile a binary during installation.

For source development, run the Rust CLI directly:

```bash
cd runtime
cargo run -p palladin-cli -- doctor
```

The npm dispatcher is not a fallback development runtime. It intentionally fails if its signed platform package is absent.

## Connect an Agent

Create a local Agent identity:

```bash
palladin init
```

Release builds are pinned to the production API origin. Connect using the organization API key from a masked prompt:

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
| `palladin search <query>` | Search metadata visible to the Agent. |
| `palladin get <vaultId> <entryId>` | Intentionally return a granted credential to the operator. |
| `palladin exec <vaultId> <entryId> -- <program>` | Run an allowlisted program with delivered values in a sanitized child environment. |
| `palladin inject ...` | Fail closed until an authenticated browser boundary exists. |
| `palladin mcp serve` | Serve Palladin tools over MCP stdio. |
| `palladin security upgrade` | Explicitly migrate pre-production schema v2 state and secret slots to integrity-bound schema v3. |
| `palladin purge --confirm` | Explicitly remove native profiles and their known secret slots. |

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

- The production origin is pinned to exactly `https://api.palladin.io`; development HTTP accepts only literal `127.0.0.1` or `[::1]` with an explicit port.
- Native secret storage has no file or environment fallback.
- The organization API key and private keys are never child-process environment variables.
- `exec` uses no implicit shell, rebuilds the child environment from an allowlist, and supplies null stdin.
- Browser injection is disabled because a caller-controlled CDP endpoint cannot attest the browser or page origin.
- The npm launcher has no third-party JavaScript runtime dependencies. Its only production dependency is the exact-version platform package.
- Removing the npm package never deletes identity. Purge is always an explicit native command.

## Public local state

Native public state lives under `~/.palladin` and contains only profile aliases, opaque identity/organization references, host, Agent ID, public keys, signatures, and SHA-256 commitments. Secret values and the small registry trust root remain in the selected OS secure store. `PALLADIN_HOME` is rejected by identity-opening commands.

## Development

```bash
npm ci --ignore-scripts --workspaces=false
npm run build
npm test

cd runtime
cargo test --workspace --locked
```

The repository is public under Apache-2.0. Signed release artifacts, provenance, and notarization gates are produced only by the protected release workflow.
