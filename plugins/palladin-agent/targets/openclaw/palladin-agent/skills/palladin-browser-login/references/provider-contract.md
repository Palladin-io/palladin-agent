# Palladin provider contract

Keep three boundaries separate:

1. **Agent host provider** — Codex, Claude Code, OpenClaw, or Hermes packages this skill and obtains
   a trustworthy browser-tab handle.
2. **Credential surface** — MCP is the normal plugin surface; a reviewed adapter may instead call
   the equivalent CLI. Both enter the same native Rust Inject service.
3. **Browser provider** — the runtime provider ID selects a separately reviewed authenticated
   browser transport. A plugin cannot add or enable a provider by naming it.

## Surface mapping

| Operation | MCP | CLI |
|---|---|---|
| Discovery | `search_entries` | `palladin search --json <query>` |
| Inject | `inject_credential` | `palladin inject <vaultId> <entryId>` |
| Browser provider | `provider` | `--provider` |
| Exact tab | `targetTabId` | `--target-tab-id` |
| Exact URL | `targetUrl` | `--page-url` |

Packaged plugins launch `palladin mcp serve` directly, without a shell or secret environment. They
must not silently fall back to CLI when MCP fails. A CLI-only host adapter must invoke `palladin` as
one executable with a separate argument list, preserve the same provider and exact-tab values, and
parse only JSON Search output so complete `vaultId` and `entryId` values reach Inject.

## Current browser providers

Only `extension` is code-enabled. It currently resolves to the authenticated Palladin extension
transport for Google Chrome on macOS. Windows, Linux, Firefox, Opera, other Chromium browsers, and
other provider IDs fail closed until their runtime, native-host installation, launch attestation,
exact-tab mapping, extension packaging, and E2E gates are implemented together.

The disabled `playwright` and `agent-browser` fixtures are not credential providers. Never use them,
CDP, remote debugging, a plaintext pipe, or page JavaScript as a fallback.

When adding a provider, update CLI, MCP, the shared Rust Inject service, the browser/native-host
adapter, this contract, and cross-platform tests in one reviewed change. A target-specific skill or
manifest alone cannot declare support.
