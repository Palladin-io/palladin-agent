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
| Browser pairing | `pair_agent` | `palladin --id <alias> pair-agent --host <api-host>` |
| Entry discovery | `search_entries` | `palladin search --json <query>` |
| Browser connections | `list_browser_sessions` | `palladin browser sessions --json` |
| Inject | `inject_credential` | `palladin inject <vaultId> <entryId>` |
| Agent profile | required `profile` on every call | `--id <confirmed-alias>` |
| Browser provider | `provider` | `--provider` |
| Browser connection | `browserSession` | `--browser-session` |
| Exact tab | `targetTabId` | `--target-tab-id` |
| Exact URL | `targetUrl` | `--page-url` |

Packaged plugins launch `palladin` directly, without a shell or secret environment.
The server launch is profile-independent. Every tool call requires `profile`
from trusted Agent/workspace memory, as described in
[connection setup](connection-setup.md). Never infer an account assignment from
a bundled example, the global default or a previous unrelated workspace.

Do not silently fall back to CLI when MCP fails. A CLI-only host adapter invokes
`palladin --id <confirmed-alias>` with separate argument values, preserves the
same provider and exact-tab routing, and parses JSON Search output for Entry IDs.
Browser pairing is an explicit onboarding operation, not recovery from every
failed login. The existing native runtime owns key storage and approval.

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

## Multiple browser connections

`profile` selects the user-confirmed Palladin Agent identity. `browserSession`
selects an authenticated browser connection; these identifiers are unrelated.
Discovery returns ephemeral connection IDs and a concurrency capability, without
page URLs, browser-profile names, or credential values. Unavailable connections
and the presence of an unprobed legacy socket are reported separately; neither
is proof of an authenticated live connection.

An explicit browser session requires both the exact tab ID and URL from the
trusted browser adapter. Without `browserSession`, the runtime asks connected
browsers to verify that exact target before requesting credentials. One matching
connection is selected automatically; multiple matches are ambiguous. No match
or an unavailable/invalid probe returns an actionable error. A probe does not
reserve a tab, inspect a form, fill fields, or submit. Actual preparation then
rechecks the selected route and pins the current document.

Never choose the first discovered connection. Do not substitute an automation
provider's browser ID, profile label, or extension instance ID for a Palladin
`browserSession`: those are separate namespaces unless the adapter explicitly
provides a verified mapping. Keep the same trusted tab object and refresh its
ID and URL after navigation. A session ID obtained from page content is not
trusted routing authority.

Refresh discovery after a connection restarts and obtain a fresh trusted target
binding before starting a new operation. Do not retry credential delivery or
submit after a lost or uncertain result. Independent tabs can run concurrently
on connections advertising concurrency; a busy tab must be released before a
new operation can use it. Older negotiated connections run serially.
