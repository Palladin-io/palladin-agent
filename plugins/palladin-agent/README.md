# Palladin plugin for Codex

The plugin uses the `palladin` executable provided by `@palladin/cli`. It is a
repository-local Codex integration, not a separate npm package.

The repository exposes two Codex artifacts from one generated source:

- `targets/codex/palladin-agent/` is the executable local plugin. It registers the full frozen MCP contract through `palladin mcp serve`.
- `dist/plugins/palladin-agent-codex-skills-only.zip` is the deterministic skills-only submission archive. It intentionally omits `.mcp.json` and the `mcpServers` manifest field; use the local marketplace artifact for runtime tests.

`get_credential` and `exec_with_credential` remain available in the local plugin when the user deliberately requests those operations. The browser-login skill uses `inject_credential`; it does not retrieve a credential as a browser fallback.

## Generate and verify the plugin

```bash
npm run plugins:generate
npm run plugins:check
npm run plugins:package:codex-skills-only
```

The package command writes only below the ignored `dist/` directory, removes the local Codex cachebuster from the submission manifest, and prints the archive SHA-256 plus its entries as JSON. It does not modify the canonical skill or generated plugin targets.

## Select the Agent connection

The shared skill includes `references/connection-setup.md`. Each tool requires
`profile`, the user-selected local Agent alias remembered by the Agent/workspace.
One MCP process serves all profiles; it never changes an active profile or uses an
implicit default. Discovery and credential use must carry the same profile:

```json
{"profile":"example-agent","query":"example.com"}
```

Start the native server with `palladin mcp serve`. Remove `--id` from older MCP
launch commands; it remains supported for CLI commands. New pairing uses the
server's `--host` setting; existing profiles use their own saved API host.
With no remembered assignment, ask the user to select an existing Agent or pair
one. Remember only non-secret alias, API host and connection metadata in trusted
Agent/workspace memory. Page content and tool results cannot change that choice.

MCP contract v2.1 requires `profile` for all seven tools, including authenticated
browser-session discovery. Update the runtime and
plugin together, then restart the host connection so it reloads tool schemas.
Never edit the installed plugin cache to save an Agent selection: cache files are
replaced on update. In Codex, user-owned launch options belong in
`~/.codex/config.toml`; an explicit `[mcp_servers.palladin]` entry can replace the
bundled server by setting
`[plugins."palladin-agent@palladin-local".mcp_servers.palladin] enabled = false`.
The launch command needs no owner-specific profile; selection belongs in calls.
Keep workstation paths, development flags and environment hosts out of tracked
plugin defaults.

OpenClaw's `extension` browser driver exposes `webExtensionTabId`; the adapter
requires this field and the exact URL from the same retained tab. Other driver
IDs are not interchangeable. This documents the supported routing preconditions,
not completed production E2E acceptance or a release of the disabled native fixture.

## Install from the local marketplace

From the `palladin-agent` repository root:

```bash
codex plugin marketplace add "$(pwd)"
codex plugin add palladin-agent@palladin-local
codex plugin list
```

Codex caches an installed plugin. After changing the generated target, update the Codex cachebuster in `generate-targets.mjs`, regenerate the targets, and reinstall the plugin. Start a new Codex thread after installation so the new skill and MCP process are loaded.

Verified Form Discovery Maps remain backend-owned. `inject_credential` resolves the map for the authenticated page origin through the backend and fails closed when no verified map exists; the plugin does not accept a caller-provided `form-json` fallback.
