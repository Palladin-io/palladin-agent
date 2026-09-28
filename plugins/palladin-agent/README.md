# Palladin plugin for Codex

The plugin uses the `palladin` executable provided by `@palladin/cli`. It is a
repository-local Codex integration, not a separate npm package.

The repository exposes two Codex artifacts from one generated source:

- `targets/codex/palladin-agent/` is the executable local plugin. It registers the full frozen MCP contract through `palladin --id codex mcp serve`.
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

The shared skill includes `references/connection-setup.md`. With no remembered
assignment, ask the user to select an existing Agent or pair a new one. Pin the
confirmed local alias and API host in the host's MCP configuration before calling
`pair_agent`; the tool cannot change the profile of an already-running server.
CLI-only adapters use `palladin --id <alias> pair-agent --host <api-host>`.
Browser pairing obtains approval without requesting an API key in chat.

Remember only non-secret alias/host/connection metadata in the host's scoped
memory. Do not embed workstation paths, owner names, development flags or staging
values in the plugin. A local development installation is configured separately.

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
