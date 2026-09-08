# Palladin plugin for Codex

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

## Prepare a local macOS runtime

Build the native runtime from this checkout and install its reviewed development launcher somewhere already present on `PATH`:

```bash
./packaging/macos/scripts/development-runtime.sh build
./packaging/macos/scripts/development-runtime.sh install-launcher ~/.local/bin/palladin
palladin agents create codex
palladin --id codex connect --host https://api.stage.palladin.io
```

Do not pass an API key in argv or the environment. `connect` reads it from the masked prompt, or from protected standard input when `--api-key-stdin` is explicitly used. If the `codex` profile already exists, skip its creation.

The plugin's fixed command is release-compatible and therefore does not enable literal HTTP loopback. Use the repository runtime helper directly with `--local-development` for separate localhost API diagnostics.

## Install from the local marketplace

From the `palladin-agent` repository root:

```bash
codex plugin marketplace add "$(pwd)"
codex plugin add palladin-agent@palladin-local
codex plugin list
```

Codex caches an installed plugin. After changing the generated target, update the Codex cachebuster in `generate-targets.mjs`, regenerate the targets, and reinstall the plugin. Start a new Codex thread after installation so the new skill and MCP process are loaded.

Verified Form Discovery Maps remain backend-owned. `inject_credential` resolves the map for the authenticated page origin through the backend and fails closed when no verified map exists; the plugin does not accept a caller-provided `form-json` fallback.
