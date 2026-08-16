# Palladin Browser Inject for OpenClaw (disabled fixture)

This unshipped plugin is retained for non-secret build and compatibility fixtures. Its embedded
Playwright path depends on the unauthenticated `--provider-transport-stdio` flow, which the Rust CLI
rejects in every build before profile, grant, runtime session, or credential access. It is not
enabled by `local-development` and must not be configured as an Inject provider.

The historical intended flow was:

1. Call `palladin search` (or the Palladin MCP Search tool) to discover the
   matching Entry without hard-coding its IDs.
2. Use `palladin_browser` with `action: "open"`, then dismiss public cookie and
   consent controls and inspect the login surface with `action: "snapshot"`.
3. Build the complete value-free, one- or multi-step form definition.
4. Call `palladin_inject`; this now fails closed without requesting a grant or credential.

Shipping an OpenClaw provider requires a separately reviewed authenticated one-shot transport and
atomic element-bound fill primitive. The only code-enabled browser Inject direction is the
authenticated macOS Chrome extension route.

OpenClaw is an optional peer supplied by the host installation. This repository intentionally does
not install the full OpenClaw package into its lockfiles: the current upstream shrinkwrap pins a
vulnerable transitive dependency. Compile-time compatibility is checked against the narrow
`plugin-sdk/tool-plugin` declaration and the test shim; host integration remains a separate
release gate.

## Build

```bash
npm ci --ignore-scripts --workspaces=true --include-workspace-root
npm run build
npm run --workspaces=true --workspace packages/openclaw-plugin build
npm run --workspaces=true --workspace packages/openclaw-plugin test
```
