# Palladin Browser Inject for OpenClaw

This development OpenClaw plugin owns the Playwright browser and keeps ordinary browser
control and Palladin Inject on the same `Page`. It embeds the generic
`@palladin/playwright-mcp/embedded` adapter; Palladin does not start a second
browser or call OpenClaw's Gateway browser API. OpenClaw sees only public page
structure, the value-free form definition, Entry identifiers and the final
Inject status. Credential values travel from the native Palladin runtime to
the embedded provider over private child-process pipes and are never returned
as tool input or output. The current child-process pipe authenticates neither endpoint, so a
production Palladin runtime rejects this provider before opening a profile or decrypting a
credential. It is enabled only in an explicit `local-development` runtime until the one-shot
provider capability described in ADR 0005 is implemented.

The intended flow is:

1. Call `palladin search` (or the Palladin MCP Search tool) to discover the
   matching Entry without hard-coding its IDs.
2. Use `palladin_browser` with `action: "open"`, then dismiss public cookie and
   consent controls and inspect the login surface with `action: "snapshot"`.
3. Build the complete value-free, one- or multi-step form definition.
4. Call `palladin_inject`. It waits for approval, fills the same page and
   submits it. The browser stays open for the Agent's next action.

Do not use OpenClaw's separate built-in `browser` tool for this flow: it owns a
different browser session. The Palladin plugin intentionally exposes both
`palladin_browser` and `palladin_inject` so the page identity is unambiguous.

This host binding is thin and Open/Closed: another Agent that already has a
Playwright `Page` imports the same embedded adapter and does not implement a
new credential protocol.

OpenClaw is an optional peer supplied by the host installation. This repository intentionally does
not install the full OpenClaw package into its lockfiles: the current upstream shrinkwrap pins a
vulnerable transitive dependency. Compile-time compatibility is checked against the narrow
`plugin-sdk/tool-plugin` declaration and the test shim; host integration remains a separate
release gate.

For this repository checkout, configure `agentPackageRoot` with the absolute
path to the active `@palladin/agent` worktree. The adapter validates the exact
package name/version and keeps the launcher inside that root; it does not use
an arbitrary executable from `PATH`.

## Build

```bash
npm ci --ignore-scripts --workspaces=true --include-workspace-root
npm run build
npm run --workspaces=true --workspace packages/openclaw-plugin build
npm run --workspaces=true --workspace packages/openclaw-plugin test
```
