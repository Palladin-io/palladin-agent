# Palladin Playwright MCP provider

This development package composes the official Playwright MCP server with Palladin's
`inject_credential` tool. The credential is transferred through private process pipes,
filled by Playwright, and never returned in MCP tool results or model-visible arguments.

The pipe protocol does not authenticate the provider process and is therefore enabled only by a
Rust runtime compiled with `--features local-development`. Production runtimes reject it before
opening a profile or decrypting a credential. Publishing this provider requires a separately
reviewed one-shot provider capability; a hidden CLI flag, nonce, or private pipe is not sufficient.

It uses no browser extension. Install it at the exact same version as `@palladin/agent`.

Configure this server in Codex, Claude, or any MCP client in place of the plain Playwright MCP
server. It proxies the official navigation tools and adds one value-free `inject_credential` tool;
the MCP client is only a caller and never receives the credential.

For local development, set `PALLADIN_AGENT_PACKAGE_ROOT` to the checked-out `@palladin/agent`
package root. The launcher still requires the exact package identity and performs its normal
runtime integrity/version-policy checks; this variable only selects the local package checkout.
If the MCP host resolves packages from another directory, set `PALLADIN_AGENT_LAUNCHER` to the
absolute path of `dist/bin/palladin.js` in that checkout.

Before calling `inject_credential`, the Agent skill must prepare the public login surface: dismiss
cookie/consent overlays, complete public navigation, pause for a human CAPTCHA if shown, and inspect
the complete one- or multi-step form. The form definition is value-free and must include every step,
field mapping, transition, and submit action before the CLI is invoked.

For an agent that already owns a Playwright `Page`, import `injectExistingPlaywrightPage` from
`@palladin/playwright-mcp/embedded`. This is the supported OpenClaw/Claude/Codex integration path.
It operates in-process against that exact page; it does not launch a browser, create a context, or
accept a CDP endpoint. An ordinary `BrowserServer.wsEndpoint()` does not expose contexts/pages
created by another Playwright connection, so a separate CLI process cannot recover the same `Page`
from endpoint coordinates. The standalone MCP executable is only for clients that want the
official Playwright MCP server to own the browser.
