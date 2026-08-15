# Palladin AgentBrowser MCP provider

This package composes AgentBrowser's public MCP server with Palladin's
`inject_credential` tool. It uses the owner-only local AgentBrowser daemon channel for the
secret-bearing fill, so credentials never enter argv or model-visible MCP results.

No browser extension is used. Streaming must be disabled during Inject, and Windows remains
fail-closed until AgentBrowser exposes an authenticated local pipe instead of loopback TCP.

Configure this server in Codex, Claude, or any MCP client in place of the plain AgentBrowser MCP
server. It proxies the official navigation tools and adds one value-free `inject_credential` tool;
the MCP client is only a caller and never receives the credential.

Before calling `inject_credential`, the Agent skill must prepare the public login surface: dismiss
cookie/consent overlays, complete public navigation, pause for a human CAPTCHA if shown, and inspect
the complete one- or multi-step form. The form definition is value-free and must include every step,
field mapping, transition, and submit action before the CLI is invoked.
