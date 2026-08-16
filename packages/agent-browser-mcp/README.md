# Palladin AgentBrowser MCP provider

This package composes AgentBrowser's public MCP navigation server with a fail-closed Palladin
`inject_credential` tool. AgentBrowser 0.33.2 cannot bind its final secret text insertion to the
element selected for fill: page focus handlers can redirect the insertion to another control.
Palladin therefore returns `provider-unavailable` before requesting a grant, spawning a runtime,
or sending any secret-bearing AgentBrowser daemon command. This applies in every build, including
local development. The public navigation proxy still uses AgentBrowser's ordinary daemon channel.

No browser extension or secret transport is used by this package. Production support requires an
upstream atomic, session-authenticated fill primitive that binds the inserted text to the attested
element; filesystem ownership, version checks, and selector validation are insufficient.

Configure this server in Codex, Claude, or any MCP client in place of the plain AgentBrowser MCP
server. It proxies the official navigation tools and adds one value-free `inject_credential` tool
that always reports the unavailable provider. The MCP client never receives a credential.
