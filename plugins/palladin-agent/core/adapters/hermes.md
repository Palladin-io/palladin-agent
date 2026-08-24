# Hermes browser handoff

This is an Agent Plugins v1 package for Hermes. Hermes loads the shared skill and starts the native
Palladin stdio MCP server; neither component is itself a browser provider.

Use a Hermes browser integration only if it returns a native positive WebExtensions tab ID and the
exact current HTTPS URL from the same controlled external-browser tab. No Hermes adapter has passed
that acceptance gate yet. Until it does, stop before Search/Inject. Do not substitute browser text,
an opaque session or CDP target, title/URL heuristics, the active tab, or a separately launched
browser.
