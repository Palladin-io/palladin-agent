# OpenClaw browser handoff

This is an Agent Plugins v1 compatible bundle for OpenClaw. Its skill and stdio MCP server are the
supported plugin boundary; it does not load the repository's disabled native OpenClaw/Playwright
fixture and must never reactivate its rejected plaintext transport.

Use an OpenClaw browser operation only if it returns a native positive WebExtensions tab ID and the
exact current HTTPS URL from the same retained tab. No OpenClaw adapter has passed that acceptance
gate yet. Until it does, stop before Search/Inject. Do not substitute an opaque session ID, CDP
target, title, URL-only match, active tab, or a second Playwright-owned browser.
