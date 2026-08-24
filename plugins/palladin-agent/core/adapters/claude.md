# Claude Code browser handoff

This preview packages Palladin MCP and the shared login skill for Claude Code. Browser control is a
separate prerequisite: use only an external-browser integration that returns the native positive
WebExtensions tab ID and the exact current HTTPS URL from the same controlled tab object.

No Claude Code browser integration has passed the Palladin exact-tab acceptance gate yet. Until one
does, stop before Search/Inject rather than using Playwright session IDs, CDP targets, titles,
URL-only matching, the active tab, or a manually supplied number. The MCP package is valid, but that
does not by itself prove a safe browser handoff.
