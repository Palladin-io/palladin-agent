# Codex Chrome handoff

Use Codex's Chrome browser-control surface and the user's connected external Chrome. Do not use the
in-app browser, a standalone Playwright process, raw CDP, or a second browser profile for Palladin
Inject.

Keep the `Tab` object returned when Codex opens or claims the login tab. Immediately before calling
Inject:

1. read `targetUrl` with `await tab.url()` and require an exact `https:` URL;
2. parse `tab.id` as `targetTabId` and require a positive `Number.isSafeInteger` value;
3. pass both values from that same `Tab` object to Palladin.

After any navigation, challenge, or user handoff, read both values again from the same controlled
tab. If the `Tab` reference is lost, stale, closed, belongs to another browser binding, or does not
have a numeric WebExtensions ID, stop. Do not recover by selecting the active tab or matching only
the title or URL.
