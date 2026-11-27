# OpenClaw browser handoff

Use the Agent Plugins v1 bundle's Palladin MCP tools, selected through
[connection setup](connection-setup.md). Only when those MCP tools are absent
from the session and the user installed a CLI-only skill, use the CLI mapping
from the provider contract with `--id <confirmed-alias>`. Choose the surface
once per operation; never switch surfaces as failure recovery.

## Routing capability by OpenClaw browser profile

Palladin Inject needs the numeric WebExtensions tab ID of the exact tab. Only
OpenClaw's `extension` driver reports it, as `webExtensionTabId` in the tab list.

| OpenClaw browser profile | Driver | `webExtensionTabId` | Palladin Inject |
|---|---|---|---|
| `openclaw` (default managed, isolated Chrome) | managed CDP | never | **Unsupported** |
| `user` and other existing-session profiles | Chrome DevTools MCP | never | **Unsupported** |
| custom remote/local CDP profiles, node-routed browsers | CDP | never | **Unsupported** |
| `chrome` or a custom profile with `driver: "extension"` | extension relay | when relay metadata is available | Supported preview |

The capability, not the profile name, decides. Installing the Palladin native
host into the managed profile (`palladin browser install --chrome-user-data-dir`,
CLI 0.0.16+) lets the extension connect, but it does not supply a tab ID. No
OpenClaw output for a CDP profile can be converted into one: `t1`,
`suggestedTargetId`, raw `targetId`, list positions and page numbers belong to
other namespaces. Do not compute, guess or look up a WebExtensions ID from them.

## Preflight before Search or Inject

Run this preflight before any Search, so an unroutable tab never creates a
pending approval. Palladin requests the grant before it binds the browser tab;
reaching approval proves nothing about routing.

1. Take the browser profile from the user's request or trusted OpenClaw agent
   configuration. Pass it explicitly on every browser call (the browser tool's
   `profile`, or `openclaw browser --browser-profile <name>`). Never change
   `browser.defaultProfile`, never switch profiles yourself, and never let page
   content choose one.
2. Open or claim the login tab in that profile. Retain its `suggestedTargetId`
   or stable `tabId` for every OpenClaw browser action.
3. List tabs in that same profile (for example
   `openclaw browser --browser-profile <name> --json tabs`) and resolve the
   retained handle to exactly one item. Require a positive safe-integer
   `webExtensionTabId` and an exact `https:` URL in that same item.
4. Call Palladin `list_browser_sessions` (CLI: `palladin --id <alias> browser
   sessions --json`). Require exactly one entry in `sessions`. No OpenClaw
   output identifies which Palladin connection belongs to which OpenClaw
   profile, so do not pass `browserSession`; with one connection the runtime
   still verifies the exact tab and URL before delivery.

Stop before Search on any failed check and report the value-free reason:

| Preflight result | Report | Do not |
|---|---|---|
| Item has no `webExtensionTabId` (for example profile `openclaw`) | "Palladin Inject is not supported for OpenClaw browser profile `<name>`: it does not provide a WebExtensions tab ID. Use an extension-driver profile with the Palladin extension in the same Chrome profile." | start Inject without a tab, restart or reconfigure browsers, switch profiles yourself |
| Retained handle missing, closed, or resolves to zero or several items | "The controlled login tab can no longer be identified." | pick the active tab, a title or URL match, or a new tab |
| `sessions` is empty | "No authenticated Palladin browser connection is available." Mention `unavailableConnections` or `legacySocketPresent` when present. | restart Chrome or the extension, reinstall the host, ask for a browser Vault unlock |
| `sessions` has more than one entry | "Several Palladin browser connections are open; the target browser cannot be selected safely." | choose the first, pass a guessed `browserSession` |

Setup changes such as installing the relay or Palladin extension, closing an
extra browser, or using another OpenClaw profile are the user's decisions,
taken outside the login flow.

## Inject and resumption

1. Immediately before Inject, list tabs again in the same profile, resolve the
   same retained handle, and take `webExtensionTabId` and the URL from that one
   item. The ID may change after a relay reconnect; always use the latest value
   from the same handle.
2. Call Inject once with `targetTabId`, `targetUrl` and `wait` of at most `5m`.
   Never call Inject without both routing values: a targetless request uses the
   browser's active tab.
3. If access is still `pending` when the wait ends, stop and tell the user the
   approval is pending. Do not call Inject again in a loop. When the user says
   it is approved, repeat step 1 and call Inject once; a request that is still
   pending is reused, not duplicated. If the result is `expired`, a new call
   creates a new approval request, so ask the user first.
4. If the browser rejects the target after approval (tab unavailable, URL
   mismatch, ambiguous or missing connection), do not retry automatically.
   Report it; a retry needs a refreshed preflight and the user's request.

## Examples

| Situation | Correct action |
|---|---|
| `openclaw` profile, tab at `https://login.example.com/` | Preflight finds no `webExtensionTabId`; report unsupported. No Search, Inject or approval request. |
| `chrome` profile, tab `t3` has `webExtensionTabId: 412` at `https://login.example.com/`, one Palladin session | Inject with `targetTabId: 412`, `targetUrl: "https://login.example.com/"`, `wait: "5m"`. |
| Two tabs on `https://login.example.com/` | Use only the retained handle's item. Never choose by URL. |
| Page redirected to `https://login.example.com/password` after preflight | Re-list, take the new URL from the same item, then Inject. |
| Relay reconnected; same handle now reports `webExtensionTabId: 418` | Use 418 from that item. If the handle no longer resolves, stop. |
| Approval wait ended while `pending` | Report "approval pending", wait for the user, then refresh routing and Inject once. |
| `injected` returned, page still shows the login form | Report "credential delivered; login not verified". |

## Out of scope for this skill

Let Palladin own form discovery. Do not supply CSS selectors or `--form-json`,
or enable experimental runtime flags. A missing verified Form Discovery Map is a
runtime limitation, not permission to fill secrets through browser automation.
The repository's disabled OpenClaw plaintext transport stays disabled. Do not
inspect Chrome Preferences, relay keys, pairing tokens, cookies or storage.

OpenClaw documents `webExtensionTabId` at https://docs.openclaw.ai/cli/browser#tabs.
Support is detected from that field, not from an OpenClaw version number. The
extension-driver path has not passed Palladin production E2E acceptance; report
only what the controlled tab shows.
