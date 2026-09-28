# OpenClaw browser handoff

Use the Agent Plugins v1 bundle's MCP connection, selected through
[connection setup](connection-setup.md). A separately installed CLI-only skill
may use the same documented CLI contract with an explicitly selected profile;
do not switch credential surfaces as failure recovery.

Use a Chrome browser profile whose OpenClaw driver is `extension`, with both the
OpenClaw relay and Palladin installed in that same browser profile. Retain the
OpenClaw `suggestedTargetId` or stable `tabId` from opening/claiming the tab.
Immediately before Inject, list tabs in that same profile and resolve the retained
handle to exactly one current item. Take its exact HTTPS URL and positive
safe-integer `webExtensionTabId` together. Pass that numeric field only to Palladin;
continue to use the OpenClaw handle for browser actions.

The `user` existing-session and managed/imported CDP drivers do not supply this
WebExtensions handoff. Never substitute `t1`, a Chrome MCP page number, raw CDP
target, list index, active tab or title/URL matching. Refresh routing after
navigation, grant approval, user handoff or relay reconnect. If continuity of
the original controlled tab is lost, stop rather than retargeting the secret.

A missing numeric field or disconnected relay blocks Inject, not Agent selection
or pairing. Diagnose the selected browser profile and value-free relay status;
installation alone does not prove connection. Do not inspect Chrome Preferences,
relay keys, pairing tokens, cookies or storage. Do not require a browser Vault
unlock for Agent Inject or restart every browser session as automatic recovery.

Let Palladin own form discovery. Do not supply generated CSS selectors or
`--form-json`, or enable experimental runtime flags from this production skill.
Missing supported discovery is a runtime capability limitation, not permission
to fill secrets using browser automation. The repository's disabled OpenClaw
plaintext transport remains disabled.

OpenClaw documents this routing at https://docs.openclaw.ai/cli/browser#tabs.
The documented field is a prerequisite, not proof of this plugin's production
E2E acceptance; verify success in the controlled tab and report actual results.
