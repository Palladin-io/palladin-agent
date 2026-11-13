# Browser capture submissions (CVT-641)

This unreleased feature proposes browser fields for human Inbox review. It never prints the captured values. The runtime, extension, and v2-capable review panel must be deployed together. Existing payload v1 stays unchanged.

## CLI

Run `palladin --id agent-profile browser sessions --json` to discover current authenticated browser session identifiers. With two or more browsers, pass the intended opaque `browserSession` identifier as `--browser-session <identifier>` alongside `--from-browser`. Display names and tab IDs do not select a browser. The same tab ID and URL can exist in several browsers.

Selection is verified against authenticated `browser.status` on the same connection used for preparation and capture. A missing, stale, disconnected, or mismatched selected session fails closed; it never falls back to another browser. Reconnects require rediscovery and a new selection. Omitting the selector is supported only when exactly one browser connection is available.

```sh
palladin --id agent-profile submit new --type credential \
  --label 'Deployment account' --description 'Used by the release service' \
  --from-browser '{"targetTabId":7,"targetUrl":"https://example.test/account","fields":[{"entryFieldId":"username","selector":"#username","read":"value"},{"entryFieldId":"password","selector":"#password","read":"value"}]}' \
  --json
```

The plan contains routing metadata only. Do not put field values into it. Supported reads are `value` on ordinary form controls and `textContent` on supported text elements. Each selector must identify exactly one visible element in the prepared top-level document. All declared fields are required to exist; empty strings are handled by the entry schema. A changed tab, document, URL, missing/ambiguous selector, timeout, cancellation, or invalid response rejects the operation atomically.

For an update, use `submit update --type credential --vault <vault-uuid> --entry <entry-uuid> --from-browser <plan>`. Omit fields to preserve them. The runtime retains active-grant and revision checks. The panel must review all proposed fields before encrypting the replacement and retaining existing field policies. No deletion operation is exposed. An explicitly captured empty string clears only fields allowed by the v2 schema.

Only `--label` and `--description` are agent-supplied literal entry values. `--username`, `--url`, `--generate`, `--from-prompt`, and password-generation options conflict with `--from-browser`. Prompt and generation flows retain their existing v1 semantics. Capture never bypasses a protected prompt.

Builtin capture IDs are `username`, `password` for Credential; `value` for Key; and `url`, `notes` for both. Other entry types fail closed.

Custom IDs use `custom:<RFC-4122-uuid>:<type>:value` and optionally `custom:<same-uuid>:<same-type>:label`. Types are `text`, `multiline`, `concealed`, or `totp`. A new custom field requires a captured label; an existing field can preserve its label. TOTP is captured as one structured JSON object and validated against the v2 TOTP schema, not executed. Custom labels are never accepted as agent literals.

## Security boundary

Capture runs in the extension isolated world and uses the existing authenticated encrypted native session. It is a dedicated `capture.result`, never a secret-bearing `inject.result`. A local capture-only preparation selects a one-shot route; there is no general CLI command returning raw captured values. Host replies are immediately re-encrypted to the authenticated local client. Captured buffers, including queued multiplex replies, are erased on drop as supported by the runtime. JavaScript immutable strings cannot be reliably zeroized and are not persisted.

The CLI prints only the usual submission status/reference. Actual values are encrypted for the trusted approver and agent recipient, then POSTed through the existing submission endpoint. Human approval in the panel remains required. No browser storage, cookie scan, arbitrary script, page-world bridge, telemetry, or file handoff is used.

## Current platform and release limits

- Native capture currently uses the existing Unix local socket implementation and supports explicit authenticated browser session selection. Without `--browser-session`, ambiguous sessions fail closed.
- Windows capture, Script/CreditCard, built-in TOTP fields, and deletion are not added.
- Existing v1 pending-submission injection does not open v2 payloads; that optional capability is a follow-up, not a plaintext fallback.
- The additive payload v2 uses the unchanged signed/encrypted v1 envelope. Older panels reject it. Publish the versioned contract and cross-client fixture with coordinated runtime/extension/panel releases.
- Automated tests use synthetic values. Real-site acceptance and coordinated deployment must happen before enabling this for actual credentials.
