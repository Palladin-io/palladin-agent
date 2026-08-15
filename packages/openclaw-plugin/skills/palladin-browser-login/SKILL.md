---
name: palladin-browser-login
description: Authenticate a retained OpenClaw Playwright browser session with an approved Palladin credential without exposing field values. Use for website sign-in, account login, credential discovery, one-step or multi-step login forms, cookie-banner preparation, and retrying a stale public form map through palladin_browser and palladin_inject.
---

# Palladin Browser Login

Use Palladin Discovery and the retained Playwright page. Never request, print, copy, or inspect a
credential value.

## Workflow

1. Identify the service and requested account from the user's instruction. Search Palladin by
   service plus username/email using the available Palladin Search/MCP surface. Do not hard-code a
   vault or Entry ID. `vaultId` and `entryId` are the Inject coordinates. `agentFields` contains
   public `{ label, value }` metadata for matching; it does not contain separate `id`/`fieldId`
   properties. When a Search page is too large for the tool output, filter that same fresh Search
   locally by `urlDomain` and `agentFields` instead of relying on a truncated model transcript. If
   Search returns multiple plausible accounts, ask the user which one.
2. Open the HTTPS login surface with `palladin_browser` action `open`. Keep its opaque `sessionId`
   for every later browser and Inject action. Do not use OpenClaw's separate `browser` tool for this
   flow because it owns a different page.
3. Snapshot the retained page. Dismiss only visible public overlays such as cookie consent through
   `palladin_browser` action `click`, then snapshot again. Complete ordinary public navigation
   before constructing the form.
4. If a CAPTCHA, 2FA challenge, passkey prompt, or account-recovery choice requires the user, keep
   the session open and request that exact action. Continue from the same `sessionId` afterward.
5. Build the complete value-free form definition before Inject:
   - include every ordered page/step, including username-then-password flows;
   - map only field IDs present in the authorized Entry schema to unique visible selectors;
   - for a standard Palladin Credential Entry, the built-in field IDs are
     `credential.username` and `credential.password`; use those exact IDs in the form and never
     expect Search to return the password field or a separate field-ID property;
   - treat `credential.urlDomain` as public origin metadata, never as a field to fill;
   - declare the submit/advance action for every step;
   - declare `waitFor` when the next public control appears after a transition;
   - include no field values, page scripts, cookies, storage, CDP endpoints, or browser commands.
6. Call `palladin_inject` with the Search result coordinates, a clear approval reason, the retained
   `sessionId`, and the complete form. Wait for approval according to the tool result; do not fall
   back to `get`, clipboard, environment variables, or manual value entry. Treat a structured
   `{ status: "failed", stage, code }` response as the authoritative terminal result. Report its
   exact bounded `stage` and `code`; never replace a known result with `unknown` and never retry a
   site failure automatically.
7. After Inject, snapshot the same session and verify only public success state such as the current
   URL or an authenticated navigation control. Do not read cookies, storage, hidden inputs, or
   populated field values. Leave the browser open for the user's next requested action.

## Failure Rules

- If a selector is missing, hidden, ambiguous, stale, or semantically wrong, stop Inject, snapshot
  again, and rebuild the complete public form definition.
- If the origin changes outside the credential's authenticated domain, stop and report it.
- If approval expires or is denied, report the bounded result and keep the page available.
- On `status: "failed"`, perform no further browser action unless the user explicitly requests it.
  Preserve the site's public error state for inspection. A public Discovery username may remain
  visible; password, OTP, and other secret fields must be cleared by the provider.
- Never claim login success from an `injected` result alone; confirm a public post-login state.
