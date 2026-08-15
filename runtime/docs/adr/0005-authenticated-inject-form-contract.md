# ADR 0005: Authenticated Inject and Agent-defined form contract

- Status: Accepted
- Date: 2026-08-11
- Supersedes: ADR 0003 only for authenticated browser providers

## Context

ADR 0003 correctly rejected caller-controlled CDP because a supplied endpoint cannot attest the
browser or document receiving plaintext. It was later misread as disabling the `Inject` grant
method itself.

`Inject` is the safe browser-login path: an Agent must be able to prepare a public login surface,
then let Palladin fill approved credential values without returning those values to the Agent,
model, MCP transcript, terminal, clipboard, argv, environment, or logs.

Browser providers cannot reliably infer every login flow. A login may use one form, multiple
same-document steps, full-document transitions, or additional approved Entry fields. The Agent
already controls public navigation and can inspect the form without seeing credential values.

## Decision

`Inject` is enabled only through an authenticated, registered browser provider. Caller-controlled
CDP remains disabled.

### Agent-owned Playwright Page transport

The Agent owns the browser process, `BrowserContext`, and `Page` used before and after Inject. A
reviewed Palladin adapter is embedded in that same trusted Agent process and receives the existing
Playwright `Page` object directly. The adapter starts the native Palladin runtime with private pipes,
performs the bounded fill/submit on that exact object, and returns only a value-free outcome. It
never launches a second browser or serializes the `Page` into model-visible data.

The public CLI/MCP contract never accepts a CDP HTTP/WebSocket URL, remote-debugging port, browser
process ID, or `connectOverCDP` target. A browser endpoint selected by the Agent cannot attest the
receiving browser and could impersonate Chrome to obtain plaintext. Attaching to an already-running
unmanaged Chrome therefore remains unsupported. Existing-profile injection uses the separately
authenticated extension/Native Messaging provider.

An ordinary `BrowserServer.wsEndpoint()` is not a substitute for the embedded adapter. Playwright
connections do not expose one client's non-persistent contexts and pages to another client, so an
endpoint plus a page index cannot identify the Agent's current `Page`. CDP can enumerate a Chromium
default context, but that would be Chromium-only and would restore the caller-controlled endpoint
boundary rejected by ADR 0003. The portable contract is therefore the in-process Playwright `Page`
capability, supported equally by Chromium, Firefox, and WebKit integrations.

This means Playwright can perform Inject without the Palladin extension: the runtime transfers the
approved values through private child-process pipes to the embedded Palladin Playwright adapter, and
that adapter writes them through the Agent's existing `Page` object.

The operation has two distinct phases:

1. The Agent prepares the public login surface with ordinary browser tools: it reaches the correct
   HTTPS login surface, dismisses cookie/consent overlays, completes allowed public navigation,
   pauses for any human CAPTCHA, then inspects its visible controls and builds a complete bounded,
   value-free form definition. The CLI is not called until this preparation phase is complete.
2. The native CLI/runtime requests or consumes the approved Inject grant, verifies and decrypts only
   the granted fields in native memory, and sends the definition plus those values to the selected
   provider over its reviewed private transport. The provider validates and executes the definition,
   then returns only a bounded result. The browser session remains available to the Agent.

The provider-neutral definition contains a version and an ordered list of one or more steps. A step
may contain:

- mappings from approved Entry field IDs to public control locators;
- one bounded submit/advance action: click a declared control or press Enter on a declared field;
- one bounded transition expectation, such as waiting for a declared public control in the same or
  a replacement top-level document.

The definition never contains a credential value, JavaScript, caller-selected page URL, CDP
endpoint, cookie/storage data, or arbitrary browser command. It is safe to appear in MCP arguments.
Credential values are never MCP arguments or results.

## Validation and execution rules

- Each locator must resolve to exactly one visible, enabled, semantically compatible control in the
  live top-level document. Password values may be written only to password controls.
- Each mapped field must exist in the approved delivery or in authenticated Discovery metadata
  explicitly allowed for Inject. An unknown, unapproved, or absent field fails closed.
- The provider verifies HTTPS and the runtime-authenticated Entry domain before every fill and
  submit, and again after every navigation or document replacement.
- A transition invalidates old control handles. The provider re-resolves only the next declared
  step in the original authenticated browser session.
- Missing, stale, hidden, ambiguous, or semantically invalid definitions fail closed. Providers do
  not guess a replacement form and do not fall back to `get`, clipboard, CDP, or model-visible
  output.
- No provider-specific form semantics enter grant, crypto, or backend code. New providers implement
  the same contract behind the existing registry.

## Required tests

One shared contract fixture set must cover:

- a combined single-step form;
- same-document and full-document multi-step forms;
- arbitrary ordered approved-field mappings;
- click and press-Enter submission;
- hidden, duplicate, stale, missing, and semantically incompatible controls;
- origin changes before fill, after advance, and before final submit;
- field IDs absent from the approved delivery;
- value-free MCP input/output and private secret transport;
- retention of the authenticated browser session after final submit.

Every provider must run the shared fixtures plus its transport-specific replay, ownership, version,
and end-to-end tests.

## Consequences

- Agents describe public browser structure; they never receive credential values.
- The native CLI/runtime remains the only component that retrieves and decrypts approved values.
- Form support scales through a provider-neutral declarative contract instead of Palladin hard-coded
  service rules or provider-specific extensions.
- The browser controller has authority over the authenticated session after login. This is an
  intentional capability of the approved Inject operation and remains inside the selected local
  provider trust boundary.
- A new Playwright-based Agent integrates by embedding the shared Page adapter. It does not require
  a provider-specific extension or changes to grant, crypto, backend, or form contracts.
