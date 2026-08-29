# ADR 0003: Browser injection boundary

- Status: Superseded by ADR 0005 for authenticated providers; the caller-controlled CDP rejection remains accepted
- Date: 2026-07-13

## Context

The organization API key belongs to the organization and may be shared by multiple Agents. A specific Agent is identified separately by its Agent ID and X25519/Ed25519 key material. This decision does not change that identity model or the backend protocol.

The legacy client accepted a caller-provided Chrome DevTools Protocol endpoint. It obtained the page URL and performed the plaintext fill through that same unauthenticated endpoint. A fake CDP service can therefore report an allowed URL, emulate the required browser operations, and receive the credential. Loopback addressing and a registrable-domain comparison do not attest the browser or document.

## Decision

The legacy external-CDP injection path is disabled. Its compatibility CLI and MCP inputs remain
parseable, but the supplied endpoint is never contacted. That path rejects before resolving an
Agent profile; it never accesses the organization API key, requests a grant, delivers a credential,
or decrypts one. This decision does not disable the `Inject` grant method through an authenticated
provider defined by ADR 0005.

The production support matrix for the legacy caller-controlled CDP path is deliberately explicit:

| Operating system | Chrome / Chromium | Edge | Brave | Firefox | Safari |
| --- | --- | --- | --- | --- | --- |
| macOS | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported |
| Windows | Unsupported | Unsupported | Unsupported | Unsupported | N/A |
| Linux | Unsupported | Unsupported | Unsupported | Unsupported | N/A |

No injection diagnostics or stale-credential reports are produced on this path because no browser action and no secret delivery occurred. Errors contain only static, value-free text.

## Secure boundaries required for re-enablement

A future implementation must use one of two reviewed designs:

1. An Agent-owned Playwright `Page` passed directly to the reviewed embedded provider described by
   ADR 0005, with no caller-supplied port, WebSocket URL, or CDP endpoint.
2. A browser extension and native-messaging host where the runtime verifies the browser/platform-
   authored official extension identity, the local CLI authenticates the installation-scoped host,
   and authenticated encryption, freshness, replay protection, browser-owned document identity,
   and origin validation apply before every release.

Native Messaging by itself is not a same-user security boundary. A future design must also account for a malicious local process or an Agent controlling the same browser after a fill. Firefox requires its own extension/native host integration. Safari requires a signed containing application and Safari Web Extension, so it is not an npm-only path.

Any enabled implementation must bind release to HTTPS, a trusted backend-provided registrable domain, the top-level committed document, and a one-shot transaction. Navigation or document identity changes invalidate authorization. Diagnostics must never include field values, HTML, screenshots, URL path/query/fragment, or raw protocol traces.

## Consequences

- The fake-CDP plaintext exfiltration path is removed without changing the organization-wide API key or backend.
- Existing callers receive a deterministic exit/error rather than silently falling back to an unsafe browser connection.
- At the time of this ADR, browser injection remained unavailable pending a separately reviewed
  trust boundary. ADR 0005 records the authenticated provider boundary that enables `Inject` while
  preserving this ADR's rejection of caller-controlled CDP.
