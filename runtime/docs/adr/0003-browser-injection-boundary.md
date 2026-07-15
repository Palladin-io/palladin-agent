# ADR 0003: Browser injection boundary

- Status: Accepted
- Date: 2026-07-13
- Issue: CVT-316

## Context

The organization API key belongs to the organization and may be shared by multiple Agents. A specific Agent is identified separately by its Agent ID and X25519/Ed25519 key material. This decision does not change that identity model or the backend protocol.

The legacy client accepted a caller-provided Chrome DevTools Protocol endpoint. It obtained the page URL and performed the plaintext fill through that same unauthenticated endpoint. A fake CDP service can therefore report an allowed URL, emulate the required browser operations, and receive the credential. Loopback addressing and a registrable-domain comparison do not attest the browser or document.

## Decision

External CDP browser injection is disabled. The compatibility CLI and MCP inputs remain parseable, but the endpoint is never contacted. The CLI rejects before resolving an Agent profile. MCP may already hold an Agent session to serve its other tools, but the inject handler never accesses the organization API key, requests a grant, delivers a credential, or decrypts one.

The production support matrix is deliberately explicit:

| Operating system | Chrome / Chromium | Edge | Brave | Firefox | Safari |
| --- | --- | --- | --- | --- | --- |
| macOS | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported |
| Windows | Unsupported | Unsupported | Unsupported | Unsupported | N/A |
| Linux | Unsupported | Unsupported | Unsupported | Unsupported | N/A |

No injection diagnostics or stale-credential reports are produced on this path because no browser action and no secret delivery occurred. Errors contain only static, value-free text.

## Future secure boundaries

A future implementation must use one of two reviewed designs:

1. A Rust-runtime-managed Chromium-family process connected through a private inherited remote-debugging pipe, with no caller-supplied port, WebSocket URL, or endpoint.
2. A browser extension and native-messaging host with user-mediated pairing, installation-specific keys, authenticated encryption, freshness and replay protection, browser-owned document identity, and origin validation before every release.

Native Messaging by itself is not a same-user security boundary. A future design must also account for a malicious local process or an Agent controlling the same browser after a fill. Firefox requires its own extension/native host integration. Safari requires a signed containing application and Safari Web Extension, so it is not an npm-only path.

Any enabled implementation must bind release to HTTPS, a trusted backend-provided registrable domain, the top-level committed document, and a one-shot transaction. Navigation or document identity changes invalidate authorization. Diagnostics must never include field values, HTML, screenshots, URL path/query/fragment, or raw protocol traces.

## Consequences

- The fake-CDP plaintext exfiltration path is removed without changing the organization-wide API key or backend.
- Existing callers receive a deterministic exit/error rather than silently falling back to an unsafe browser connection.
- Browser injection remains unavailable until its cross-platform client component has a separately reviewed trust boundary.
