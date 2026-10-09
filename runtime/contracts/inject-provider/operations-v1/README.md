# Concurrent Inject operations, version 1

This capability extends the existing authenticated `palladin.inject-provider.v1`
secure channel. It does not replace its identity, signature, sequence, origin,
document, grant, expiry, or replay checks. No plaintext envelope travels outside
the encrypted channel.

Before publishing a browser-session socket, the host sends `operation.hello`
with `version: 1`. The extension replies `operation.ready` with the same version.
`negotiation.json` is the shared value-free fixture consumed by the Rust host and
the extension runtime tests. The extension copy lives at
`tests/fixtures/protocol/operation-negotiation-v1.json`; copy it byte-for-byte
when changing the contract. Unknown versions or fields are rejected. Only the
exact legacy unknown-message rejection selects serial operation; a transport
failure or arbitrary rejection must not trigger downgrade.

Once negotiated, host requests use:

```json
{"protocol":"palladin.inject-provider.v1","type":"operation.request","operationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request":{"protocol":"palladin.inject-provider.v1","type":"prepare","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","targetTabId":7,"targetUrl":"https://login.example.test/"}}
```

The extension wraps the unchanged provider reply in `operation.result` with the
same operation ID and a `response` property. IDs are host-generated 128-bit
random values encoded as 32 lowercase hexadecimal characters. They are routing
identifiers, not credential or origin authority. One request may be outstanding
per operation; different operations may finish out of order. Secure frame
sequence numbers remain global to the connection and are never reused.

A first preparation reserves its exact tab before asynchronous page inspection.
A second operation targeting that tab receives `target-tab-busy` before any
credential acquisition. An operation cannot retarget itself. Explicit targets
never fall back to the active tab. The legacy CLI mode without any target
resolves the active tab once, then pins that tab and URL.

The host ends an operation with `operation.close` and no request payload. The
extension stops subsequent writes, waits for in-flight work and pending deferred
submission cleanup, releases the tab, then returns `operation.closed`. Both
messages carry the protocol and operation ID. A canceled request may return its
result before the close acknowledgement or omit it; `operation.closed` is
terminal and no result may follow it. Closing an unknown/already closed
operation is idempotent. The host retains admission capacity until authenticated
acknowledgement; a missing acknowledgement terminates the stale connection after
the cleanup deadline. Neither side replays credential delivery or submission.

At most 32 active/closing operations are admitted. The extension expires an
operation after six minutes; the native host bounds individual exchanges and
checks credential authorization expiry immediately before sealing a queued
request. Cancelling one local client closes only its operation. Corrupt framing,
wrong secure sequence, or an uncorrelated response invalidates the connection.

Browser-session discovery is a separate authenticated local-IPC query. It does
not start an extension operation, enumerate pages, or select a Chrome profile.
Session identifiers expire with the native connection. A trusted browser adapter
supplies a fresh exact tab ID and URL. Without an explicit browser session, the
runtime sends a `target.probe` on each live candidate connection and selects only
a unique match. This request carries the protocol, a nonce, `targetTabId`, and
`targetUrl`. The authenticated `target.probe.result` echoes the nonce and returns
only `match`, `no-match`, or `unavailable`. Probes create no tab reservation and
never enter credential delivery. Missing, ambiguous, or incomplete resolution
stops before preparation/decryption; the selected connection is then prepared
again to pin its current document. Never guess among ambiguous connections.

These are protocol fixtures and synthetic tests, not evidence that real Chrome
profiles or live websites have passed the end-to-end acceptance gate.
