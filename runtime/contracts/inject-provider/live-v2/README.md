# Private deferred credential fixtures

`deferred-submit.json` is byte-identical to the matching browser-extension
`tests/fixtures/protocol/deferred-live-v2.json` fixture, jointly authored during the
2026-09-20 deferred identifier implementation. All values are synthetic. This is
an additive private live contract, not a revision of the immutable v1 stored-map
contract or a production-page capture.

The four messages show fill, submit-ready, value-free commit, and best-effort
cancel. Native and extension parsers reject unknown keys and scope widening.
The scope handle in a v2 plan is not an existing button. The returned submit handle
uses the pending ID as its snapshot component and binds an actual native control.

`deferred-password.json` is byte-identical to the extension's
`tests/fixtures/protocol/deferred-password-v2.json`. Its `passwordOnly` and
`carriedUsername` examples extend the same four-message contract. Supported
ordered shapes are username, password, or username then password. Controls and
opaque handles are validated independently; arbitrary fields, duplicate handles
and cross-snapshot bindings are rejected. TOTP remains on v1.

A fresh password stage can follow a committed identifier stage in one call.
The current validated stage URL binds each pending commit, and submitted-field
tracking prevents replay even if the next discovery uses fresh handles. Field
writability is private extension state fixed at discovery, not a wire permission
to overwrite a carried username.
