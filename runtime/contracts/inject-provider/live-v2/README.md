# Private deferred identifier fixture

`deferred-submit.json` is byte-identical to the matching browser-extension
`tests/fixtures/protocol/deferred-live-v2.json` fixture, jointly authored during the
2026-09-20 deferred identifier implementation. All values are synthetic. This is
an additive private live contract, not a revision of the immutable v1 stored-map
contract or a production-page capture.

The four messages show fill, submit-ready, value-free commit, and best-effort
cancel. Native and extension parsers reject unknown keys and scope widening.
The scope handle in a v2 plan is not an existing button. The returned submit handle
uses the pending ID as its snapshot component and binds an actual native control.

The approved first implementation supports one initial username-only deferred
stage. Password/TOTP and mixed deferred stages are deliberately rejected.
