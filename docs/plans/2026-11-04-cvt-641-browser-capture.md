# CVT-641 browser capture

## Agreed requirements

CLI starts a bounded, generic capture of declared fields in one exact HTTPS tab/document. The extension reads input values or element text in the isolated world, returns them only over the existing authenticated encrypted native connection, and the runtime creates an encrypted submission for human Inbox review. The agent may supply literal name/description only; all other field values originate in the browser. Missing/ambiguous required fields abort atomically. Updates preserve omitted fields and existing grant/revision checks.

## Implementation

1. A dedicated `capture` / `capture.result` exchange after exact-target preparation; never add secret values to `inject.result`.
2. Typed declarative field locators, 1–32 fields, unique IDs/selectors, no JS, 64 KiB maximum value and 256 KiB total response. Correlation, HTTPS target, document identity, operation lifetime and cancellation remain mandatory.
3. Host and CLI buffers are zeroized on drop; no secret Debug or user output. The host immediately reseals responses for the authorized local operation.
4. Frozen submission v1 accepts only Credential/Key, mandatory password/value, and no description/custom fields. A coordinated new protocol version and web reviewer are required for generic sparse fields; never weaken the v1 parser or claim full support before this integration is tested.

## Checkpoint

- Linear CVT-641 updated to Coding with owner decisions.
- Isolated branches `feat/cvt-641-browser-capture` in `palladin-cvt-641-agent` and `palladin-cvt-641-extension`.
- Agent baseline CLI submission parser: 5 passed.
- Extension implementation delegated with agreed transport schema.
- Next: contract rejection tests, authenticated host round trip, then payload version integration.
- No live accounts, profiles, debug installation, tokens or production state changed.

## Implemented checkpoint

- Dedicated native capture route, exact local preparation, encrypted one-shot response and zeroizing queued multiplex responses.
- `submit new/update --from-browser` with label/description-only literals and typed field mapping; no raw capture output command.
- Additive encrypted payload v2, untouched v1 vectors, sparse update and custom field validation. CLI/bridge package suites pass.
- Extension full tests: 237 files / 3908 tests; all target builds pass.
- Runtime capture trust/revision tests and web complete-review/parser/merge validation underway. Cross-language v2 fixture requested.
- Script/CreditCard and Windows capture explicitly unsupported. Production acceptance/deployment and public protocol publication remain separate steps.

## Validation and review

- Final Rust tests passed for palladin-cli, palladin-runtime, palladin-crypto and palladin-browser-bridge (`--lib --tests --locked`), including captured submission trust/revision tests and shared v2 fixture.
- Clippy for all targets of those four packages passed with warnings denied; rustfmt and git diff whitespace checks passed.
- Launcher npm lint/build passed. npm tests: 70 files, 707 passing, 2 skipped; release security tests: 41 passing, 4 packaging skips.
- Independent source review found one sparse-update-to-new-entry completeness issue; web builder and UI now reject incomplete conversion and regression tests cover it. Follow-up review found no remaining confirmed findings.
- Official protocol draft: https://github.com/Palladin-io/palladin-protocol/pull/19.
- No merge, deployment, real-site capture, profile mutation or installed debug runtime change was performed.
