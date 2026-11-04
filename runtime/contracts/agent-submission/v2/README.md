# Agent submission payload v2 (CVT-641)

This additive payload schema is carried inside the unchanged v1 transport,
identity, AEAD, signatures and DEK wrappers. The encrypted payload schema is
`palladin.agent-submission-payload.v2`. Frozen v1 readers continue to reject it;
v2 approval requires a compatible panel. Existing v1 fixtures are unchanged.

Required top-level fields: `schema`, `identity`, `content`. Optional: `label`,
`description`. Identity must exactly match the authenticated transport identity.
Only Credential and Key are supported. Script and CreditCard are rejected.

New entries require label and credential username/password or key value. Updates
are sparse: absent fields retain current values. Updates require at least one
label, description, built-in field or custom-field change. Empty strings clear
string fields except label and credential HTTPS URL; required new values are
nonempty. Null built-in values and deletions are unsupported.

Content permits `username`, `password`, `url`, `notes`, `customFields` for
Credential and `value`, `url`, `notes`, `customFields` for Key. Unknown keys fail
closed at every level. Description maps to root MemberSecret description;
notes remains a distinct content field.

`customFields` contains at most 64 unique `{id,type,value,label?}` objects. IDs
are canonical lowercase `custom:<UUID>` with RFC4122 variant and versions 1–8.
The supported types are text, multiline and concealed (string values), and totp
(object value). Label is required for new submissions. When updating, omitted
labels retain the existing field's label; the approver rejects a new field ID
without a label or a type mismatch for an existing ID. Merge by ID preserves
all unspecified fields and existing visibility policy. A newly added custom
field starts with `never` Agent visibility. Submissions cannot change policy.

TOTP values require uppercase unpadded base32 `secret`, `algorithm` in
SHA1/SHA256/SHA512, `digits` 6 or 8, and `period` 15–120. Optional issuer/account
are strings or null. Unknown fields, invalid values and unknown types reject.

Limits in UTF-8 bytes: label 256, description/notes 8192, username 1024,
password 4096, key/custom string value 16384, URL 2048, custom label 128, TOTP
secret/issuer/account 1024. All strings are NFC; secrets are never normalized.
Total canonical plaintext is at most 32768 bytes, as in v1.

The model may supply only label and description literals. Every content value,
including usernames, URLs, notes, custom labels and custom values, comes from
protected browser capture. Field IDs/types are routing metadata. Neither
plaintext nor ciphertext is returned in MCP/tool results. The backend sees only
the existing encrypted v1 transport.

Authoritative draft: [palladin-protocol Agent submission payload v2](https://github.com/Palladin-io/palladin-protocol/blob/feat/cvt-641-submission-v2/contracts/agent-submission/v2/README.md).
The vendored deterministic fixture is byte-identical to that contract. Coordinate
protocol and reader review before enabling v2 producers; this is not a release
authorization.

## Synthetic cross-language fixture

`fixture.json` is generated only by `generate-fixture.mjs`; never edit it by hand.
With the root npm dependencies installed, regenerate using
`node runtime/contracts/agent-submission/v2/generate-fixture.mjs --write` and verify
without `--write`. The optional `--dependencies=/absolute/path/package.json`
selects an existing dependency installation for local generation. It must provide
`libsodium-wrappers` 0.8.4-compatible behavior.

The fixture deliberately reuses v1's synthetic identity and DEK wrappers, then
re-encrypts and signs the v2 payload with deterministic fixture-only material.
It proves both Rust and web readers accept sparse updates with description,
concealed and structured TOTP custom values while frozen v1 readers reject them.
Never use any fixture key, secret or nonce outside conformance tests.
