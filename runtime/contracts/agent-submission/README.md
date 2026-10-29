# Agent Submission v1 fixtures

Byte-identical vendored copy of `contracts/agent-submission/v1/contract.json` and
`v1/fixture.json` from the public
[palladin-protocol](https://github.com/Palladin-io/palladin-protocol) repository
(branch `feat/cvt-627-agent-submission-contract`, commit `597535b`).

| File | SHA-256 |
| --- | --- |
| `v1/contract.json` | `58995ee2a26c2b1dcb9c7248ee944aaeb62c4df44b9b7eaacd459ba89b12fb21` |
| `v1/fixture.json` | `4778ca29b0bee27e8d73c71838f9c51d51ecd59962f7f263272370e53dcf4101` |

All keys, nonces and secrets are deterministic synthetic test data and are invalid
outside conformance tests. Do not edit these files; replace them only from a new
upstream commit and update the digests, which
`palladin-crypto/tests/agent_submission_vectors.rs` verifies.
