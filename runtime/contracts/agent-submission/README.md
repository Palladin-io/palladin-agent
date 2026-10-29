# Agent Submission v1 fixtures

Byte-identical vendored copy of `contracts/agent-submission/v1/contract.json` and
`v1/fixture.json` from the public
[palladin-protocol](https://github.com/Palladin-io/palladin-protocol) repository
(branch `feat/cvt-627-agent-submission-contract`, commit `e6e7195`).

| File | SHA-256 |
| --- | --- |
| `v1/contract.json` | `21a40ebb4366d3559deaeccd4675470e1b07ab384b9ca45d3004c509a97a246a` |
| `v1/fixture.json` | `4778ca29b0bee27e8d73c71838f9c51d51ecd59962f7f263272370e53dcf4101` |

All keys, nonces and secrets are deterministic synthetic test data and are invalid
outside conformance tests. Do not edit these files; replace them only from a new
upstream commit and update the digests, which
`palladin-crypto/tests/agent_submission_vectors.rs` verifies.
