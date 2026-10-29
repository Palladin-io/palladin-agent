# Agent Submission v1 fixtures

Byte-identical vendored copy of `contracts/agent-submission/v1/contract.json` and
`v1/fixture.json` from the public
[palladin-protocol](https://github.com/Palladin-io/palladin-protocol) repository
(branch `feat/cvt-627-agent-submission-contract`, commit `41792ea`).

| File | SHA-256 |
| --- | --- |
| `v1/contract.json` | `998190ba37499981275679e2d40535816203062736fc5fcc4ede4fe3025aceba` |
| `v1/fixture.json` | `4778ca29b0bee27e8d73c71838f9c51d51ecd59962f7f263272370e53dcf4101` |

All keys, nonces and secrets are deterministic synthetic test data and are invalid
outside conformance tests. Do not edit these files; replace them only from a new
upstream commit and update the digests, which
`palladin-crypto/tests/agent_submission_vectors.rs` verifies.
