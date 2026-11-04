# Key wrapper v1 fixtures

Byte-identical vendored copy of `contracts/key-wrapper/v1` from the public
[palladin-protocol](https://github.com/Palladin-io/palladin-protocol) repository
(pull request #18, commit `70f309d8beef49e1129fd155652ffc379ef26d89`). Replace the
files from the merged upstream commit before this runtime is released.

| File | SHA-256 |
| --- | --- |
| `v1/registry.json` | `511890576c74b1f78439e10838c4e074a80186179f9ca17f98fb754a84fa223e` |
| `v1/vectors.json` | `c5a3fa98287def283527d15407d6aa44fd034af7a6014785637df1e697c9b83a` |
| `v1/suites/palladin-x25519-sealed-box-v1.json` | `197ff3929b10e02c1aebc7e147088f187a18101f242546bf6b3b9645ef4bb0c7` |
| `v1/suites/palladin-xwing-v1.json` | `ffcd71cc171c70e9a0a2f3e5f2f85573946b1c300a906c583aeafc4c5d49d604` |

All keys and identifiers are deterministic synthetic test data. Do not edit these
files; replace them only from a new upstream commit and update the digests, which
`palladin-crypto/tests/key_wrapper_vectors.rs` verifies.
