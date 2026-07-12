# Palladin native runtime

The Rust workspace is the secret-owning runtime boundary. The public Node package may eventually select and spawn a version-matched binary, but it must never load these crates into Node or pass identity material in arguments or environment variables.

## Crates

- `palladin-core`: secret wrappers, redacted panic handling, dangerous-environment policy, and atomic public JSON stores.
- `palladin-platform`: compile-time platform adapter and Palladin data location. It does not load code from the current working directory.
- `palladin-cli`: standalone `palladin` binary. CVT-309 provides `--version` and `doctor`; later tasks add the frozen v1 command contract.

## Security invariants

- Secret values use `secrecy` and `zeroize`; their debug representation is redacted.
- Panic output is fixed text and never includes a payload, argument, path, or secret.
- The launcher must remove loader injection variables before `exec`; direct invocation with `LD_*`/`DYLD_*` is already outside the runtime's control because the OS loader acts before `main` and may execute code or print its own diagnostics. If `main` is reached, the runtime guard prevents future identity-owning handlers from proceeding when loader/Node injection variables, TLS trust-store overrides, or legacy secret environment variables are present. Palladin-authored `doctor` output reports variable names only, never values.
- Public registry/config schemas contain no API key or private-key fields, reject unknown fields, and are written through a same-directory temporary file followed by flush, `fsync`, and atomic persistence.
- On Unix, the public data root comes from the current OS account record (`getpwuid_r` through a safe wrapper), not `$HOME`; on Windows it comes from the Profile known folder. The runtime never discovers plugins, libraries, config, or scripts from the caller's current directory.

## Target policy

| Target | CVT-309 status |
|---|---|
| `aarch64-apple-darwin` | build |
| `x86_64-apple-darwin` | build |
| `x86_64-pc-windows-msvc` | build |
| `aarch64-pc-windows-msvc` | build |
| `x86_64-unknown-linux-gnu` | build |
| `aarch64-unknown-linux-gnu` | build with GNU cross-linker |
| `x86_64-unknown-linux-musl` | build with musl linker |
| `aarch64-unknown-linux-musl` | build with musl linker on a native Linux ARM64 runner |

CI builds and executes every target on a native runner matching its OS and architecture. CVT-320 still owns Alpine packaging and artifact compatibility tests; an unavailable or unproved artifact is unsupported, never silently replaced by a different target.

## Local checks

```bash
cd runtime
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p palladin-cli -- --version
cargo run -p palladin-cli -- doctor
```
