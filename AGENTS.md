# Palladin Agent

Public npm launcher and native Rust CLI/MCP runtime for Palladin. The Node entry point only locates and spawns an exact-version platform runtime; secret-bearing behavior belongs to Rust.

## Security

Security violations are blocking findings.

- Never print, log, return, or persist plaintext credentials unnecessarily.
- Never log private keys, API keys, access tokens, passwords, or injected secrets.
- The API key belongs to the organization and may be shared by multiple Agents. `agentId`, X25519, and Ed25519 identify an individual Agent; do not introduce API keys per Agent.
- The public Node launcher must never read secure storage, API keys, private keys, decrypted credentials, or public profile state.
- Native secret storage fails closed. There is no file, environment-variable, TypeScript, Login Keychain, or weaker-store fallback from a Hardened build.
- macOS Hardened storage uses a signed/provisioned app bundle, one fixed Data Protection Keychain access group, non-synchronizable `WhenUnlockedThisDeviceOnly` items, and user presence for the organization credential.
- An unsigned, modified, wrongly entitled, or differently signed runtime must never report `Hardened` and must not open identity.
- Commands that use secrets should prefer the existing `exec` and `inject` flows instead of exposing plaintext.
- Do not weaken origin checks, approval checks, masking, or grant-method enforcement.

## Project Conventions

- Rust 1.97 and Node.js 20 or newer; ESM and strict TypeScript for the dispatcher/tests.
- No `any`; use typed interfaces or `unknown` with narrowing.
- Do not use non-null assertions for values that can be absent.
- Node resolves only the exact platform package and fixed executable path, spawns without a shell, and has no PATH/download/legacy fallback.
- Native registry changes go through `ProfileRepository`; profile aliases never own or rename secret slots.
- Platform npm packages have no install lifecycle scripts. Signing and notarization run only in the owner-dispatched protected workflow.
- Preserve actionable CLI errors and consistent non-zero exit codes for failures.
- Keep user-facing CLI output in English.
- Avoid speculative abstractions and reuse existing helpers.

## Commands

```bash
npm ci
npm run lint
npm run build
npm test

cd runtime
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Run lint, build, and relevant tests before finishing code changes.

## Pull Requests

- All changes go through pull requests.
- PR titles, descriptions, review comments, and commit messages are written in Polish.
- Use `.agents/skills/pr-review/SKILL.md` for PR reviews.
- Use `.agents/skills/fix-pr/SKILL.md` for implementing review feedback.

## Maintaining instruction files

`AGENTS.md` and `CLAUDE.md` are intentionally maintained as complete, byte-for-byte identical copies by product-owner decision. Every instruction change must update both files in the same commit and verify them with `cmp`.
