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
npm ci --workspaces=false
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
- PR titles, descriptions, review comments, and commit messages are written in English.
- PR review and remediation automation is Codex-only. Use `.agents/skills/pr-review/SKILL.md` for reviews and `.agents/skills/fix-pr/SKILL.md` for feedback implementation. Do not add Claude Code PR workflows or `.claude/skills/pr-review` / `.claude/skills/fix-pr` adapters.

## Bounded Pull Request Review

Official Codex review is a bounded release gate, not an iterative design loop.

- Request the first official review only after the scoped implementation is complete, local validation passes, and CI is green.
- Batch all accepted findings into one remediation pass; do not run a separate review after each comment or commit.
- Run at most two standard official review rounds. A third round is allowed only to verify a concrete P0/P1 fix involving security, authorization, data integrity, atomicity, or material performance. Any further round requires explicit product-owner approval.
- Treat review comments critically. Before changing code, identify the reproducible production scenario, verify that the current code permits it, and confirm that the fix belongs to the issue's acceptance criteria.
- P0/P1 findings in scope are blocking. Fix a P2 only when it is real, in scope, and small; otherwise document it or create a follow-up. Do not expand the PR for P3/style feedback, speculative edge cases, or unrelated architecture work.
- A review comment does not expand Linear scope by itself. If remediation would introduce a subsystem, broad abstraction, or substantial diff growth, stop and move it to a follow-up unless it closes a confirmed P0/P1.
- Inspect CI status first. Fetch logs only for failed checks, and then only the failing step and necessary surrounding context.
- Stop the review loop when CI is green, no unresolved in-scope P0/P1 remains, and lower-severity findings are either addressed or explicitly dispositioned.

## Maintaining instruction files

`AGENTS.md` and `CLAUDE.md` are intentionally maintained as complete, byte-for-byte identical copies by product-owner decision. Every instruction change must update both files in the same commit and verify them with `cmp`.
