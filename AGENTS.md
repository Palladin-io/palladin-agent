# Palladin Agent CLI

TypeScript CLI and MCP server for Palladin. It manages agent identities, authenticates with the backend, requests credential grants, and exposes vault operations to AI assistants.

## Security

Security violations are blocking findings.

- Never print, log, return, or persist plaintext credentials unnecessarily.
- Never log private keys, API keys, access tokens, passwords, or injected secrets.
- Private keys use the platform keychain when available. File fallback must use mode `0o600`.
- `@napi-rs/keyring` is optional. Dynamic imports and keychain operations must fail gracefully and fall back safely.
- Commands that use secrets should prefer the existing `exec` and `inject` flows instead of exposing plaintext.
- Do not weaken origin checks, approval checks, masking, or grant-method enforcement.

## Project Conventions

- Node.js 20 or newer, ESM, strict TypeScript.
- No `any`; use typed interfaces or `unknown` with narrowing.
- Do not use non-null assertions for values that can be absent.
- All profile-aware commands use `getProfile()`; never hardcode `~/.palladin/`.
- Registry changes go through the existing registry helper functions.
- Preserve actionable CLI errors and consistent non-zero exit codes for failures.
- Keep user-facing CLI output in English.
- Avoid speculative abstractions and reuse existing helpers.

## Commands

```bash
npm ci
npm run lint
npm run build
npm test
```

Run lint, build, and relevant tests before finishing code changes.

## Pull Requests

- All changes go through pull requests.
- PR titles, descriptions, review comments, and commit messages are written in Polish.
- Use `.agents/skills/pr-review/SKILL.md` for PR reviews.
- Use `.agents/skills/fix-pr/SKILL.md` for implementing review feedback.
