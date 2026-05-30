# PR Review Criteria — Claw Vault Agent CLI

---

## 1. TypeScript Correctness

- **No `any`** — use `unknown` + narrowing or proper typed interfaces.
- **Async/await correctness** — functions that call `@napi-rs/keyring` or keychain ops must be `async`. Callers must `await` them. Missing `await` on keychain calls is a silent bug.
- **Optional dependency handling** — `@napi-rs/keyring` is optional. Dynamic `import('@napi-rs/keyring')` must be wrapped in `try/catch`; failure must gracefully fall back to the next tier, never throw.
- **No non-null assertions (`!`)** on values that can be null (e.g. keychain returns `null` when key not found).
- **`process.exit` codes** — `0` for success, `1` for user errors, `1` for unrecoverable failures.

---

## 2. Security — Key Storage

This is the most important category. The CLI handles X25519 private keys. Every violation here is Critical.

- **Private key never in logs** — `console.log`, `console.warn`, `console.error` must never output the private key base64 value or raw bytes.
- **Private key never hardcoded** — no base64 string literals that look like keys in source.
- **Keychain as primary** — `storePrivateKey` must try keychain first. If keychain succeeds, the plaintext file must NOT be written.
- **File fallback is `0o600`** — `writeFileSync` for key files must include `{ mode: 0o600 }`. Missing mode is a Critical finding.
- **Graceful keychain failure** — if `@napi-rs/keyring` import fails or `setPassword` throws, code must fall back to file storage, not crash.
- **No API key in plaintext logs** — `config.apiKey` must not appear in any `console.*` output.
- **`CLAUDE_CODE_OAUTH_TOKEN` or similar tokens** — must never be printed in workflow logs. Verify any new env vars containing tokens use `${{ secrets.* }}`.

---

## 3. Multi-Profile Consistency

- **All commands use `getProfile()`** — no command should construct `ProfilePaths` directly or hardcode `~/.claw-vault/`. Every file operation must go through the resolved profile.
- **Registry operations through helpers** — `registryAddAgent`, `registryDeleteAgent`, `registrySetDefault`, `registryRenameAgent` must be used — no direct mutation of registry objects and `saveRegistry`.
- **`loadRegistry()` called once per command action** — not on every file operation.
- **Auto-migration** — `loadRegistry()` handles legacy `~/.claw-vault/config.json` migration. New code must not bypass it.

---

## 4. CLI UX

- **Security tier shown where needed** — `init`, `connect`, `status`, `agents create` must all call `tierLabel(tier)` and display the result. New commands that store or load keys must also show the tier.
- **Upgrade hint for non-keychain tiers** — `tierUpgradeHint(tier, name)` must be shown after any `tierLabel` output when tier ≠ `'keychain'`.
- **Error messages are actionable** — error strings must tell the user what to run next (e.g. `"Run: claw-vault init"`). Bare `"Error"` without context is a Warning.
- **Consistent exit codes** — `process.exit(1)` on unrecoverable errors; no `process.exit(0)` on errors; no missing `process.exit` in error branches.
- **`--id` flag respected everywhere** — commands that read/write profile data must route through `getProfile()`, which reads `program.opts().id`.

---

## 5. Build and Lint

- `npm run lint` (`tsc --noEmit`) must pass with zero errors.
- `npm run build` (`tsc`) must produce output with zero errors.
- No `@ts-ignore` or `@ts-expect-error` without a comment explaining why.
- No new `console.error` that leaks internal stack traces to end users — wrap with a user-friendly message.

---

## 6. Over-Engineering Check

Flag any of the following:

- A new abstraction (class, factory, helper) with exactly one call site in the current PR.
- Speculative optional parameters added "for future use" with no current consumer.
- Re-implementing logic already in `registry.ts` helpers inline in a command.
- Sync file operations where the existing codebase uses async (or vice versa) without reason.
