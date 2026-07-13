# PR Review Criteria — Palladin Agent CLI

---

## 1. TypeScript Correctness

- **No `any`** — use `unknown` + narrowing or proper typed interfaces.
- **Native dispatcher only** — the public TypeScript entry point may resolve and spawn the exact platform package. It must not import the legacy TypeScript runtime, search `PATH`, download a binary, invoke a shell, or receive secrets.
- **Optional platform package is exact** — the platform package version must be pinned exactly and resolution must fail closed when it is absent, outside the expected package root, or not executable.
- **No non-null assertions (`!`)** on values that can be null or absent.
- **Exit codes** — the Node dispatcher must propagate the native exit code; the native CLI must return non-zero for errors and must not report success after a failed security operation.

---

## 2. Security — Key Storage

This is the most important category. The native runtime handles an organization API key and per-Agent X25519/Ed25519 private keys. Every violation here is Critical.

- **Private key never in logs** — `console.log`, `console.warn`, `console.error` must never output the private key base64 value or raw bytes.
- **Private key never hardcoded** — no base64 string literals that look like keys in source.
- **No plaintext fallback** — native secret-store failure must return an error. API keys and private keys must never fall back to a file, environment variable, argv, stdin retained after setup, Login Keychain, or the legacy TypeScript store.
- **Ownership model is fixed** — the API key belongs to the organization and may be shared by multiple Agents. Agent identity remains the separate `agentId` plus X25519/Ed25519 keys. Treat any API-key-per-Agent refactor or backend protocol change as Critical unless the product model was explicitly changed.
- **macOS Hardened is fail closed** — only a provisioned, correctly signed runtime with the exact bundle identifier, Team ID, application identifier, and Data Protection Keychain access group may report Hardened or touch hardened items.
- **Data Protection attributes** — hardened items must be non-synchronizable and `WhenUnlockedThisDeviceOnly`; the shared organization credential requires user presence. Missing entitlement or authorization must not fall back to another store.
- **Public Node process cannot read secrets** — the npm dispatcher must only launch the fixed native bundle and must never expose a secret-returning API to Node.
- **No API key in plaintext logs** — `config.apiKey` must not appear in any `console.*` output.
- **`CLAUDE_CODE_OAUTH_TOKEN` or similar tokens** — must never be printed in workflow logs. Verify any new env vars containing tokens use `${{ secrets.* }}`.

---

## 3. Multi-Profile Consistency

- **Public registry contains references only** — aliases, Agent IDs, organization credential IDs, hosts, and public keys may be persisted; API keys and private keys may not.
- **Shared organization credential lifecycle** — deleting or renaming one Agent must not delete the organization credential while another Agent still references it.
- **Profile selection is explicit** — commands must use the native registry/profile resolution path and preserve distinct Agent identities even when they share an organization credential.
- **Legacy TypeScript is not production code** — retained compatibility source or fixtures must not be imported by the public entry point or included in the public npm tarball.

---

## 4. CLI UX

- **Security tier is truthful** — unsigned, ad-hoc, wrongly entitled, or otherwise unauthorized macOS builds must report Unavailable, never Hardened.
- **No false recovery hint** — hardened storage failures must not suggest installing a Node keyring dependency or using a plaintext fallback.
- **Error messages are actionable** — error strings must tell the user what to run next (e.g. `"Run: palladin init"`). Bare `"Error"` without context is a Warning.
- **Consistent exit codes** — both the dispatcher and native CLI must return non-zero on unrecoverable errors and must not omit an error result on a failure branch.
- **`--id` flag respected everywhere** — native commands that read or write profile data must pass the explicit alias through `RuntimeService` profile resolution.

---

## 5. Build and Lint

- `npm run lint` (`tsc --noEmit`), `npm run build` (`tsc`), and Node tests must pass with zero errors.
- Rust changes require `cargo fmt --check`, Clippy with warnings denied, and relevant workspace/feature tests.
- Packaging changes require shell/YAML/plist validation and an npm pack/install smoke test without lifecycle scripts.
- No `@ts-ignore` or `@ts-expect-error` without a comment explaining why.
- No new `console.error` that leaks internal stack traces to end users — wrap with a user-friendly message.

---

## 6. Over-Engineering Check

Flag any of the following:

- A new abstraction (class, factory, helper) with exactly one call site in the current PR.
- Speculative optional parameters added "for future use" with no current consumer.
- Re-implementing logic already provided by `ProfileRepository` or native profile helpers inline in a command.
- Sync file operations where the existing codebase uses async (or vice versa) without reason.
