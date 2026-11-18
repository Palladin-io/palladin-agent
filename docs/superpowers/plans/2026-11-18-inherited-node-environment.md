# Inherited Node environment implementation plan

> **For agentic workers:** Use superpowers:executing-plans. Execute this bounded fix inline.

**Goal:** Official npm CLI/MCP launches work from agent hosts exporting valid NODE_OPTIONS and NODE_EXTRA_CA_CERTS, without changing native security controls.

**Architecture:** Both native dispatcher entry points copy the parent environment and remove exactly these two Node-host settings before starting the independently verified native process. Windows name matching is case-insensitive; POSIX matching is exact. The parent environment, all other variables, signed manifest binding, Windows lease and native frozen contract remain unchanged. This does not prevent Node startup hooks from running in the host/dispatcher, and does not support malformed Node startup options.

**Tech Stack:** TypeScript dispatcher, Vitest, existing signed Rust runtime.

**Spec:** User-approved cross-host CLI/MCP compatibility objective in this conversation (2026-11-18); focused boundary review confirmed independent native authority and recommended preserving frozen native contracts.

## Constraints and review focus

- No secrets or profile changes; no source debug runtime on the user's account.
- Do not filter LD_*, DYLD_*, SSL_CERT_FILE, NODE_PATH or key/root overrides: native must still reject these.
- Both CLI and private provider paths, including Windows locked spawn, use the same adaptation.
- Empty settings and Windows mixed-case spellings must be removed; preserve POSIX case distinctions and the parent environment.
- Preserve signature rejection, argument forwarding, protocol pipes, signals and exit status.

## Task 1 — Adapt the official dispatcher boundary

- [x] Add regression cases in tests/runtime/native-dispatch.test.ts for CLI/provider on macOS, Linux and Windows; assert actual spawn options, preserved unsafe settings and parent environment.
- [x] Run focused tests and observe the two inherited settings reaching the child (red).
- [x] Add a private environment-copy helper in src/runtime/native-dispatch.ts; use it at both spawn sites.
- [ ] Run focused tests, lint/build, full npm suite and packaging checks.
- [x] Document scope and direct-native behavior in README.md.
- [ ] Independent review and reviewed PR; do not modify installed published package bytes.

## Decisions

The broader alternative was native-startup reclassification plus browser-child sanitization. Rejected for this patch because the direct-native exit78 behavior is a frozen CLI contract. A pre-Node bootstrap is a separate cross-platform packaging project and does not cover direct node entrypoints. No local wrapper or per-agent prompt is the product fix.

## Validation record

- Focused tests: observed three expected failures before implementation; 43 dispatcher tests passed afterward. Type checking and compilation to a scratch output directory passed.
- Independent source review found no production blocker; fixed its Windows test-fixture aliasing finding by using a temporary plain environment map.
- Full suite in the restricted local test sandbox was not a valid green run: initial process-limit/npm environment failures, then a 180-second timeout. Full supported Node/platform matrix must pass in hosted CI.
- Packaged native doctor in the restricted scratch test stopped at OS account directory lookup before environment checks; no end-to-end claim, no installed package modification or profile access.

## Owner-approved release preparation — 2026-11-18

- The owner approved publishing and installing exact 0.0.13 preview, deferring only manual adversarial/physical lifecycle evidence. The release remains draft, latest stays 0.0.9, and all automated/signature/provenance gates remain mandatory.
- Aligned all launcher/platform/Rust versions, exact pins, lockfiles, dispatch fixtures and SBOM; no external dependency update.
- The owner separately approved RUSTSEC-2026-0457/0462/0543 exceptions through November 24 inclusive. CI validates the resolved all-target/all-workspace-feature graph excludes the affected rmcp clients and enforces expiry from November 25. Existing exception deadlines are unchanged.
- Seven Python policy tests pass after red regressions; real dependency CI passed at 5396ddc. Exact-preview policy regressions observed red, then all 43 release checks passed (four platform checks skipped). Type checking and actionlint pass. Independent source review of the exception and release preparation found no blockers.
- Local packaging staging tests hit sandbox-denied Bash heredoc temporary files (six failures); rely on the final hosted packaging matrix, not a local green claim. The full hosted Node matrix and OpenClaw compatibility passed before the version bump; final-source CI remains required.
- Follow-up before exception expiry: upgrade rmcp past the patched client advisories and remove its transitive chrono maintenance dependency through an upstream-supported or separately reviewed migration. No automatic renewal.
