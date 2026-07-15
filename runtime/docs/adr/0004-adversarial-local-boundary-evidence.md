# ADR 0004: Adversarial local-boundary evidence

- Status: Accepted
- Date: 2026-07-15
- Scope: Palladin Agent Runtime v2 local process and distribution boundaries

## Context

Unit tests and package smoke tests are necessary but do not prove the same property as a hostile
process running beside the exact native runtime. Palladin also has deliberately different trust
boundaries by platform and tier. A single green check cannot honestly be presented as process
isolation on every target.

The adversary is an untrusted application running on the same machine, including a foreign Node.js
process. It may enumerate known storage locations, spawn the genuine public client, modify or copy
artifacts, control argv and environment variables, replace writable paths, attach a debugger, request
a core dump, inject a loader library, replay an authorization, impersonate a protocol peer, expose a
fake browser endpoint, or provide shell metacharacters to an execution request.

The operating system, the protected release identity, the Palladin backend, and the user or operator
at an explicit approval boundary are trusted. Root, Administrator, kernel compromise, malicious
hardware, and a compromised signing account remain outside this local-process boundary.

## Decision

Every supported target and security tier has an explicit adversarial disposition. Automated and
manual evidence is bound to the exact source SHA, target, tier, artifact digest, test catalog, and
workflow run. Missing, duplicate, expired, or mismatched evidence fails closed. A release is blocked
when any Critical or High finding is not resolved. Accepting a Critical or High finding is not a way
around the gate.

Manual evidence is not trusted because it contains an operator URI. After native smoke tests, the
owner-only protected workflow derives every manual cell from the exact report and signs the complete
approval payload with the pinned Ed25519 KMS key. Meta-package staging and finalization both verify
that signature, operator, source SHA, report digest, observation, target, attack, result, and artifact
digest. An unsigned or copied manual approval is release-blocking.

The canonical target, attack, evidence, and residual-risk matrix lives under
`security/adversarial/`. Reports contain only public identifiers and enumerated outcomes. They never
contain a canary, credential, API key, private key, plaintext secret, raw process memory, raw process
environment, or captured protocol payload.

## Platform trust domains

### macOS

The public Hardened tier is the exact Developer ID signed and provisioned application using the
`session-v2` Data Protection Keychain access group. A fresh LocalAuthentication decision is bound to
one exact operation and connection. Unsigned development code does not claim this tier.

The source-development Convenience tier uses the current user's Login Keychain and does not isolate
one same-user process from another. This is an expected tier limitation and must be reported as such,
not as a passing process-isolation test.

Positive LocalAuthentication replay, cancellation, lock, sleep, and logout evidence requires
dedicated interactive Apple Silicon and Intel Macs. Hosted CI proves negative and structural
properties only. A release report cannot convert missing hardware evidence into `passed`.

### Windows

The public Hardened tier uses the signed client and AppContainer companion with a packaged
LocalService broker. Broker state is ACL-bound to SYSTEM, Administrators, and the restricted service
SID. Windows Hello consent is bound to the exact profile, operation, caller, connection, and lifecycle
epoch. The public client is not secret-bearing and being able to inspect it is not a finding.

The source-development Convenience tier uses Windows Credential Manager for the current user. It has
the same expected same-user limitation as other Convenience stores.

Positive Windows Hello and hostile same-login-user process evidence requires a clean, non-elevated,
dedicated Windows x64 or ARM64 test account. GitHub-hosted Administrator runners may prove fail-closed
behavior and package integrity, but may not claim the missing standard-user evidence.

### Linux glibc

Convenience uses Secret Service and treats the entire desktop UID as one trust domain. `LD_PRELOAD`
or another same-UID process can enter the public client, so the client must remain zero-secret and
must clear the loader environment before executing the sealed worker image.

Hardened uses a dedicated, locked Agent UID, a separate broker UID, root-owned principal mapping,
broker-owned encrypted state, and a one-shot executor identity. The dedicated Agent UID is the
workload principal, not a per-process principal. Unrelated Node.js applications must never run under
that UID: they could request operations as the Agent and inspect transient input or client memory in
the same UID. Broker-held identity keys, the master key, broker memory, and encrypted broker state
remain isolated behind the separate broker UID. This is an operator constraint, not a claim that
Linux authenticates an npm package or isolates sibling processes inside the Agent UID.

A privileged container is package-integration evidence only. Release acceptance for the Hardened
boundary requires a native VM with systemd 252 or newer and distinct kernel UIDs.
DEB and RPM are separate release-evidence targets for each architecture; neither package digest or
native run can authorize the other format.

### Linux musl

The MVP supports Convenience on x64 and ARM64 when a compatible Secret Service is available. The
same-UID limitation applies. Hardened is not applicable on Alpine/OpenRC in the MVP because there is
no equivalent per-request executor and service boundary. Absence of Hardened is an explicit supported
matrix disposition, not a skipped test.

## Residual-risk rules

- Expected Convenience same-user or same-UID access is demonstrated with synthetic values and
  reported as `expected-residual`.
- Linux Hardened trusts the entire dedicated Agent UID. Runtime authority, transient input, and
  client memory inside that UID are an expected residual. Run no unrelated application under it.
- Interactive macOS and Windows consent transitions remain release-blocking manual evidence until a
  trusted hardware run is attached to the exact source and artifact.
- Medium and Low residual risks require an owner, review date, and this or another ADR reference.
- Critical and High findings must be fixed and re-tested; an `accepted` status still blocks release.

## Consequences

Release preparation is intentionally fail-closed when an evidence-producing runner, signer,
interactive test account, or protected environment is unavailable. This is preferable to publishing
a report that upgrades structural or unit evidence into a claim about a live OS boundary.
