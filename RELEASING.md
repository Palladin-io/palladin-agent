# Palladin Agent release runbook

Palladin Agent is a public repository and a security-sensitive credential runtime. Releases are built, signed, staged, approved, and published by protected GitHub Actions workflows. Publishing from a laptop or with a long-lived npm token is forbidden.

The product owner and only release approver is `@patryk-roguszewski`. A release is not complete until every verification below passes and the GitHub release is immutable.

## Release invariants

- Release only a protected `vX.Y.Z` tag whose commit is reachable from `main` and has all required CI gates green.
- Use GitHub-hosted runners. npm trusted publishing does not support self-hosted runners.
- Pin every third-party GitHub Action to a full 40-character commit SHA and keep the readable version in a comment.
- Give build jobs `contents: read`. Grant `id-token: write`, `attestations: write`, or other write permissions only to the exact job that needs them.
- Keep npm trusted publishers stage-only. CI may run `npm stage publish`, but it must never run a direct `npm publish` for an established package.
- Require Patryk's GitHub environment approval before any signing secret, OIDC publishing identity, or release finalization becomes available.
- Require Patryk to review every staged npm package and approve it interactively with npm 2FA.
- Never place npm tokens, signing keys, notarization credentials, package contents, or runtime secrets in logs or artifacts.
- Never move or reuse a release tag. Never reuse a version that reached npm staging or the live registry.
- Run only one Palladin npm release train at a time. All release workflows share a global concurrency group, and a new version must not be staged while an earlier version still awaits owner approval or finalization.
- Treat SHA-256 checksums, a release manifest, an SBOM, npm provenance, and GitHub artifact attestations as release artifacts, not optional metadata.

## One-time npm bootstrap

npm staged publishing and trusted publishing both require the package to exist first. Bootstrap is therefore a one-time exception for each of these packages:

- `@palladin/agent`
- `@palladin/runtime-darwin-arm64`
- `@palladin/runtime-darwin-x64`
- `@palladin/runtime-linux-arm64-gnu`
- `@palladin/runtime-linux-arm64-musl`
- `@palladin/runtime-linux-x64-gnu`
- `@palladin/runtime-linux-x64-musl`
- `@palladin/runtime-win32-arm64`
- `@palladin/runtime-win32-x64`

For each package:

1. Patryk enables npm account 2FA and confirms ownership of the `@palladin` scope.
2. Patryk creates a granular npm access token with the minimum package-creation scope and the shortest available expiry. The token exists only for this bootstrap window.
3. Store it only in the protected `npm-bootstrap` GitHub environment. That environment must require Patryk's approval and must not expose the secret to pull requests.
4. Run the owner-dispatched bootstrap workflow from a reviewed commit on `main`. It publishes a generated, inert `0.0.0-bootstrap` package under the non-default `bootstrap` dist-tag with `--access public` and provenance. The tarball may contain only `package.json`, `README.md`, and `LICENSE`. It must contain no binary, launcher, lifecycle script, `bin` entry, optional dependency, or production source.
5. Verify the package name, scope, bootstrap tag, tarball contents, source repository, and provenance on npm.
6. Configure the exact trusted publisher described below.
7. Set Publishing access to **Require two-factor authentication and disallow tokens**.
8. Revoke the bootstrap token and delete the GitHub environment secret immediately. Verify that token authentication can no longer publish.
9. Delete the temporary bootstrap workflow in a reviewed PR. Keep its GitHub run and npm package history as the audit trail.

Do not bootstrap from a developer machine. Do not keep a fallback token after trusted publishing is configured. If bootstrap is interrupted, revoke the token before investigating and create a new short-lived token only for the next protected attempt.

## Trusted publisher configuration

Configure each npm package separately. npm permits only one trusted publisher per package.

Use these settings:

- Provider: GitHub Actions
- Organization or user: `Palladin-io`
- Repository: `palladin-agent`
- Workflow: the exact platform or meta release workflow filename in `.github/workflows/`
- Environment: `npm-release`
- Allowed action: `npm stage publish` only
- Direct `npm publish`: disabled

The publishing job must use Node `22.14.0` or newer and npm `11.15.0` or newer, request `id-token: write`, and run on a GitHub-hosted runner. Pin an exact npm 11 version in the workflow so CLI behavior does not change during a release.

After configuring trust, verify a staged dry run through the protected workflow before disallowing tokens. `npm whoami` is not an OIDC verification and must not be used as one. A successful `npm stage publish`, visible source provenance, and a rejected direct `npm publish` are the verification.

## Protected GitHub configuration

Repository administrators must configure these settings outside the repository:

- Create `release-prepare`, `macos-signing`, `windows-signing`, `version-policy-signing`, `npm-bootstrap`, `npm-release`, and `release-finalize` environments.
- Add only `@patryk-roguszewski` as required reviewer for all seven environments.
- Keep **Prevent self-review** disabled because Patryk both starts and approves the release.
- Restrict `release-prepare`, signing, npm release, and finalization environments to protected release tags. Restrict `npm-bootstrap` to the default branch and remove its secret after bootstrap.
- Create a tag ruleset for `v*`. Limit tag creation, update, and deletion to Patryk. Block force updates and deletions.
- Require pull requests, CODEOWNERS approval, and the stable CI, native platform, and dependency policy gates before changes reach `main`.
- Enable the dependency graph, Dependabot alerts and security updates, secret scanning, push protection, and private vulnerability reporting.
- Allow only selected actions and reusable workflows. Require actions to be pinned to full commit SHAs.
- Enable immutable GitHub Releases.
- Protect workflow files with CODEOWNERS and do not permit workflow changes to bypass the normal pull request path.

Do not enable branch or tag protections until their required check names are present on `main`, otherwise the stacked pre-production pull requests can deadlock. Enable them immediately after the release stack lands.

## Signed version-policy operations

Every production native binary and meta-package embeds the same public Ed25519 trust anchor and exact source commit. The private key never enters GitHub or npm: Cloud KMS performs raw Ed25519 signing through GitHub OIDC and Workload Identity Federation. The fixed public object is `https://releases.palladin.io/agent/version-policy.json`.

Configure these public repository variables:

- `PALLADIN_VERSION_POLICY_PUBLIC_KEY`: canonical base64 of the raw 32-byte Ed25519 public key
- `PALLADIN_WINDOWS_PUBLISHER` and `PALLADIN_WINDOWS_SIGNER_THUMBPRINT`: exact Authenticode identity committed by each Windows artifact binding

Configure these variables only on the protected `version-policy-signing` environment:

- `GCP_WORKLOAD_IDENTITY_PROVIDER`
- `GCP_VERSION_POLICY_SERVICE_ACCOUNT`
- `GCP_PROJECT_ID`
- `GCP_VERSION_POLICY_KEY_VERSION`
- `GCP_VERSION_POLICY_KEY`
- `GCP_VERSION_POLICY_KEYRING`
- `GCP_VERSION_POLICY_LOCATION`
- `PALLADIN_RELEASE_BUCKET`

The environment must require Patryk's approval. Restrict the Workload Identity Provider condition to the exact `Palladin-io/palladin-agent` repository, `version-policy-signing` environment, approved workflow filenames, and either protected `main` for maintenance or the protected release tag for a release. Its service account may read the configured public key, sign only with the single enabled `EC_SIGN_ED25519` key version, and create objects only below `gs://$PALLADIN_RELEASE_BUCKET/agent/version-policy/` plus conditionally replace `agent/version-policy.json`. It must not have repository, npm, or general bucket administration access. Enable object versioning and a retention policy on the bucket so an incident has an external audit trail. Every signed policy is first written under its immutable sequence-and-digest name with generation-match zero; the fixed pointer is replaced only when its observed generation still matches. The public endpoint must preserve the exact pointer bytes, return `Content-Type: application/json`, reject redirects, and use `Cache-Control: no-store`.

The release sequence is intentionally asymmetric:

1. `release-platforms.yml` builds and signs all native candidates with the public key and exact `SOURCE_SHA`, then stages the platform packages.
2. After Patryk approves all eight immutable platform candidates, `release-meta.yml` installs those exact registry versions without lifecycle scripts and verifies npm registry signatures.
3. The workflow hashes every installed npm client and credential-bearing worker, verifies the Windows worker hash against the signed MSIX binding, creates the next monotonic policy, and signs its canonical payload in KMS.
4. Before publication, every exact macOS, Windows, Linux glibc, and Linux musl worker verifies that candidate's signature, freshness, source/version binding, and its own executable hash without opening profile or secret state.
5. Only after every native smoke passes is the byte-identical policy published to the fixed endpoint.
6. Only after byte verification and an identity-free native retrieval from the live endpoint is the meta-package containing that policy staged. This keeps the consumer-visible package behind the artifact and policy gates.

Set `bootstrap_policy=true` only for the first policy, after confirming that neither the GCS object nor fixed endpoint exists. Every later release must use `false`; the workflow verifies the previous signature, preserves immutable bindings for an already published version, and increments the sequence. A rollback never republishes an old version or lowers the security floor. Rebuild the safe source as a new, higher patch version.

The policy lifetime is at most 30 days. Run `version-policy-maintenance.yml` in `renew` mode by day 21 even when no release is planned. The weekly tokenless `version-policy-verify.yml` check fails when fewer than nine days remain. Renewal verifies the historical signature even if the previous policy has just expired, increments the sequence, and changes no artifact binding.

For a compromised immutable version, run the maintenance workflow in `incident` mode with the exact blocked version, an already published safe version, and confirmation `SIGN POLICY`. The workflow signs and publishes the higher sequence first, then prints a manual npm deprecation and dist-tag plan. Patryk performs those npm operations interactively; the workflow has no npm token and never executes them. Preserve the old GCS object generation and workflow run as incident evidence.

## Release order

npm does not provide a multi-package transaction. Palladin uses the `@palladin/agent` meta package as the atomic consumer boundary: all eight native packages become verified candidates first, and the meta package is published last.

### 1. Prepare the release

1. Update all nine package versions to the same exact `X.Y.Z`. The meta package must pin every optional platform dependency to that exact version.
2. Regenerate lockfiles and run the full TypeScript, Rust, contract, packaging, and cross-platform test suite.
3. Review dependency and license changes. Do not add a license to an allowlist without Patryk's security and legal review.
4. Merge through the normal pull request path. Do not invoke a release from an unreviewed branch.
5. Create the protected `vX.Y.Z` tag on the reviewed commit.

### 2. Build and verify platform candidates

The release pipeline builds all eight platform packages from the same tagged source commit. It must not download a runtime executable from a mutable URL or another release.

For every platform tarball:

1. Build with the locked toolchain and dependency lockfiles.
2. Sign macOS and Windows binaries in their protected environments. Linux artifacts remain unsigned binaries but still require provenance and attestations.
3. Run `npm pack --dry-run`, create the final tarball, extract that tarball into a clean directory, and verify the extracted binary. Verification of a pre-packaging build output is insufficient.
4. On macOS, require `codesign --verify --deep --strict`, the expected Team ID, hardened runtime, fixed entitlements, successful notarization, and a stapled ticket validated with `spctl` and `stapler validate`.
5. On Windows, require Authenticode status `Valid`, the expected publisher certificate and thumbprint, a trusted RFC 3161 timestamp, and signature verification on both runtime and broker or executor binaries shipped in the package.
6. Run the package on its target operating system and architecture. Verify the launcher selects only the exact platform package and executable.
7. Generate `SHA256SUMS`, `release-manifest.json`, a CycloneDX or SPDX SBOM, npm provenance, and GitHub build and SBOM attestations tied to the tag commit and tarball digest.
8. Upload artifacts with short retention. Artifacts are inputs to later protected jobs, never a substitute for registry verification.

Any mismatch in signature, entitlement, identity, checksum, manifest, SBOM, provenance, attestation, package contents, version, or source commit stops the release.

### 3. Stage and approve platform candidates

1. The protected OIDC job stages each platform tarball with `npm stage publish --tag candidate`. It must not receive an npm token.
2. Record each stage ID and expected SHA-256 digest in the release manifest without exposing credentials.
3. Patryk uses npmjs.com or an interactive npm CLI session to inspect every staged package. Download the staged tarball and compare it byte-for-byte with the attested tarball.
4. Patryk approves each platform stage with npm 2FA. No bot, workflow, access token, or second person approves on Patryk's behalf.
5. Install every published platform package from the public npm registry by exact `X.Y.Z` in clean target runners. Re-run signature, checksum, launcher, startup, and smoke tests against the registry tarball.

The `candidate` dist-tag deliberately keeps platform packages away from their default tag. Exact optional dependency versions still allow the meta package to resolve them after the final approval.

### 4. Stage and approve the meta package

Only after all eight registry smoke tests pass:

1. Build the meta tarball from the same tag commit.
2. Verify its package allowlist contains only the launcher, runtime metadata, documentation, and license files. It must not contain private source, keys, build caches, test fixtures, or lifecycle scripts.
3. Verify all eight optional dependencies use exact `X.Y.Z` versions and no unsupported platform fallback exists.
4. Generate and verify its checksum, manifest entry, SBOM, provenance, and attestations.
5. Stage it through the protected OIDC workflow with `npm stage publish --tag latest`.
6. Patryk downloads and inspects the staged tarball, verifies the digest and provenance, then approves it with npm 2FA.
7. Install `@palladin/agent@X.Y.Z` and `@palladin/agent@latest` from npm in clean macOS, Windows, and Linux runners and repeat the end-to-end smoke checks.

Publishing the meta package is the consumer-visible commit point. Never approve it while a platform package, registry smoke test, or attestation is missing.

### 5. Finalize the immutable GitHub release

After npm smoke tests pass, Patryk approves finalization. Create the GitHub release from the existing protected tag and attach only the already verified artifacts:

- all npm tarballs
- `SHA256SUMS`
- `release-manifest.json`
- SBOMs
- signature and notarization verification reports without secrets
- links to npm and GitHub attestations

Verify every attachment digest once more, publish the release, and confirm GitHub reports it as immutable. Do not replace assets or move the tag after publication.

## Failure and recovery

- **Build, test, signing, notarization, or attestation fails before staging:** publish nothing. Fix through a pull request. If the tag's source changes, create a new version and a new protected tag.
- **A staged package is wrong and no package was approved:** reject every stage for that version with interactive npm 2FA. Fix through a pull request and use a new version. Never overwrite or reuse the staged version.
- **Only some platform stages were approved:** do not approve the meta package. Do not unpublish the approved packages as routine cleanup. Correct the issue under a new patch version, rebuild all nine packages, and repeat the complete flow.
- **All platforms are live but a registry smoke test fails:** keep the meta package unapproved. Preserve evidence, reject its stage if present, and issue a complete new patch release after the cause is fixed.
- **The meta package is live but GitHub finalization fails:** do not republish npm packages and do not move the tag. Resume finalization from the same verified artifacts and digests after Patryk's protected approval.
- **A stage expires or is rejected:** treat that version as consumed and start a new version. Do not silently create a different tarball with the same version.
- **A signing or publishing credential may be compromised:** stop release workflows, reject all pending stages, remove trusted publisher access, revoke tokens, rotate affected signing credentials, preserve audit evidence, and follow the security incident process before releasing again.
- **A published package is malicious or exposes secrets:** follow npm and GitHub security incident procedures immediately. Do not use routine unpublish as a substitute for coordinated revocation, advisory, and recovery.

Every retry must be reproducible and attributable to a reviewed source commit. Never bypass a failed gate, weaken a policy, use a developer-built artifact, or introduce an emergency laptop publish path.

## Post-release audit

Record the following without secrets:

- version, protected tag, and full source commit SHA
- GitHub workflow run IDs and environment approvals
- npm stage IDs and Patryk's approval timestamps
- package names, registry URLs, tarball digests, and dist-tags
- signing identities, certificate fingerprints, timestamps, notarization request IDs, and verification results
- release manifest, SBOM, provenance, and attestation URLs and digests
- clean-registry smoke test results for every supported platform
- immutable GitHub release URL

Confirm that no bootstrap token exists, no npm token is available to release workflows, no pending stage remains, no release environment is accessible to unapproved actors, and no release artifact contains a secret.
