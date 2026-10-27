# Linux Hardened installation

The official Linux path consists of an authenticated `palladin-runtime` DEB/RPM,
its broker and one-shot executor, and one dedicated system account per Agent.
npm remains an unprivileged launcher: it never runs sudo, installs a service,
reads keys, or silently falls back to Secret Service.

**Release status:** this distribution is being prepared for a subsequent release.
The previously published npm-only Linux releases provide Convenience and do not
satisfy this installation contract. Do not substitute those artifacts for the
system packages below. Implementation, native-host acceptance and publication
are separate release gates; the presence of this runbook is not evidence that a
Hardened release has been published.

## 0.0.11 AWS acceptance status

The owner-selected next step is to produce the signed Linux candidate and then
perform the complete installation acceptance on a supported AWS VM. This is not
a claim that 0.0.11 is a finalized release. Keep the existing signature,
provenance, package isolation and publication gates; do not promote the candidate
to a fully accepted release before recording the required evidence.

The legacy `platform-lifecycle.yml` Linux harness still uses the runner UID and
scratch-HOME registry. It is not valid Hardened acceptance evidence and must not
be used to certify this candidate. AWS acceptance must provision the dedicated
account described below and exercise pairing, MCP, non-secret Exec, reinstall,
identity continuity, revocation and cleanup through the broker boundary. Record
the exact package/source and actual host distribution; no Windows acceptance is
claimed by this Linux rollout.

## Platform contract

The installer accepts these candidate targets on x64 and ARM64:

| Distribution | Version | Package |
| --- | --- | --- |
| Ubuntu | 24.04 LTS | DEB |
| Debian | 13 | DEB |
| Fedora | 44 | RPM |
| Rocky Linux | 9.x | RPM |

All require glibc, systemd 252 or newer as PID 1, distinct kernel UIDs, and the
installed systemd sandbox. The release must pass native x64/ARM64 isolation and
package-family tests before claiming this matrix as tested. QEMU user-mode and
systemd container tests alone are insufficient isolation evidence.

Alpine/musl, OpenRC, Ubuntu 22.04, other distribution versions and application
containers are unsupported. The official installer also rejects systemd
containers: use a supported native host or VM. npm availability on a platform
does not imply Hardened support. No unsupported target is downgraded to
Convenience by the official client.

Hardened protects against ordinary processes outside the dedicated Agent UID.
Code intentionally running as that Agent UID is in its trust domain. It does not
protect against root, the kernel, or offline disk access without full-disk
encryption. Never share the Agent UID with unrelated applications.

## Verify and install a released system package

Prerequisites: administrator access and GitHub CLI at `/usr/bin/gh` with
`attestation verify`, `--bundle`, `--source-ref`, `--source-digest` and
`--deny-self-hosted-runners` support. Use an exact published release version;
there is no install-time build or mutable `latest` download.

Download the matching package and verification material from the same release:

```bash
VERSION='<exact-published-version>'
SOURCE_SHA=$(gh api "repos/Palladin-io/palladin-agent/commits/v$VERSION" --jq .sha)
# Ubuntu/Debian x64; use arm64 instead of amd64 on ARM64.
PACKAGE="palladin-runtime_${VERSION}-1_amd64.deb"
# Fedora/Rocky x64: PACKAGE="palladin-runtime-${VERSION}-1.x86_64.rpm"
# Fedora/Rocky ARM64: PACKAGE="palladin-runtime-${VERSION}-1.aarch64.rpm"
BUNDLE=linux-system-x64.intoto.jsonl
# ARM64: BUNDLE=linux-system-arm64.intoto.jsonl

gh release download "v$VERSION" --repo Palladin-io/palladin-agent \
  --pattern "$PACKAGE" --pattern "$BUNDLE" \
  --pattern install-hardened.sh --pattern installer.intoto.jsonl
```

Copy the bootstrap into a private root-owned directory and verify that snapshot
before executing it. The installer then snapshots and verifies the complete
package before any package maintainer script executes:

```bash
sudo /bin/bash -c '
  set -euo pipefail
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin
  stage=$(mktemp -d /var/tmp/palladin-bootstrap.XXXXXX)
  trap '\''rm -rf "$stage"'\'' EXIT
  install -m 0600 ./install-hardened.sh ./installer.intoto.jsonl "$stage/"
  env -i PATH="$PATH" HOME=/root /usr/bin/gh attestation verify "$stage/install-hardened.sh" \
    --bundle "$stage/installer.intoto.jsonl" --repo Palladin-io/palladin-agent \
    --signer-workflow Palladin-io/palladin-agent/.github/workflows/release-platforms.yml \
    --source-ref "refs/tags/v$1" --source-digest "$2" --deny-self-hosted-runners
  /bin/bash "$stage/install-hardened.sh" "$1" "$2" "$3" "$4"
' -- "$VERSION" "$SOURCE_SHA" "$PACKAGE" "$BUNDLE"
```

The complete package uses the existing GitHub signed provenance mechanism,
bound to the release workflow, tag and source commit. Inside the package,
`release-signature.json` uses the existing KMS Ed25519 runtime signature. It
binds the exact client/worker source and version. No new signing authority or
production signing configuration is needed. RPM local-package GPG verification
is replaced for this one verified file by provenance verification; repository
dependency GPG verification remains enabled.

## Create a dedicated Agent identity

Provision a locked, non-login account. Choose its profile and exact API origin
explicitly. The root-owned record is the authority; the workload cannot change
its account/profile/API binding.

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin palladin-agent-qa
sudo /usr/lib/palladin/runtime/palladin-manage-agent-uid \
  authorize palladin-agent-qa qa https://api.stage.palladin.io --dedicated
sudo -u palladin-agent-qa /usr/lib/palladin/runtime/palladin-linux-client doctor
sudo -u palladin-agent-qa /usr/lib/palladin/runtime/palladin-linux-client init
sudo -u palladin-agent-qa /usr/lib/palladin/runtime/palladin-linux-client connect
```

`connect` reads the organization credential from a masked terminal prompt.
Automation uses a protected pipe and `connect --api-key-stdin`; never put a key
in arguments, environment variables, unit files or logs. No install or update
step needs an organization credential.

Run the Agent workload itself under this dedicated UID. Its CLI and MCP commands
can use `/usr/lib/palladin/runtime/palladin-linux-client` directly. For example,
an MCP client already running under the dedicated account uses:

```json
{
  "mcpServers": {
    "palladin": {
      "command": "/usr/lib/palladin/runtime/palladin-linux-client",
      "args": ["mcp", "serve"]
    }
  }
}
```

Every MCP tool call includes the authorized profile (`qa` in this example).
Only `init` creates that fixed profile; arbitrary profile creation, renaming,
force-init and workload-triggered purge are intentionally unavailable.

If you start with npm, install the exact same CLI version. Run it as the
authorized Agent UID. Missing broker/configuration stops operations before
credential input is consumed. Installing npm alone does not provision Hardened.
An existing MCP process must be restarted after an update.

## Update, reinstall and transition from Convenience

Package replacement first stops the broker, its MCP workers and executor activation.
A failed replacement leaves protected operations unavailable until the package is
repaired. Existing Agent identities remain preserved.

For an update, repeat the authenticated package download/install with the new
release and update npm to the same version if used. Reinstallation uses the same
verified package. Do not run `authorize` again: upgrades/reinstalls preserve the
master key, principal namespace, account binding and existing Agent identity.
They restart the broker boundary so components cannot mix versions. Package
removal also preserves `/etc/palladin` and `/var/lib/palladin-runtime`.

Convenience-to-Hardened transition is explicit new enrollment, not a transparent
key migration:

1. Preserve the previous user's profiles and Secret Service entries. Stop its
   Agent workload while arranging the transition; do not export old private keys.
2. Install Hardened and create a different dedicated account and fresh Agent
   identity using the steps above.
3. Connect and approve the new Agent in the panel. Regrant its required access.
   Verify CLI/MCP and Exec with non-secret test data before switching the workload.
4. Deliberately revoke/deactivate the old Agent in the panel after verification.
   Rotate an organization credential if the old same-UID boundary was exposed.
5. Any old local-data cleanup is a separate explicit operation. Neither npm nor
   system package installation deletes or imports those secrets.

To stop one Hardened principal without deleting its state:

```bash
sudo /usr/lib/palladin/runtime/palladin-manage-agent-uid revoke palladin-agent-qa
```

Revocation preserves a root-owned tombstone and terminates broker sessions.
Reauthorization creates a new random namespace and refuses a UID with live
processes. Permanent local deletion additionally requires:

```bash
sudo /usr/lib/palladin/runtime/palladin-manage-agent-uid \
  revoke-purge palladin-agent-qa --confirm-purge
```

## Build and verify (maintainers)

The release pipeline builds all five GNU components on native x64/ARM64 builders
against glibc 2.34. `release-platforms.yml` retains and attests those exact bytes.
After the existing KMS runtime signature is available, `release-meta.yml`
packages the set, generates SBOM/checksums and attests DEB/RPM. Finalization must
verify the system-package manifests and provenance as well as npm artifacts.
Production publishing/signing workflows remain owner-dispatched.

Builders require `--version`, `--architecture`, `--binaries`, `--output`,
`--release-manifest`, `--public-key` and `--source-sha`. An optional numeric
`--revision` allows package lifecycle testing without falsely relabeling runtime
binary versions. They reject a missing/invalid signature or mismatched
client/worker/version/source/architecture before producing an artifact.

CI uses isolated throwaway signing keys. `PALLADIN_TEST_SYSTEM_PACKAGES=1 node
--test packaging/linux/tests/runtime-manifest.test.mjs` builds and inspects both
formats with native packaging tools. Container package-family tests provide
integration evidence; native hosted systemd jobs provide the distinct UID,
ptrace, executor and authorization boundary evidence. Synthetic-state lifecycle
fixtures must not be reported as actual API enrollment. Live staging enrollment,
MCP and non-secret Exec remain separate acceptance requirements.

After a successful owner-dispatched `Rust Runtime` run, its `linux-hardened-qa-x64` artifact retains
only the tested DEB for one day. The owner can dispatch the existing `Rust Runtime`
workflow from the same source revision with `qa_build_run_id`, `qa_api_origin`,
`qa_vault_id` and `qa_entry_id` (plus optional `qa_field`). A nonempty build ID
routes directly to the reusable `Linux staging acceptance` job and skips rebuilding.
This entry point works from a PR branch before the new reusable workflow is on main.
Use an explicit staging API origin and a fixture containing only fictional data.
The workflow verifies the successful build's repository, workflow and source SHA
against its own revision before installing the package. PR merge builds are not
accepted as exact-revision QA packages. A fork, failed build,
different workflow or mismatched commit is rejected. No release-environment
secrets or signing authority are used.

Start this short separate job when the approver is available. Download its
`linux-staging-approval` artifact and open the value-free approval URL before the
request expires. The QA harness allows the runtime's existing 31-minute identity-only
pairing lease to finish, with a 32-minute process cap; it does not extend server
expiry or credential-operation authorization. The current staging API alias shares the promoted backend and returns
`https://panel.palladin.io/agent-pairing/...`; only that exact panel origin is
accepted by this QA handoff. Approve the new Agent in the intended organization, then approve
its Exec request for the fixture. The test uses the existing primary-value mapping
(`CLAW_SECRET`); an optional field label selects another fictional field. It
checks CLI/MCP and nonempty injection without printing the value, then purges local
authorization. Revoke any created disposable backend Agent in the panel after QA.
A timed-out job cannot be resumed through its old approval URL. This is CI-build
integration evidence, not production-signature or publication evidence.
