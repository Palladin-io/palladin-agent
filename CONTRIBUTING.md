# Contributing to Palladin Agent

Palladin Agent handles access to passwords and other credentials. Start with a
public issue describing the problem, threat model, compatibility impact, and
proposed tests before opening a substantial pull request. Report vulnerabilities
privately according to `SECURITY.md`.

## Security and compatibility

Do not weaken the zero-knowledge boundary, native secure-storage guarantees,
origin and approval checks, secret masking, signed release policy, or script-free
npm installation. Never include real credentials, signing material, or private
keys in issues, fixtures, logs, screenshots, or pull requests.

Changes to frozen contracts or cryptographic wire formats require an explicit
version and migration decision. Released contract directories are immutable.

The repository package manifests remain private source workspaces. Release
automation constructs public, exact-version npm packages in isolated staging
directories and verifies their contents before publication. Do not publish a
source workspace directly or add npm lifecycle scripts.

Every change must include appropriate positive and negative tests. Run the Node
and Rust checks documented in `AGENTS.md` before requesting review.

## Legal terms

By contributing, you agree that your contribution is licensed under the license
applicable to the files you modify.

Every commit must include a Developer Certificate of Origin sign-off:

    Signed-off-by: Your Name <your.email@example.com>

Add it with `git commit -s`. Do not submit code copied from another project
unless its source, copyright, and license are identified and compatible.

Submitting a contribution does not grant rights to Palladin trademarks.
