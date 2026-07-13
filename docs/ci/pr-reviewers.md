# Pull Request Reviewers

The Agent CLI supports Claude Code and Codex as independent pull request reviewers. The existing Claude implementation is also used by `fix-pr.yml`.

## Manual flow

The Agent CLI repository is public, so subscription-backed reviews never run automatically. Both reviewers must be dispatched manually from `main`: `pr-review.yml` for Claude or `codex-pr-review.yml` for Codex. Both workflows are restricted to the repository owner so public contributors and collaborators cannot consume the configured subscription allowance.

The Codex authorization job additionally verifies repository write access before starting the job that receives the ChatGPT session. Dispatch Codex only after validating that the target pull request is appropriate for subscription-backed review.

## Results and failure isolation

Claude keeps the existing formal GitHub review behavior: `APPROVE` or `REQUEST_CHANGES`, inline comments, replies, and thread resolution.

Codex analysis runs in a separate read-only job and returns a structured result tied to the analyzed PR commit. A fresh publisher job refuses stale results, posts inline comments prefixed with `Codex`, and creates or updates one summary comment headed `Codex Review — APPROVED` or `Codex Review — CHANGES_REQUESTED`. The Codex summary is an advisory PR comment, so the same `github-actions[bot]` identity cannot overwrite Claude's formal verdict. A valid Codex review keeps the `Codex Review` check green regardless of verdict; Codex is advisory and Claude retains the formal blocking verdict.

The reviewers do not depend on each other. A Codex failure does not remove or modify a Claude review, and Codex never replies to or resolves Claude threads.

## Secrets, permissions, and security

| Reviewer | Required secret | API access |
|---|---|---|
| Claude Code | `CLAUDE_CODE_OAUTH_TOKEN` | Existing Claude Code subscription/session allowance |
| Codex | organization secret `CODEX_AUTH_JSON_B64` | ChatGPT-managed Codex subscription session |

The Codex workflow accepts manual dispatches only from `main`, so its definition and reviewer sources come from the trusted default branch. It never checks out or executes pull request code; it fetches the diff as untrusted review input. The Codex analysis job has only `contents: read` and `pull-requests: read`, and checkout credentials are not persisted.

The organization secret contains the Base64-encoded `auth.json` produced by a ChatGPT login and is exposed only to the Codex process. The runner validates `auth_mode=chatgpt`, drops `sudo`, starts Codex in an empty directory with a read-only sandbox, disables shell and external tools, and removes the temporary credential file on exit. The separate publisher receives only the structured review result and has `pull-requests: write`; it never receives the ChatGPT session.

Do not put either credential in repository variables, workflow inputs, prompts, artifacts, or logs. Restrict `CODEX_AUTH_JSON_B64` to the repositories that use Codex Review in the GitHub organization secret policy. Treat the source `auth.json` like a password. GitHub-hosted runners cannot persist a refreshed session back to the organization secret, so reseed it when authentication expires.

## Models, cost, and limits

`CODEX_REVIEW_MODEL` is an optional repository variable. When unset, Codex selects the workspace default model. Reviews consume the ChatGPT workspace's included Codex allowance and, after that allowance is exhausted, any configured ChatGPT workspace credits. They do not use Platform API billing. Large diffs and higher reasoning effort consume the subscription allowance faster.

Claude uses the configured `CLAUDE_MODEL` and the allowance associated with `CLAUDE_CODE_OAUTH_TOKEN`. Its session limit is shared by repositories using the same token. A session-limit failure is an infrastructure failure and can be retried after the allowance resets.

Current provider details:

- Codex subscription pricing and limits: <https://developers.openai.com/codex/pricing>
- Codex account auth in CI/CD: <https://learn.chatgpt.com/docs/auth/ci-cd-auth>
- Anthropic Claude Code costs: <https://code.claude.com/docs/en/costs>

## Rollback

Remove the repository secret `CODEX_AUTH_JSON_B64` to disable Codex Review completely. Claude Review and `fix-pr.yml` remain unchanged.
