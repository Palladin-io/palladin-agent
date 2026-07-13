---
name: pr-review
description: Reviews a pull request in the Palladin Agent CLI and native runtime for correctness, fail-closed secret storage, CLI UX, packaging, and cross-platform security. Posts findings as a structured GitHub PR comment.
argument-hint: <pr-number>
disable-model-invocation: true
allowed-tools: Read Grep Glob Bash(gh pr view *) Bash(gh pr diff *) Bash(gh pr comment *) Bash(gh api *) Bash(gh api graphql *) Bash(git log *) Bash(npm *) Bash(cargo *) Bash(bash *) Bash(shellcheck *) Bash(actionlint *)
effort: high
---

# PR Review — Palladin Agent CLI and Native Runtime

`PR_NUMBER` below is a symbolic placeholder. Parse the PR number from the explicit user request and replace the placeholder in every command before executing it. Never guess a PR number.

Before reviewing, materialize the context files referenced later in this workflow:

```bash
REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner')
gh pr view $PR_NUMBER --json number,title,body,author,additions,deletions,changedFiles,baseRefName,headRefName,reviews > /tmp/pr_reviews.json
gh api "repos/$REPO/pulls/$PR_NUMBER/comments" > /tmp/pr_inline_comments.json
gh pr diff $PR_NUMBER > /tmp/pr_diff.patch
```

Fail the review setup if any command above fails; never continue with missing or stale context files.

## Pull Request Context

**Metadata:**
- Run: `gh pr view $PR_NUMBER --json number,title,body,author,additions,deletions,changedFiles,baseRefName,headRefName 2>/dev/null || echo "PR metadata unavailable"`

**Changed files:**
- Run: `gh pr diff $PR_NUMBER --name-only 2>/dev/null || echo "No changed files"`

**Diff (first 50 000 chars):**
- Run: `gh pr diff $PR_NUMBER 2>/dev/null | head -c 50000`

---

## How to Conduct the Review

0. **Sprawdź poprzednie komentarze** — zanim przejdziesz do nowego kodu, przeczytaj `/tmp/pr_reviews.json` i `/tmp/pr_inline_comments.json`. Dla każdego wątku REQUEST_CHANGES: ustal czy problem został zaadresowany w aktualnym diffie.
1. Read `AGENTS.md` — source of truth for project conventions.
2. Load [criteria.md](criteria.md) — detailed review checklist. Read it fully before starting.
3. For each changed file: use `Read`, `Grep`, `Glob` to explore related files beyond the diff.
4. Cite **file path and line number** for every issue.
5. One clear sentence per finding.

## Review Focus Areas

Cover all sections from `criteria.md`:
- TypeScript: strict mode, no `any`, native dispatcher containment and argument forwarding
- Rust: formatting, Clippy, tests, error handling, and feature-gated platform code
- Security: no plaintext secret fallback, organization-wide API-key ownership, per-Agent identity keys, fail-closed native storage
- Multi-profile: commands use native `RuntimeService` profile resolution and preserve registry consistency
- CLI UX: clear error messages, correct exit codes, security tier shown where needed
- Packaging: fixed platform package, no lifecycle download, no `PATH`/TypeScript fallback, signature and entitlement verification
- Build: Node and Rust checks relevant to the changed files pass

## Output

Submit a proper GitHub pull request review — inline file comments + a final verdict. Do NOT use `gh pr comment`.

### Step 0 — obsłuż poprzednie komentarze

Dla każdego wątku z poprzednich review (`/tmp/pr_reviews.json`, `/tmp/pr_inline_comments.json`):

**Jeśli problem został zaadresowany** — odpowiedz na komentarz i rozwiąż wątek:
```bash
REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner')
gh api "repos/${REPO}/pulls/$PR_NUMBER/comments/{COMMENT_ID}/replies" \
  --method POST --field body="✅ Zaadresowane — [opis co zostało zrobione]."

gh api graphql -f query='
  query($owner:String!,$repo:String!,$pr:Int!) {
    repository(owner:$owner,name:$repo) {
      pullRequest(number:$pr) {
        reviewThreads(first:50) {
          nodes { id isResolved comments(first:1) { nodes { databaseId } } }
        }
      }
    }
  }
' -f owner="$(echo $REPO | cut -d/ -f1)" \
  -f repo="$(echo $REPO | cut -d/ -f2)" \
  -F pr=$PR_NUMBER \
  --jq '.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved==false) | {id, commentId: .comments.nodes[0].databaseId}'

gh api graphql -f query='mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}' \
  -f id="{THREAD_NODE_ID}"
```

**Jeśli problem NIE został zaadresowany** — wymień go w `body` nowego review z odwołaniem.

### Step 1 — determine the verdict

- `REQUEST_CHANGES` — any Critical or Warning findings
- `APPROVE` — only Suggestions / Highlights, or a clean PR
- `COMMENT` — only if literally cannot determine a verdict

### Step 2 — build `/tmp/review.json`

```json
{
  "body": "## 🔍 PR Review — Palladin Agent CLI\n\n### Summary\n2–3 sentence verdict.\n\n### ✅ Highlights\n- good pattern noted",
  "event": "REQUEST_CHANGES",
  "comments": [
    {
      "path": "src/crypto/secure-storage.ts",
      "line": 42,
      "side": "RIGHT",
      "body": "🚨 **Critical** — one-sentence explanation."
    }
  ]
}
```

### Step 3 — submit

```bash
REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner')
gh api "repos/${REPO}/pulls/$PR_NUMBER/reviews" --method POST --input /tmp/review.json
```

### Rules

- **Inline comments** — only on lines present in the diff (`/tmp/pr_diff.patch`).
- **`line`** — file line number (not diff position). **`side`** — always `"RIGHT"` for added/changed lines.
- **Severity prefix** — `🚨 Critical —`, `⚠️ Warning —`, or `💡 Suggestion —`.
- Omit `"comments"` key entirely if there are no file-level findings.
