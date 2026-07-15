---
name: fix-pr
description: Implementuje poprawki na podstawie komentarzy review — czyta nierozwiązane uwagi, modyfikuje kod, buduje, commituje, odpowiada na komentarze i resolvuje wątki.
argument-hint: <pr-number>
disable-model-invocation: true
allowed-tools: Read Write Edit Grep Glob Bash(gh pr *) Bash(gh api *) Bash(gh api graphql *) Bash(git *) Bash(npm *) Bash(cargo *) Bash(bash *) Bash(shellcheck *) Bash(actionlint *)
effort: high
---

# Fix PR — Palladin Agent CLI

`PR_NUMBER` below is a symbolic placeholder. Parse the PR number from the explicit user request and replace the placeholder in every command before executing it. Never guess a PR number.

## Kontekst PR

**Metadane:**
- Run: `gh pr view $PR_NUMBER --json number,title,headRefName,baseRefName,author 2>/dev/null`

**Poprzednie review (REQUEST_CHANGES do naprawy):**
- Run: `gh pr view $PR_NUMBER --json reviews 2>/dev/null`

**Komentarze inline:**
- Run: `gh api repos/$(gh repo view --json nameWithOwner --jq '.nameWithOwner')/pulls/$PR_NUMBER/comments 2>/dev/null`

**Zmienione pliki:**
- Run: `gh pr diff $PR_NUMBER --name-only 2>/dev/null`

---

## Jak przeprowadzić naprawę

### Krok 1 — przygotuj branch

```bash
HEAD=$(gh pr view $PR_NUMBER --json headRefName --jq '.headRefName')
git fetch origin "$HEAD"
git checkout "$HEAD"
```

### Krok 2 — przeanalizuj komentarze

Przeczytaj wszystkie nierozwiązane komentarze. Dla każdego:
- Zrozum problem — użyj `Read`, `Grep`, `Glob` żeby przejrzeć powiązany kod
- Ustal konkretną zmianę do wprowadzenia

### Krok 3 — wprowadź poprawki

Edytuj pliki używając `Edit`. Przestrzegaj konwencji (AGENTS.md):
- Publiczny entry point TypeScript tylko uruchamia dokładny pakiet natywny — bez `PATH`, pobierania, shella i fallbacku do legacy TypeScript
- Brak plaintext fallbacku: błąd systemowego magazynu kończy operację; sekret nie trafia do pliku, env ani argv
- API key należy do organizacji i może być współdzielony przez wielu Agentów; `agentId` oraz X25519/Ed25519 pozostają per Agent
- Registry przechowuje wyłącznie jawne referencje; usunięcie jednego Agenta nie usuwa współdzielonego credentialu używanego przez innych
- macOS Hardened wymaga dokładnego podpisu, provisioning profile, entitlements i Data Protection Keychain; brak autoryzacji oznacza Unavailable
- Nigdy nie loguj klucza prywatnego ani API key w `console.*`

### Krok 4 — zbuduj i sprawdź typy

```bash
npm ci --workspaces=false
npm run lint
npm run build
cd runtime && cargo fmt --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked
```

Jeśli lint lub build nie przechodzą — napraw przed przejściem dalej.

### Krok 5 — commituj

```bash
git add [konkretne pliki]
git commit -m "fix: [opis co naprawiono]"
git push
```

Commit message po polsku, zwięzły.

### Krok 6 — odpowiedz na komentarze i resolvuj wątki

```bash
REPO=$(gh repo view --json nameWithOwner --jq '.nameWithOwner')

gh api "repos/${REPO}/pulls/$PR_NUMBER/comments/{COMMENT_ID}/replies" \
  --method POST \
  --field body="✅ Naprawione — [opis co zostało zrobione]."

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
  -F pr=$PR_NUMBER

gh api graphql \
  -f query='mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}' \
  -f id="{THREAD_NODE_ID}"
```

### Krok 7 — podsumowanie na PR

```bash
gh pr comment $PR_NUMBER --body "## 🔧 Fix PR — podsumowanie

### Naprawione
- \`ścieżka/do/pliku.ts:42\` — co zmieniono

### Świadomie pominięte
- [opcjonalnie]"
```
