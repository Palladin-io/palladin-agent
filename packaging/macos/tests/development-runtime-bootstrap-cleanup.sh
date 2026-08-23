#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly DEVELOPMENT_SCRIPT="$REPOSITORY_ROOT/packaging/macos/scripts/development-runtime.sh"

[[ "$(uname -s)" == "Darwin" ]] || {
  printf 'Skipping macOS development signing bootstrap cleanup outside macOS.\n'
  exit 0
}

test_root="$(mktemp -d "${TMPDIR:-/tmp}/palladin-development-signing-cleanup-test.XXXXXX")"
tree="$test_root/worktree"
test_tmp="$test_root/tmp"
fake_bin="$test_root/bin"
keychain="$test_root/palladin-development.keychain-db"

cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

mkdir -p "$tree/packaging/macos/scripts" "$tree/runtime/target/debug" "$test_tmp" "$fake_bin"
cp "$DEVELOPMENT_SCRIPT" "$tree/packaging/macos/scripts/development-runtime.sh"
chmod 700 "$tree/packaging/macos/scripts/development-runtime.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$tree/runtime/target/debug/palladin"
chmod 700 "$tree/runtime/target/debug/palladin"

# The real trust-setting operation deliberately requires user-present macOS
# authorization. These command doubles isolate the first-run cleanup control
# flow without weakening or bypassing that operating-system boundary.
cat >"$fake_bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$fake_bin/file" <<'EOF'
#!/usr/bin/env bash
printf 'Mach-O 64-bit executable\n'
EOF

cat >"$fake_bin/security" <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

readonly fingerprint="0123456789ABCDEF0123456789ABCDEF01234567"

case "${1:-}" in
  create-keychain)
    keychain="${@: -1}"
    : >"$keychain"
    chmod 600 "$keychain"
    ;;
  find-certificate)
    if [[ " $* " == *' -Z '* ]]; then
      printf 'SHA-1 hash: %s\n' "$fingerprint"
    fi
    ;;
  find-identity)
    printf '  1) %s "Palladin Local Development"\n' "$fingerprint"
    printf '     1 valid identities found\n'
    ;;
  list-keychains)
    if [[ " $* " != *' -s '* ]]; then
      printf '    "/Library/Keychains/System.keychain"\n'
    fi
    ;;
  set-keychain-settings | unlock-keychain | import | set-key-partition-list | add-trusted-cert)
    ;;
  *)
    printf 'unexpected security command: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF

cat >"$fake_bin/codesign" <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

if [[ " $* " == *' --verbose=4 '* ]]; then
  cat >&2 <<'DETAILS'
Identifier=io.palladin.runtime.development
Authority=Palladin Local Development
TeamIdentifier=not set
CodeDirectory v=20400 size=1 flags=0x0(none) hashes=1+0 location=embedded
DETAILS
elif [[ " $* " == *' -r- '* ]]; then
  printf 'designated => identifier "io.palladin.runtime.development" and certificate root = H"0123456789abcdef0123456789abcdef01234567"\n' >&2
elif [[ " $* " == *' --entitlements '* ]]; then
  printf '<?xml version="1.0"?><plist version="1.0"><dict/></plist>\n' >&2
fi
EOF

chmod 700 "$fake_bin/cargo" "$fake_bin/file" "$fake_bin/security" "$fake_bin/codesign"

TMPDIR="$test_tmp" PATH="$fake_bin:$PATH" PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
  "$tree/packaging/macos/scripts/development-runtime.sh" run -- --version >/dev/null

[[ -f "$keychain" && ! -L "$keychain" ]]
if compgen -G "$test_tmp/palladin-development-signing.*" >/dev/null; then
  printf 'first development run left bootstrap key material behind\n' >&2
  exit 1
fi

printf 'Verified first-run development signing bootstrap cleanup.\n'
