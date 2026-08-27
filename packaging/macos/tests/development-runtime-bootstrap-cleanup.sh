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
helper="$test_root/palladin-keychain-helper-v1"
cargo_argument_log="$test_root/cargo-arguments.log"

cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

mkdir -p "$tree/packaging/macos/scripts" "$tree/runtime/target/debug" "$test_tmp" "$fake_bin"
cp "$DEVELOPMENT_SCRIPT" "$tree/packaging/macos/scripts/development-runtime.sh"
chmod 700 "$tree/packaging/macos/scripts/development-runtime.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$tree/runtime/target/debug/palladin"
chmod 700 "$tree/runtime/target/debug/palladin"
printf '#!/usr/bin/env bash\nexit 0\n' >"$tree/runtime/target/debug/palladin-macos-keychain-helper"
chmod 700 "$tree/runtime/target/debug/palladin-macos-keychain-helper"

# The real trust-setting operation deliberately requires user-present macOS
# authorization. These command doubles isolate the first-run cleanup control
# flow without weakening or bypassing that operating-system boundary.
cat >"$fake_bin/cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${PALLADIN_CARGO_ARGUMENT_LOG:?}"
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
  find-generic-password)
    if [[ "${PALLADIN_TEST_HELPER_ITEMS_PRESENT:-0}" == 1 ]]; then
      exit 0
    fi
    exit 44
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
  identifier='io.palladin.runtime.development'
  if [[ " $* " == *'palladin-keychain-helper'* ]]; then
    identifier='io.palladin.runtime.development.keychain-helper.v1'
  fi
  cat >&2 <<'DETAILS'
Authority=Palladin Local Development
TeamIdentifier=not set
CodeDirectory v=20400 size=1 flags=0x0(none) hashes=1+0 location=embedded
DETAILS
  printf 'Identifier=%s\n' "$identifier" >&2
elif [[ " $* " == *' -r- '* ]]; then
  identifier='io.palladin.runtime.development'
  if [[ " $* " == *'palladin-keychain-helper'* ]]; then
    identifier='io.palladin.runtime.development.keychain-helper.v1'
  fi
  printf 'designated => identifier "%s" and certificate root = H"0123456789abcdef0123456789abcdef01234567"\n' "$identifier" >&2
elif [[ " $* " == *' --entitlements '* ]]; then
  printf '<?xml version="1.0"?><plist version="1.0"><dict/></plist>\n' >&2
fi
EOF

chmod 700 "$fake_bin/cargo" "$fake_bin/file" "$fake_bin/security" "$fake_bin/codesign"

TMPDIR="$test_tmp" PATH="$fake_bin:$PATH" PALLADIN_CARGO_ARGUMENT_LOG="$cargo_argument_log" \
  PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
  PALLADIN_DEVELOPMENT_HELPER_PATH="$helper" \
  "$tree/packaging/macos/scripts/development-runtime.sh" run -- --version >/dev/null

[[ -f "$keychain" && ! -L "$keychain" ]]
grep -F -x -q 'build --locked -p palladin-cli' "$cargo_argument_log"
grep -F -x -q 'build --locked -p palladin-macos-keychain-helper' "$cargo_argument_log"
if compgen -G "$test_tmp/palladin-development-signing.*" >/dev/null; then
  printf 'first development run left bootstrap key material behind\n' >&2
  exit 1
fi

installed_helper_checksum="$(cksum "$helper")"
printf '# changed helper implementation\n' >>"$tree/runtime/target/debug/palladin-macos-keychain-helper"
replacement_error="$test_root/helper-replacement-error.txt"
if TMPDIR="$test_tmp" PATH="$fake_bin:$PATH" PALLADIN_CARGO_ARGUMENT_LOG="$cargo_argument_log" \
  PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
  PALLADIN_DEVELOPMENT_HELPER_PATH="$helper" \
  "$tree/packaging/macos/scripts/development-runtime.sh" migrate-keychain-access \
    >"$replacement_error" 2>&1; then
  printf 'migration unexpectedly replaced the versioned development helper\n' >&2
  exit 1
fi
grep -F -q 'refusing to replace the versioned Keychain helper in place' "$replacement_error"
[[ "$(cksum "$helper")" == "$installed_helper_checksum" ]]

reset_error="$test_root/helper-reset-error.txt"
if TMPDIR="$test_tmp" PATH="$fake_bin:$PATH" PALLADIN_TEST_HELPER_ITEMS_PRESENT=1 \
  PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
  PALLADIN_DEVELOPMENT_HELPER_PATH="$helper" \
  "$tree/packaging/macos/scripts/development-runtime.sh" reset --confirm \
    >"$reset_error" 2>&1; then
  printf 'reset unexpectedly removed a helper that owns Login Keychain items\n' >&2
  exit 1
fi
grep -F -q 'refusing to reset while versioned helper-owned Login Keychain items exist' \
  "$reset_error"
[[ -f "$keychain" && ! -L "$keychain" ]]
[[ "$(cksum "$helper")" == "$installed_helper_checksum" ]]

launcher="$test_root/palladin"
"$tree/packaging/macos/scripts/development-runtime.sh" install-launcher "$launcher" >/dev/null
: >"$cargo_argument_log"
TMPDIR="$test_tmp" PATH="$fake_bin:$PATH" PALLADIN_CARGO_ARGUMENT_LOG="$cargo_argument_log" \
  PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
  PALLADIN_DEVELOPMENT_HELPER_PATH="$helper" \
  "$launcher" --local-development --version >/dev/null
grep -F -x -q 'build --locked -p palladin-cli --features local-development' "$cargo_argument_log"

printf 'Verified first-run development signing bootstrap cleanup.\n'
