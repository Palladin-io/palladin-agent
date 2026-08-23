#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly DEVELOPMENT_SCRIPT="$REPOSITORY_ROOT/packaging/macos/scripts/development-runtime.sh"
readonly IDENTITY_NAME="Palladin Local Development"
readonly IDENTIFIER="io.palladin.runtime.development"

[[ "$(uname -s)" == "Darwin" ]] || {
  printf 'Skipping macOS development signing contract outside macOS.\n'
  exit 0
}

test_root="$(mktemp -d "${TMPDIR:-/tmp}/palladin-development-signing-test.XXXXXX")"
keychain="$test_root/palladin-development.keychain-db"
tree_one="$test_root/worktree-one"
tree_two="$test_root/worktree-two"

cleanup() {
  if [[ -f "$keychain" && ! -L "$keychain" ]]; then
    PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
      "$tree_one/packaging/macos/scripts/development-runtime.sh" reset --confirm >/dev/null 2>&1 || true
  fi
  rm -rf -- "$test_root"
}
trap cleanup EXIT

prepare_tree() {
  local tree="$1"
  local return_code="$2"
  mkdir -p "$tree/packaging/macos/scripts" "$tree/runtime/target/debug"
  cp "$DEVELOPMENT_SCRIPT" "$tree/packaging/macos/scripts/development-runtime.sh"
  chmod 700 "$tree/packaging/macos/scripts/development-runtime.sh"
  printf 'int main(void) { return %s; }\n' "$return_code" >"$tree/runtime/palladin.c"
  xcrun clang "$tree/runtime/palladin.c" -o "$tree/runtime/target/debug/palladin"
}

requirement() {
  codesign -d -r- "$1/runtime/target/debug/palladin" 2>&1 |
    sed -n '/designated => /s/^# //p'
}

cdhash() {
  codesign -d --verbose=4 "$1/runtime/target/debug/palladin" 2>&1 |
    sed -n 's/^CDHash=//p'
}

prepare_tree "$tree_one" 11
prepare_tree "$tree_two" 12

unsigned_requirement_one="$(requirement "$tree_one")"
unsigned_requirement_two="$(requirement "$tree_two")"
[[ "$unsigned_requirement_one" == designated\ =\>\ cdhash\ * ]]
[[ "$unsigned_requirement_two" == designated\ =\>\ cdhash\ * ]]
[[ "$unsigned_requirement_one" != "$unsigned_requirement_two" ]]

PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
  "$tree_one/packaging/macos/scripts/development-runtime.sh" bootstrap >/dev/null
PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
  "$tree_one/packaging/macos/scripts/development-runtime.sh" bootstrap >/dev/null

for tree in "$tree_one" "$tree_two"; do
  PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
    "$tree/packaging/macos/scripts/development-runtime.sh" sign >/dev/null
  PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
    "$tree/packaging/macos/scripts/development-runtime.sh" verify >/dev/null
done

signed_requirement_one="$(requirement "$tree_one")"
signed_requirement_two="$(requirement "$tree_two")"
[[ "$signed_requirement_one" == "$signed_requirement_two" ]]
[[ "$signed_requirement_one" == *"identifier \"$IDENTIFIER\" and certificate root"* ]]
[[ "$signed_requirement_one" != *'cdhash '* ]]
[[ "$(cdhash "$tree_one")" != "$(cdhash "$tree_two")" ]]

for tree in "$tree_one" "$tree_two"; do
  details="$(codesign -d --verbose=4 "$tree/runtime/target/debug/palladin" 2>&1)"
  grep -F -x -q "Identifier=$IDENTIFIER" <<<"$details"
  grep -F -x -q "Authority=$IDENTITY_NAME" <<<"$details"
  grep -F -x -q 'TeamIdentifier=not set' <<<"$details"
  grep -E -q '^CodeDirectory .*flags=0x0\(none\)' <<<"$details"
  if grep -F -q 'Signature=adhoc' <<<"$details"; then
    printf 'development runtime remained ad hoc signed\n' >&2
    exit 1
  fi
done

launcher="$test_root/bin/palladin"
mkdir -p "$(dirname -- "$launcher")"
PALLADIN_DEVELOPMENT_KEYCHAIN_PATH="$keychain" \
  "$tree_one/packaging/macos/scripts/development-runtime.sh" install-launcher "$launcher" >/dev/null
[[ -x "$launcher" && ! -L "$launcher" ]]
grep -F -q 'development-runtime.sh run -- "$@"' "$launcher"

release_error="$test_root/release-error.txt"
if PALLADIN_APPLICATION_IDENTIFIER='A1B2C3D4E5.io.palladin.runtime' \
  PALLADIN_KEYCHAIN_ACCESS_GROUP='A1B2C3D4E5.io.palladin.runtime.session-v2' \
  "$REPOSITORY_ROOT/packaging/macos/scripts/sign-notarize.sh" \
    --bundle-dir "$test_root/missing-bundle" \
    --architecture arm64 \
    --identity "$IDENTITY_NAME" \
    --notary-key "$test_root/missing-notary-key" \
    --notary-key-id TESTKEY123 \
    --notary-issuer 00000000-0000-0000-0000-000000000000 \
    --output-archive "$test_root/missing-output.zip" >"$release_error" 2>&1; then
  printf 'release signing unexpectedly accepted the development identity\n' >&2
  exit 1
fi
grep -F -q 'signing identity must be a Developer ID Application identity' "$release_error"

printf 'Verified stable local macOS development signing contract.\n'
