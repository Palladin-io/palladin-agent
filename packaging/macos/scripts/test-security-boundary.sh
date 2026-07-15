#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
PACKAGING_DIR="$(dirname -- "$SCRIPT_DIR")"
readonly PACKAGING_DIR
# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat >&2 <<'USAGE'
Usage: test-security-boundary.sh --app PATH --entitlements PATH
                                 --identity "Developer ID Application: ... (TEAMID)"
                                 --homebrew-node PATH

Required environment:
  PALLADIN_APPLICATION_IDENTIFIER  Exact TEAMID.io.palladin.runtime value.
  PALLADIN_KEYCHAIN_ACCESS_GROUP   Exact TEAMID.io.palladin.runtime value.
  PALLADIN_SECURITY_TEST_CONFIRM   Must equal ephemeral-runner.

This test creates and then purges synthetic Palladin identities in the current OS account.
It never creates a legacy Login Keychain item and all untrusted queries disable authentication UI.
USAGE
  exit 64
}

app_path=""
entitlements=""
identity=""
homebrew_node=""
while (( $# > 0 )); do
  case "$1" in
    --app) [[ $# -ge 2 ]] || usage; app_path="$2"; shift 2 ;;
    --entitlements) [[ $# -ge 2 ]] || usage; entitlements="$2"; shift 2 ;;
    --identity) [[ $# -ge 2 ]] || usage; identity="$2"; shift 2 ;;
    --homebrew-node) [[ $# -ge 2 ]] || usage; homebrew_node="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "${PALLADIN_SECURITY_TEST_CONFIRM:-}" == "ephemeral-runner" ]] ||
  die "refusing to alter the current account without PALLADIN_SECURITY_TEST_CONFIRM=ephemeral-runner"
application_identifier="${PALLADIN_APPLICATION_IDENTIFIER:-}"
access_group="${PALLADIN_KEYCHAIN_ACCESS_GROUP:-}"
validate_contract_identifiers "$application_identifier" "$access_group"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle is unavailable: $app_path"
[[ "$identity" =~ ^Developer\ ID\ Application:\ .+\ \(([A-Z0-9]{10})\)$ ]] ||
  die "signing identity must be a Developer ID Application identity"
[[ "${BASH_REMATCH[1]}" == "$(contract_team_identifier "$application_identifier")" ]] ||
  die "signing identity Team ID does not match the application identifier"
require_regular_file "$homebrew_node" "Homebrew Node executable"
[[ -x "$homebrew_node" ]] || die "Homebrew Node is not executable"

binary="$app_path/Contents/MacOS/palladin"
require_regular_file "$binary" "signed runtime binary"
require_regular_file "$entitlements" "generated entitlements"
require_regular_file "$PACKAGING_DIR/tests/node-keyring-probe.mjs" "Node isolation probe"
require_regular_file "$PACKAGING_DIR/tests/untrusted-dpk-probe.swift" "Data Protection Keychain probe"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-boundary.XXXXXX")"
cleanup() {
  "$binary" purge --confirm >/dev/null 2>&1 || true
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

"$binary" purge --confirm >/dev/null 2>&1 || true
"$binary" init >/dev/null
"$binary" --id default security upgrade >/dev/null

registry="$HOME/.palladin/registry.json"
require_regular_file "$registry" "native public registry"
identity_id="$(/usr/bin/plutil -extract agents.0.identityId raw -o - "$registry")" ||
  die "could not read the public identity reference"
[[ "$identity_id" =~ ^[0-9a-f]{32}$ ]] || die "public identity reference has an invalid format"
account="$identity_id:x25519-private-key"

"$homebrew_node" "$PACKAGING_DIR/tests/node-keyring-probe.mjs" \
  "io.palladin.runtime" "$account"

swift_probe="$work_dir/untrusted-dpk-probe"
xcrun swiftc -O "$PACKAGING_DIR/tests/untrusted-dpk-probe.swift" -o "$swift_probe"
"$swift_probe" "$access_group" "io.palladin.runtime" "$account"

unsigned_binary="$work_dir/palladin-unsigned"
cp "$binary" "$unsigned_binary"
codesign --remove-signature "$unsigned_binary"
if "$unsigned_binary" --id default security upgrade >"$work_dir/unsigned.out" 2>&1; then
  die "unsigned clone unexpectedly opened the identity"
fi

fork_app="$work_dir/PalladinFork.app"
ditto "$app_path" "$fork_app"
codesign --force --sign - --options runtime --entitlements "$entitlements" "$fork_app" >/dev/null
if "$fork_app/Contents/MacOS/palladin" --id default security upgrade >"$work_dir/fork.out" 2>&1; then
  die "differently signed fork unexpectedly opened the identity"
fi

modified_app="$work_dir/PalladinModified.app"
ditto "$app_path" "$modified_app"
printf '\0' >>"$modified_app/Contents/MacOS/palladin"
if codesign --verify --strict "$modified_app" >/dev/null 2>&1; then
  die "modified bundle unexpectedly retained a valid signature"
fi
if "$modified_app/Contents/MacOS/palladin" --id default security upgrade \
  >"$work_dir/modified.out" 2>&1; then
  die "modified bundle unexpectedly opened the identity"
fi

update_app="$work_dir/PalladinUpdate.app"
ditto "$app_path" "$update_app"
current_version="$(plist_read "$update_app/Contents/Info.plist" 'CFBundleVersion')" ||
  die "update fixture lacks CFBundleVersion"
IFS='.' read -r -a version_parts <<<"$current_version"
last_index=$(( ${#version_parts[@]} - 1 ))
version_parts[last_index]=$(( 10#${version_parts[last_index]} + 1 ))
update_version="$(IFS='.'; printf '%s' "${version_parts[*]}")"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $update_version" \
  "$update_app/Contents/Info.plist"
codesign --force --timestamp --options runtime --entitlements "$entitlements" \
  --sign "$identity" "$update_app"
codesign --verify --strict "$update_app"
"$update_app/Contents/MacOS/palladin" --id default security upgrade >/dev/null

"$binary" agents create build >/dev/null
"$binary" agents rename build build-renamed >/dev/null
"$binary" --id build-renamed security upgrade >/dev/null
"$binary" agents set-default build-renamed >/dev/null
"$binary" agents set-default default >/dev/null
"$binary" agents delete build-renamed >/dev/null
if "$binary" --id build-renamed security upgrade >"$work_dir/deleted.out" 2>&1; then
  die "deleted profile unexpectedly remained usable"
fi
"$binary" --id default security upgrade >/dev/null

printf 'Verified Homebrew Node, unsigned clone, fork signature, modified binary, signed update, and profile lifecycle isolation.\n'
