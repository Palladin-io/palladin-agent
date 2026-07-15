#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat >&2 <<'USAGE'
Usage: verify-bundle.sh --app PATH --architecture arm64|x86_64|universal

Required environment:
  PALLADIN_APPLICATION_IDENTIFIER  Exact TEAMID.io.palladin.runtime value.
  PALLADIN_KEYCHAIN_ACCESS_GROUP   Exact TEAMID.io.palladin.runtime value.

The command verifies a final Developer ID-signed, notarized and stapled bundle.
USAGE
  exit 64
}

app_path=""
architecture=""
while (( $# > 0 )); do
  case "$1" in
    --app) [[ $# -ge 2 ]] || usage; app_path="$2"; shift 2 ;;
    --architecture) [[ $# -ge 2 ]] || usage; architecture="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

application_identifier="${PALLADIN_APPLICATION_IDENTIFIER:-}"
access_group="${PALLADIN_KEYCHAIN_ACCESS_GROUP:-}"
[[ -n "$app_path" ]] || usage
[[ "$architecture" == "arm64" || "$architecture" == "x86_64" || "$architecture" == "universal" ]] ||
  die "architecture must be arm64, x86_64 or universal"
validate_contract_identifiers "$application_identifier" "$access_group"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle is not a directory: $app_path"

info_plist="$app_path/Contents/Info.plist"
binary="$app_path/Contents/MacOS/palladin"
embedded_profile="$app_path/Contents/embedded.provisionprofile"
require_regular_file "$info_plist" "Info.plist"
require_regular_file "$embedded_profile" "embedded provisioning profile"
assert_binary_contract "$binary" "$access_group" "$architecture"
[[ "$(plist_read "$info_plist" 'CFBundleIdentifier')" == "$PALLADIN_BUNDLE_IDENTIFIER" ]] ||
  die "bundle identifier is not $PALLADIN_BUNDLE_IDENTIFIER"
[[ "$(plist_read "$info_plist" 'CFBundleExecutable')" == "palladin" ]] ||
  die "bundle executable is not palladin"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-macos-verify.XXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

decoded_profile="$work_dir/profile.plist"
decode_provisioning_profile "$embedded_profile" "$decoded_profile"
validate_profile_contract "$decoded_profile" "$application_identifier" "$access_group"

codesign --verify --strict --verbose=2 "$app_path" >/dev/null 2>&1 ||
  die "bundle signature is invalid"
signature_details="$(codesign -d --verbose=4 "$app_path" 2>&1)" ||
  die "bundle signature details are unavailable"
grep -q '^Authority=Developer ID Application:' <<<"$signature_details" ||
  die "bundle is not signed with a Developer ID Application certificate"
grep -E -q '^CodeDirectory .*flags=.*\(runtime\)' <<<"$signature_details" ||
  die "bundle signature does not enable Hardened Runtime"
expected_team="$(contract_team_identifier "$application_identifier")"
grep -F -x -q "TeamIdentifier=$expected_team" <<<"$signature_details" ||
  die "bundle signature Team ID does not match the security contract"
grep -F -x -q "Identifier=$PALLADIN_BUNDLE_IDENTIFIER" <<<"$signature_details" ||
  die "bundle signature identifier does not match the bundle identifier"

signed_entitlements="$work_dir/signed-entitlements.plist"
codesign -d --entitlements "$signed_entitlements" "$app_path" >/dev/null 2>&1 ||
  die "signed entitlements cannot be extracted"
/usr/bin/plutil -lint "$signed_entitlements" >/dev/null ||
  die "signed entitlements are not a valid plist"
assert_plist_contract "$signed_entitlements" "$application_identifier" "$access_group"

xcrun stapler validate "$app_path" >/dev/null 2>&1 ||
  die "bundle has no valid stapled notarization ticket"
spctl --assess --type execute --verbose=2 "$app_path" >/dev/null 2>&1 ||
  die "Gatekeeper assessment rejected the bundle"

printf 'Verified signed and notarized macOS bundle for %s.\n' "$architecture"
