#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat >&2 <<'USAGE'
Usage: sign-notarize.sh --bundle-dir PATH --architecture arm64|x86_64|universal
                         --identity "Developer ID Application: ... (TEAMID)"
                         --notary-key PATH --notary-key-id ID --notary-issuer UUID
                         --output-archive PATH

Required environment:
  PALLADIN_APPLICATION_IDENTIFIER  Exact TEAMID.io.palladin.runtime value.
  PALLADIN_KEYCHAIN_ACCESS_GROUP   Exact TEAMID.io.palladin.runtime.session-v2 value.
USAGE
  exit 64
}

bundle_dir=""
architecture=""
identity=""
notary_key=""
notary_key_id=""
notary_issuer=""
output_archive=""

while (( $# > 0 )); do
  case "$1" in
    --bundle-dir) [[ $# -ge 2 ]] || usage; bundle_dir="$2"; shift 2 ;;
    --architecture) [[ $# -ge 2 ]] || usage; architecture="$2"; shift 2 ;;
    --identity) [[ $# -ge 2 ]] || usage; identity="$2"; shift 2 ;;
    --notary-key) [[ $# -ge 2 ]] || usage; notary_key="$2"; shift 2 ;;
    --notary-key-id) [[ $# -ge 2 ]] || usage; notary_key_id="$2"; shift 2 ;;
    --notary-issuer) [[ $# -ge 2 ]] || usage; notary_issuer="$2"; shift 2 ;;
    --output-archive) [[ $# -ge 2 ]] || usage; output_archive="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

application_identifier="${PALLADIN_APPLICATION_IDENTIFIER:-}"
access_group="${PALLADIN_KEYCHAIN_ACCESS_GROUP:-}"
[[ -n "$bundle_dir" && -n "$identity" && -n "$notary_key" && -n "$output_archive" ]] || usage
[[ "$architecture" == "arm64" || "$architecture" == "x86_64" || "$architecture" == "universal" ]] ||
  die "architecture must be arm64, x86_64 or universal"
[[ "$notary_key_id" =~ ^[A-Z0-9]+$ ]] || die "notary key ID has an invalid format"
[[ "$notary_issuer" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] ||
  die "notary issuer has an invalid format"
validate_contract_identifiers "$application_identifier" "$access_group"
expected_team="$(contract_team_identifier "$application_identifier")"
[[ "$identity" =~ ^Developer\ ID\ Application:\ .+\ \(([A-Z0-9]{10})\)$ ]] ||
  die "signing identity must be a Developer ID Application identity"
[[ "${BASH_REMATCH[1]}" == "$expected_team" ]] ||
  die "signing identity Team ID does not match the application identifier"
require_regular_file "$notary_key" "notary private key"
notary_mode="$(stat -f '%Lp' "$notary_key")" || die "cannot inspect notary private key permissions"
(( (8#$notary_mode & 077) == 0 )) || die "notary private key must not be accessible by group or others"
require_empty_output_path "$output_archive" "output archive"

prepared_app_path="$bundle_dir/PalladinRuntime.app"
entitlements_path="$bundle_dir/PalladinRuntime.entitlements.plist"
[[ -d "$prepared_app_path" && ! -L "$prepared_app_path" ]] ||
  die "prepared app bundle is unavailable: $prepared_app_path"
require_regular_file "$entitlements_path" "generated entitlements"
assert_plist_contract "$entitlements_path" "$application_identifier" "$access_group"
assert_binary_contract "$prepared_app_path/Contents/MacOS/palladin" "$access_group" "$architecture"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-notary.XXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
app_path="$work_dir/PalladinRuntime.app"
ditto "$prepared_app_path" "$app_path"
decoded_profile="$work_dir/profile.plist"
decode_provisioning_profile "$app_path/Contents/embedded.provisionprofile" "$decoded_profile"
validate_profile_contract "$decoded_profile" "$application_identifier" "$access_group"

codesign --force --timestamp --options runtime \
  --entitlements "$entitlements_path" \
  --sign "$identity" \
  "$app_path"

codesign --verify --strict --verbose=2 "$app_path" >/dev/null 2>&1 ||
  die "bundle signature validation failed before notarization"
signature_details="$(codesign -d --verbose=4 "$app_path" 2>&1)" ||
  die "bundle signature details are unavailable"
grep -F -x -q "TeamIdentifier=$expected_team" <<<"$signature_details" ||
  die "signed bundle Team ID does not match the application identifier"
grep -E -q '^CodeDirectory .*flags=.*\(runtime\)' <<<"$signature_details" ||
  die "signed bundle does not enable Hardened Runtime"

submission_archive="$work_dir/submission.zip"
submission_result="$work_dir/notary-result.json"
ditto -c -k --keepParent "$app_path" "$submission_archive"
if ! xcrun notarytool submit "$submission_archive" \
  --key "$notary_key" \
  --key-id "$notary_key_id" \
  --issuer "$notary_issuer" \
  --wait \
  --output-format json >"$submission_result"; then
  die "Apple notary service rejected or could not process the submission"
fi
notary_status="$(/usr/bin/plutil -extract status raw "$submission_result" 2>/dev/null)" ||
  die "notary response did not contain a status"
[[ "$notary_status" == "Accepted" ]] || die "notary submission status is not Accepted"

xcrun stapler staple "$app_path" >/dev/null
xcrun stapler validate "$app_path" >/dev/null
spctl --assess --type execute --verbose=2 "$app_path" >/dev/null 2>&1 ||
  die "Gatekeeper rejected the notarized bundle"

"$SCRIPT_DIR/verify-bundle.sh" --app "$app_path" --architecture "$architecture"
mkdir -p "$(dirname -- "$output_archive")"
temporary_output="$work_dir/final.zip"
ditto -c -k --keepParent "$app_path" "$temporary_output"
mv -- "$temporary_output" "$output_archive"
printf 'Signed, notarized and verified macOS archive: %s\n' "$output_archive"
