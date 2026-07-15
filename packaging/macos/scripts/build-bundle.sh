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
Usage: build-bundle.sh --binary PATH --profile PATH --output-dir PATH
                       --architecture arm64|x86_64|universal
                       --marketing-version N[.N[.N]] --bundle-version N[.N[.N]]

Required environment:
  PALLADIN_APPLICATION_IDENTIFIER  Exact TEAMID.io.palladin.runtime value.
  PALLADIN_KEYCHAIN_ACCESS_GROUP   Exact TEAMID.io.palladin.runtime.session-v2 value embedded in the binary.
USAGE
  exit 64
}

binary=""
profile=""
output_dir=""
architecture=""
marketing_version=""
bundle_version=""

while (( $# > 0 )); do
  case "$1" in
    --binary) [[ $# -ge 2 ]] || usage; binary="$2"; shift 2 ;;
    --profile) [[ $# -ge 2 ]] || usage; profile="$2"; shift 2 ;;
    --output-dir) [[ $# -ge 2 ]] || usage; output_dir="$2"; shift 2 ;;
    --architecture) [[ $# -ge 2 ]] || usage; architecture="$2"; shift 2 ;;
    --marketing-version) [[ $# -ge 2 ]] || usage; marketing_version="$2"; shift 2 ;;
    --bundle-version) [[ $# -ge 2 ]] || usage; bundle_version="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

application_identifier="${PALLADIN_APPLICATION_IDENTIFIER:-}"
access_group="${PALLADIN_KEYCHAIN_ACCESS_GROUP:-}"
[[ -n "$binary" && -n "$profile" && -n "$output_dir" ]] || usage
[[ "$architecture" == "arm64" || "$architecture" == "x86_64" || "$architecture" == "universal" ]] ||
  die "architecture must be arm64, x86_64 or universal"
[[ "$marketing_version" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] ||
  die "marketing version must contain one to three numeric components"
[[ "$bundle_version" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] ||
  die "bundle version must contain one to three numeric components"
validate_contract_identifiers "$application_identifier" "$access_group"
require_regular_file "$PACKAGING_DIR/Info.plist.in" "Info.plist template"
require_regular_file "$PACKAGING_DIR/PalladinRuntime.entitlements.in" "entitlements template"
require_regular_file "$profile" "provisioning profile"
require_empty_output_path "$output_dir" "output directory"
assert_binary_contract "$binary" "$access_group" "$architecture"
assert_binary_session_contract "$binary"

output_parent="$(dirname -- "$output_dir")"
mkdir -p "$output_parent"
work_dir="$(mktemp -d "$output_parent/.palladin-macos-bundle.XXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

decoded_profile="$work_dir/profile.plist"
decode_provisioning_profile "$profile" "$decoded_profile"
validate_profile_contract "$decoded_profile" "$application_identifier" "$access_group"

team_identifier="$(contract_team_identifier "$application_identifier")"
bundle_root="$work_dir/output"
app_path="$bundle_root/PalladinRuntime.app"
contents_path="$app_path/Contents"
mkdir -p "$contents_path/MacOS"
install -m 0755 "$binary" "$contents_path/MacOS/palladin"
install -m 0644 "$profile" "$contents_path/embedded.provisionprofile"

sed \
  -e "s/@BUNDLE_IDENTIFIER@/$PALLADIN_BUNDLE_IDENTIFIER/g" \
  -e "s/@MARKETING_VERSION@/$marketing_version/g" \
  -e "s/@BUNDLE_VERSION@/$bundle_version/g" \
  "$PACKAGING_DIR/Info.plist.in" >"$contents_path/Info.plist"

entitlements_path="$bundle_root/PalladinRuntime.entitlements.plist"
sed \
  -e "s/@APPLICATION_IDENTIFIER@/$application_identifier/g" \
  -e "s/@TEAM_IDENTIFIER@/$team_identifier/g" \
  -e "s/@KEYCHAIN_ACCESS_GROUP@/$access_group/g" \
  "$PACKAGING_DIR/PalladinRuntime.entitlements.in" >"$entitlements_path"

/usr/bin/plutil -lint "$contents_path/Info.plist" >/dev/null
/usr/bin/plutil -lint "$entitlements_path" >/dev/null
if grep -R -E -q '@[A-Z_]+@' "$bundle_root"; then
  die "generated bundle contains an unresolved template token"
fi
assert_plist_contract "$entitlements_path" "$application_identifier" "$access_group"

mv -- "$bundle_root" "$output_dir"
printf 'Prepared unsigned macOS bundle for %s at %s\n' "$architecture" "$output_dir"
printf 'The bundle is not distributable until sign-notarize.sh completes successfully.\n'
