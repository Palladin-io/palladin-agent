#!/usr/bin/env bash

set -euo pipefail

readonly PALLADIN_BUNDLE_IDENTIFIER="io.palladin.runtime"
readonly PALLADIN_APPLICATION_IDENTIFIER_SUFFIX=".io.palladin.runtime"
readonly PALLADIN_ACCESS_GROUP_SUFFIX=".io.palladin.runtime.session-v2"
readonly PALLADIN_IDENTITY_KEYCHAIN_SERVICE="io.palladin.runtime.session-v2.identity"
readonly PALLADIN_STATE_KEYCHAIN_SERVICE="io.palladin.runtime.session-v2.state"
readonly PALLADIN_ORGANIZATION_SLOT_SUFFIX="organization-api-key-v3"
readonly PALLADIN_X25519_SLOT_SUFFIX="x25519-private-key-v3"
readonly PALLADIN_ED25519_SLOT_SUFFIX="ed25519-secret-key-v3"
readonly PALLADIN_INVOCATION_SLOT_SUFFIX="invocation-authorization-seed-v2"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_regular_file() {
  local path="$1"
  local label="$2"
  [[ -f "$path" ]] || die "$label is not a regular file: $path"
  [[ ! -L "$path" ]] || die "$label must not be a symbolic link: $path"
}

require_empty_output_path() {
  local path="$1"
  local label="$2"
  [[ -n "$path" && "$path" != "/" ]] || die "$label is unsafe"
  [[ ! -e "$path" && ! -L "$path" ]] || die "$label already exists: $path"
}

plist_read() {
  /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null
}

plist_array_contains() {
  local plist="$1"
  local key="$2"
  local expected="$3"
  local index=0
  local value

  while value="$(plist_read "$plist" "$key:$index")"; do
    if [[ "$value" == "$expected" ]]; then
      return 0
    fi
    index=$((index + 1))
  done
  return 1
}

validate_contract_identifiers() {
  local application_identifier="$1"
  local access_group="$2"
  local expected_application_suffix="$PALLADIN_APPLICATION_IDENTIFIER_SUFFIX"
  local expected_access_group_suffix="$PALLADIN_ACCESS_GROUP_SUFFIX"

  [[ "$application_identifier" =~ ^[A-Z0-9]{10}\.io\.palladin\.runtime$ ]] ||
    die "application identifier must be TEAMID.$PALLADIN_BUNDLE_IDENTIFIER"
  [[ "$access_group" =~ ^[A-Z0-9]{10}\.io\.palladin\.runtime\.session-v2$ ]] ||
    die "Keychain access group must be TEAMID$PALLADIN_ACCESS_GROUP_SUFFIX"
  [[ "$application_identifier" == *"$expected_application_suffix" && "$application_identifier" != *'*'* ]] ||
    die "application identifier is not app-scoped"
  [[ "$access_group" == *"$expected_access_group_suffix" && "$access_group" != *'*'* ]] ||
    die "Keychain access group is not app-scoped"
  [[ "$(contract_team_identifier "$application_identifier")" == "$(contract_team_identifier "$access_group")" ]] ||
    die "application identifier and Keychain access group must use the same Team ID"
}

contract_team_identifier() {
  printf '%s\n' "${1%%.*}"
}

decode_provisioning_profile() {
  local source="$1"
  local destination="$2"

  require_command security
  require_regular_file "$source" "provisioning profile"
  security cms -D -i "$source" >"$destination" 2>/dev/null ||
    die "provisioning profile is not a valid CMS document"
  /usr/bin/plutil -lint "$destination" >/dev/null ||
    die "decoded provisioning profile is not a valid plist"
}

validate_profile_contract() {
  local profile_plist="$1"
  local application_identifier="$2"
  local access_group="$3"
  local team_identifier
  local expected_team
  local profile_application_identifier
  local entitlement_team
  local expiration
  local expiration_epoch
  local now_epoch

  validate_contract_identifiers "$application_identifier" "$access_group"
  expected_team="$(contract_team_identifier "$application_identifier")"
  profile_application_identifier="$(plist_read "$profile_plist" 'Entitlements:com.apple.application-identifier')" ||
    die "provisioning profile lacks com.apple.application-identifier"
  [[ "$profile_application_identifier" == "$application_identifier" ]] ||
    die "provisioning profile application identifier does not match the build contract"

  entitlement_team="$(plist_read "$profile_plist" 'Entitlements:com.apple.developer.team-identifier')" ||
    die "provisioning profile lacks com.apple.developer.team-identifier"
  team_identifier="$(plist_read "$profile_plist" 'TeamIdentifier:0')" ||
    die "provisioning profile lacks TeamIdentifier"
  [[ "$entitlement_team" == "$expected_team" && "$team_identifier" == "$expected_team" ]] ||
    die "provisioning profile Team ID does not match the application identifier"

  plist_array_contains "$profile_plist" 'ApplicationIdentifierPrefix' "$expected_team" ||
    die "provisioning profile application prefix does not match the application identifier"
  plist_array_contains "$profile_plist" 'Platform' 'OSX' ||
    die "provisioning profile is not a macOS profile"
  plist_array_contains "$profile_plist" 'Entitlements:keychain-access-groups' "$access_group" ||
    die "provisioning profile does not authorize the exact Keychain access group"

  expiration="$(plist_read "$profile_plist" 'ExpirationDate')" ||
    die "provisioning profile lacks an expiration date"
  expiration_epoch="$(LC_ALL=C date -j -f '%a %b %d %T %Z %Y' "$expiration" '+%s' 2>/dev/null)" ||
    die "provisioning profile expiration date cannot be parsed"
  now_epoch="$(date '+%s')"
  (( expiration_epoch > now_epoch )) || die "provisioning profile has expired"
}

assert_binary_contract() {
  local binary="$1"
  local access_group="$2"
  local expected_architecture="$3"
  local architectures

  require_command lipo
  require_command strings
  require_regular_file "$binary" "runtime binary"
  [[ -x "$binary" ]] || die "runtime binary is not executable: $binary"

  architectures="$(lipo -archs "$binary" 2>/dev/null)" ||
    die "runtime binary is not a valid Mach-O executable"
  case "$expected_architecture" in
    arm64|x86_64)
      [[ "$architectures" == "$expected_architecture" ]] ||
        die "runtime binary architecture is '$architectures', expected exactly '$expected_architecture'"
      ;;
    universal)
      [[ " $architectures " == *' arm64 '* && " $architectures " == *' x86_64 '* ]] ||
        die "universal runtime must contain arm64 and x86_64 slices"
      [[ "$(wc -w <<<"$architectures" | tr -d ' ')" == "2" ]] ||
        die "universal runtime must contain exactly two architecture slices"
      ;;
    *) die "unsupported expected architecture: $expected_architecture" ;;
  esac
  LC_ALL=C strings -a "$binary" |
    grep -F -x -- "PALLADIN_KEYCHAIN_ACCESS_GROUP=$access_group" >/dev/null ||
    die "runtime binary does not contain the exact compile-time Keychain access group"
}

assert_plist_contract() {
  local plist="$1"
  local application_identifier="$2"
  local access_group="$3"
  local team_identifier

  team_identifier="$(contract_team_identifier "$application_identifier")"
  [[ "$(plist_read "$plist" 'com.apple.application-identifier')" == "$application_identifier" ]] ||
    die "signed entitlements contain a different application identifier"
  [[ "$(plist_read "$plist" 'com.apple.developer.team-identifier')" == "$team_identifier" ]] ||
    die "signed entitlements contain a different Team ID"
  plist_array_contains "$plist" 'keychain-access-groups' "$access_group" ||
    die "signed entitlements do not contain the exact Keychain access group"

  local get_task_allow
  get_task_allow="$(plist_read "$plist" 'com.apple.security.get-task-allow')" ||
    die "signed entitlements must explicitly disable get-task-allow"
  [[ "$get_task_allow" == "false" ]] || die "get-task-allow must be disabled"
  assert_exact_entitlement_allowlist "$plist"
}

assert_exact_entitlement_allowlist() {
  local plist="$1"
  local key
  local count=0

  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    count=$((count + 1))
    case "$key" in
      com.apple.application-identifier|com.apple.developer.team-identifier|keychain-access-groups|com.apple.security.get-task-allow) ;;
      *) die "signed entitlements contain an unexpected key: $key" ;;
    esac
  done < <(
    /usr/libexec/PlistBuddy -c Print "$plist" |
      sed -n -E 's/^[[:space:]]*([^[:space:]][^=]*) = (Array|Dict|.*)$/\1/p' |
      sed -E 's/[[:space:]]+$//'
  )
  [[ "$count" == "4" ]] || die "signed entitlements must contain exactly four allowlisted keys"
}

assert_binary_session_contract() {
  local binary="$1"
  local marker

  require_regular_file "$binary" "runtime binary"
  for marker in \
    "$PALLADIN_IDENTITY_KEYCHAIN_SERVICE" \
    "$PALLADIN_STATE_KEYCHAIN_SERVICE" \
    "$PALLADIN_ORGANIZATION_SLOT_SUFFIX" \
    "$PALLADIN_X25519_SLOT_SUFFIX" \
    "$PALLADIN_ED25519_SLOT_SUFFIX" \
    "$PALLADIN_INVOCATION_SLOT_SUFFIX"; do
    LC_ALL=C strings -a "$binary" | grep -F -- "$marker" >/dev/null ||
      die "runtime binary is missing the authenticated-session storage contract"
  done
}
