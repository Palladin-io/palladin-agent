#!/usr/bin/env bash

set -euo pipefail

source "$(dirname "$0")/../scripts/lib.sh"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

make_profile() {
  local group="$1"
  cat >"$work_dir/profile.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Entitlements</key><dict>
<key>com.apple.application-identifier</key><string>A1B2C3D4E5.io.palladin.runtime</string>
<key>com.apple.developer.team-identifier</key><string>A1B2C3D4E5</string>
<key>keychain-access-groups</key><array><string>$group</string></array>
</dict>
<key>TeamIdentifier</key><array><string>A1B2C3D4E5</string></array>
<key>ApplicationIdentifierPrefix</key><array><string>A1B2C3D4E5</string></array>
<key>Platform</key><array><string>OSX</string></array>
<key>ExpirationDate</key><date>2035-01-01T00:00:00Z</date>
</dict></plist>
EOF
}

application_id='A1B2C3D4E5.io.palladin.runtime'
access_group='A1B2C3D4E5.io.palladin.runtime.session-v2'

for allowed in "$access_group" 'A1B2C3D4E5.*'; do
  make_profile "$allowed"
  validate_profile_contract "$work_dir/profile.plist" "$application_id" "$access_group"
done

for denied in 'Z9Y8X7W6V5.*' 'A1B2C3D4E5.io.palladin.other' '*'; do
  make_profile "$denied"
  if (validate_profile_contract "$work_dir/profile.plist" "$application_id" "$access_group") >"$work_dir/output" 2>&1; then
    printf 'invalid Keychain profile allowlist was accepted: %s\n' "$denied" >&2
    exit 1
  fi
  grep -Fq 'provisioning profile does not authorize the Keychain access group' "$work_dir/output"
done

printf 'profile Keychain allowlist checks passed\n'
