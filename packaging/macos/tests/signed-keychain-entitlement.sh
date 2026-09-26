#!/usr/bin/env bash

set -euo pipefail

source "$(dirname "$0")/../scripts/lib.sh"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

application_id='A1B2C3D4E5.io.palladin.runtime'
access_group='A1B2C3D4E5.io.palladin.runtime.session-v2'

make_entitlements() {
  local groups="$1"
  cat >"$work_dir/entitlements.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.application-identifier</key><string>$application_id</string>
<key>com.apple.developer.team-identifier</key><string>A1B2C3D4E5</string>
<key>keychain-access-groups</key><array>$groups</array>
<key>com.apple.security.get-task-allow</key><false/>
</dict></plist>
EOF
}

make_entitlements "<string>$access_group</string>"
assert_plist_contract "$work_dir/entitlements.plist" "$application_id" "$access_group"

make_entitlements "<string>$access_group</string><string>A1B2C3D4E5.*</string>"
if (assert_plist_contract "$work_dir/entitlements.plist" "$application_id" "$access_group") >"$work_dir/output" 2>&1; then
  printf 'additional signed Keychain access group was accepted\n' >&2
  exit 1
fi
grep -Fq 'signed entitlements contain an additional Keychain access group' "$work_dir/output"

printf 'signed Keychain entitlement checks passed\n'
