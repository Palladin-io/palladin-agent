#!/usr/bin/env bash

report_boundary_failure() {
  local status="$1"
  local line="$2"
  local init_error="$3"
  local category='unknown'
  local keychain_status='unavailable'
  local captured_line
  local write_failure='^Error: OS secure storage operation failed: macOS Keychain write failed \(OSStatus (-?[0-9]{1,10})\); no fallback is allowed$'
  if [[ -f "$init_error" && ! -L "$init_error" ]]; then
    if grep -Fxq -e 'Error: OS secure storage operation failed: OS secure storage is unavailable; no file or environment fallback is allowed' -e 'Error: OS secure storage is unavailable; no file or environment fallback is allowed' "$init_error"; then
      category='secure-storage-unavailable'
    elif grep -Fxq -e 'Error: OS secure storage operation failed: fresh operating-system authorization is required for this operation' -e 'Error: fresh operating-system authorization is required for this operation' "$init_error"; then
      category='operating-system-authorization-required'
    elif grep -Fxq 'Error: signed runtime release manifest is unavailable; no identity was opened' "$init_error"; then
      category='release-manifest-unavailable'
    elif grep -Fxq 'Error: signed runtime release manifest verification failed; no identity was opened' "$init_error"; then
      category='release-manifest-invalid'
    fi
    while IFS= read -r captured_line || [[ -n "$captured_line" ]]; do
      if [[ "$captured_line" =~ $write_failure ]]; then
        category='secure-storage-write-failed'
        keychain_status="${BASH_REMATCH[1]}"
        break
      fi
    done <"$init_error"
  fi
  printf 'Signed boundary failed at script line %s (exit %s); init category: %s; Keychain OSStatus: %s; captured output withheld.\n' \
    "$line" "$status" "$category" "$keychain_status" >&2
}
