#!/usr/bin/env bash

die() {
  local caller
  for ((caller = 1; caller < ${#BASH_SOURCE[@]}; caller++)); do
    if [[ "${BASH_SOURCE[caller]}" == "${boundary_script:-}" ]]; then
      boundary_failure_line="${BASH_LINENO[caller - 1]}"
      break
    fi
  done
  printf 'error: %s\n' "$*" >&2
  exit 1
}

report_boundary_failure() {
  local status="$1"
  local line="$2"
  local captured_error="$3"
  local phase="$4"
  local category='unknown'
  local keychain_status='unavailable'
  local captured_line
  local client_failure='^Palladin signed-client probe failure: (blind-genuine|blind-copied|cancelled-connect|mcp-first-connection|mcp-second-connection|mcp-connection-[12]): (profile-not-found|agent-not-registered|agent-not-active|secure-store-unavailable|manifest-unavailable|manifest-invalid|keychain-operation-failed|unclassified)$'
  local client_stage='^Palladin signed-client probe stage: (blind-genuine|blind-copied|cancelled-connect|mcp-first-connection|mcp-second-connection)$'
  local keychain_failure='^Error: OS secure storage operation failed: macOS Keychain operation failed \(OSStatus (-?[0-9]{1,10})\); no fallback is allowed$'
  if [[ -f "$captured_error" && ! -L "$captured_error" ]]; then
    if grep -Fxq -e 'Error: OS secure storage operation failed: OS secure storage is unavailable; no file or environment fallback is allowed' -e 'Error: OS secure storage is unavailable; no file or environment fallback is allowed' "$captured_error"; then
      category='secure-storage-unavailable'
    elif grep -Fxq -e 'Error: OS secure storage operation failed: fresh operating-system authorization is required for this operation' -e 'Error: fresh operating-system authorization is required for this operation' "$captured_error"; then
      category='operating-system-authorization-required'
    elif grep -Fxq 'Error: signed runtime release manifest is unavailable; no identity was opened' "$captured_error"; then
      category='release-manifest-unavailable'
    elif grep -Fxq 'Error: signed runtime release manifest verification failed; no identity was opened' "$captured_error"; then
      category='release-manifest-invalid'
    fi
    while IFS= read -r captured_line || [[ -n "$captured_line" ]]; do
      if [[ "$captured_line" =~ $keychain_failure ]]; then
        category='secure-storage-operation-failed'
        keychain_status="${BASH_REMATCH[1]}"
        break
      elif [[ "$phase" == 'intact-copy-and-client-authorization' && "$captured_line" =~ $client_failure ]]; then
        category="signed-client-${BASH_REMATCH[1]}-${BASH_REMATCH[2]}"
        break
      elif [[ "$phase" == 'intact-copy-and-client-authorization' && "$captured_line" =~ $client_stage ]]; then
        category="signed-client-${BASH_REMATCH[1]}-failed"
      fi
    done <"$captured_error"
  fi
  printf 'Signed boundary test %s failed at script line %s (exit %s); category: %s; Keychain OSStatus: %s; captured output withheld.\n' \
    "$phase" "$line" "$status" "$category" "$keychain_status" >&2
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '| %s | FAIL | %s | %s | %s | %s |\n' \
      "$phase" "$line" "$status" "$category" "$keychain_status" >>"$GITHUB_STEP_SUMMARY"
    printf '::error file=packaging/macos/scripts/test-security-boundary.sh,line=%s::Signed boundary test %s failed (exit %s, category %s, Keychain OSStatus %s).\n' \
      "$line" "$phase" "$status" "$category" "$keychain_status"
  fi
}
