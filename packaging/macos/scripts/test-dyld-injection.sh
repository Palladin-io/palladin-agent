#!/usr/bin/env bash

set -euo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
readonly PATH

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

app_path=''
mode=''
while (( $# > 0 )); do
  case "$1" in
    --app) [[ $# -ge 2 ]] || die 'missing app path'; app_path="$2"; shift 2 ;;
    --mode) [[ $# -ge 2 ]] || die 'missing probe mode'; mode="$2"; shift 2 ;;
    *) die 'invalid DYLD probe argument' ;;
  esac
done
[[ "$mode" == hosted || "$mode" == physical ]] || die 'invalid DYLD probe mode'
[[ -d "$app_path" && ! -L "$app_path" ]] || die 'signed app is unavailable'
binary="$app_path/Contents/MacOS/palladin"
require_regular_file "$binary" 'signed runtime binary'
require_regular_file "$SCRIPT_DIR/../tests/dyld-injection-probe.c" 'DYLD probe source'
codesign --verify --strict "$app_path" >/dev/null 2>&1 || die 'signed app failed verification'

sip_status="$(/usr/bin/csrutil status 2>/dev/null)" || die 'SIP status is unavailable'
if grep -Fxq 'System Integrity Protection status: enabled.' <<<"$sip_status"; then
  :
elif [[ "$mode" == hosted ]] && grep -Fxq 'System Integrity Protection status: disabled.' <<<"$sip_status"; then
  printf 'Palladin DYLD probe: UNVERIFIED on a SIP-disabled hosted runner; physical SIP-enabled acceptance is required.\n'
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '| dyld-injection | UNVERIFIED: SIP disabled; physical gate required | — | — | — | — |\n' >>"$GITHUB_STEP_SUMMARY"
  fi
  exit 0
else
  die 'DYLD acceptance requires fully enabled SIP'
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-dyld.XXXXXX")"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT
injection_library="$work_dir/palladin-dyld-probe.dylib"
injection_marker="$work_dir/dyld-injection-succeeded"
/usr/bin/xcrun clang -dynamiclib -Wall -Wextra -Werror \
  "$SCRIPT_DIR/../tests/dyld-injection-probe.c" -o "$injection_library"
if PALLADIN_DYLD_PROBE_MARKER="$injection_marker" \
  DYLD_INSERT_LIBRARIES="$injection_library" \
  "$binary" doctor >"$work_dir/dyld.out" 2>"$work_dir/dyld.err"; then
  doctor_status=0
else
  doctor_status=$?
fi
[[ ! -e "$injection_marker" && ! -L "$injection_marker" ]] || die 'DYLD injection reached the signed runtime'
grep -Fxq 'Palladin Runtime Doctor' "$work_dir/dyld.out" || die 'signed doctor did not execute'
grep -Fxq 'identity-opened: no' "$work_dir/dyld.out" || die 'identity was not proven closed'
grep -Fxq 'standalone-security-tier: Hardened' "$work_dir/dyld.out" || die 'Hardened tier was not reported'
case "$doctor_status" in
  0) grep -Fxq 'environment: safe' "$work_dir/dyld.out" || die 'doctor did not report a safe environment' ;;
  78)
    grep -Fxq 'environment: unsafe' "$work_dir/dyld.out" || die 'doctor did not report an unsafe environment'
    grep -Fxq 'dangerous-variable-names: DYLD_INSERT_LIBRARIES' "$work_dir/dyld.out" ||
      die 'doctor did not identify the injection variable'
    ;;
  *) die "signed doctor returned unexpected DYLD probe exit status: $doctor_status" ;;
esac
printf 'Palladin DYLD probe: PASS with SIP enabled.\n'
