#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat >&2 <<'USAGE'
Usage: test-session-transitions.sh --app PATH --mode lock|sleep|logout-prepare|logout-verify

Required environment:
  PALLADIN_SESSION_TEST_CONFIRM  Must equal dedicated-test-account.

Run this only from a dedicated interactive macOS test account. Lock and sleep schedule a
noninteractive identity read while the Data Protection Keychain is unavailable, then require
the same signed runtime to read the identity after unlock. logout-prepare creates the fixture;
after signing back in, logout-verify opens and purges it.
USAGE
  exit 64
}

app_path=""
mode=""
while (( $# > 0 )); do
  case "$1" in
    --app) [[ $# -ge 2 ]] || usage; app_path="$2"; shift 2 ;;
    --mode) [[ $# -ge 2 ]] || usage; mode="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "${PALLADIN_SESSION_TEST_CONFIRM:-}" == "dedicated-test-account" ]] ||
  die "session transitions require a dedicated interactive macOS test account"
[[ "$mode" == "lock" || "$mode" == "sleep" || "$mode" == "logout-prepare" || "$mode" == "logout-verify" ]] ||
  die "mode must be lock, sleep, logout-prepare or logout-verify"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle is unavailable: $app_path"
binary="$app_path/Contents/MacOS/palladin"
require_regular_file "$binary" "signed runtime binary"

if [[ "$mode" == "logout-verify" ]]; then
  "$binary" --id default security upgrade >/dev/null
  "$binary" purge --confirm >/dev/null
  printf 'Verified identity continuity after logout/login and purged the fixture.\n'
  exit 0
fi

"$binary" purge --confirm >/dev/null 2>&1 || true
"$binary" init >/dev/null
"$binary" --id default security upgrade >/dev/null

if [[ "$mode" == "logout-prepare" ]]; then
  printf 'Fixture prepared. Log out normally, sign in again, then run --mode logout-verify.\n'
  exit 0
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-session.XXXXXX")"
cleanup() {
  "$binary" purge --confirm >/dev/null 2>&1 || true
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

console_is_locked() {
  /usr/sbin/ioreg -n Root -d1 | grep -F -q '"IOConsoleLocked" = Yes'
}

(
  sleep 8
  set +e
  "$binary" --id default security upgrade >"$work_dir/probe.out" 2>&1
  printf '%s\n' "$?" >"$work_dir/probe.status"
) &
probe_pid=$!

if [[ "$mode" == "lock" ]]; then
  lock_tool='/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession'
  require_regular_file "$lock_tool" "macOS lock tool"
  printf 'Locking now. Stay on the lock screen for at least 15 seconds before unlocking.\n'
  "$lock_tool" -suspend
else
  printf 'Sleeping now. Wake the Mac after at least 15 seconds, then unlock it.\n'
  /usr/bin/pmset sleepnow
fi

wait "$probe_pid"
require_regular_file "$work_dir/probe.status" "locked-state probe status"
probe_status="$(tr -d '[:space:]' <"$work_dir/probe.status")"
[[ "$probe_status" =~ ^[0-9]+$ ]] || die "locked-state probe status is invalid"
(( probe_status != 0 )) || die "identity was readable while the session should have been locked"
console_is_locked || die "the session was unlocked before the locked-state probe completed"
while console_is_locked; do
  sleep 1
done
"$binary" --id default security upgrade >/dev/null
printf 'Verified %s denial before unlock and identity access after unlock.\n' "$mode"
