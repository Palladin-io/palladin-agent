#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat >&2 <<'USAGE'
Usage: test-session-transitions.sh --app PATH --id PROFILE
                                   --mode lock|sleep|logout-prepare|logout-verify

Required environment:
  PALLADIN_SESSION_TEST_CONFIRM  Must equal dedicated-test-account.

Run this only from a dedicated interactive macOS test account with a connected synthetic Agent.
The operator must approve the first status operation and visually verify its fixed operation
prompt. Lock and sleep then require a status operation to fail while unavailable and a fresh
approval after unlock. logout-prepare obtains approval before logout; logout-verify requires a new
approval after signing back in. This is a hardware-only acceptance hook, not hosted CI evidence.
USAGE
  exit 64
}

app_path=""
mode=""
profile=""
while (( $# > 0 )); do
  case "$1" in
    --app) [[ $# -ge 2 ]] || usage; app_path="$2"; shift 2 ;;
    --mode) [[ $# -ge 2 ]] || usage; mode="$2"; shift 2 ;;
    --id) [[ $# -ge 2 ]] || usage; profile="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "${PALLADIN_SESSION_TEST_CONFIRM:-}" == "dedicated-test-account" ]] ||
  die "session transitions require a dedicated interactive macOS test account"
[[ "$mode" == "lock" || "$mode" == "sleep" || "$mode" == "logout-prepare" || "$mode" == "logout-verify" ]] ||
  die "mode must be lock, sleep, logout-prepare or logout-verify"
[[ "$profile" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "a safe synthetic profile name is required"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle is unavailable: $app_path"
binary="$app_path/Contents/MacOS/palladin"
require_regular_file "$binary" "signed runtime binary"
assert_binary_session_contract "$binary"

if [[ "$mode" == "logout-verify" ]]; then
  "$binary" --id "$profile" status >/dev/null
  printf 'Completed the post-login status operation. Confirm that macOS required a new approval.\n'
  exit 0
fi

"$binary" --id "$profile" status >/dev/null

if [[ "$mode" == "logout-prepare" ]]; then
  printf 'Pre-logout operation approved. Log out normally, sign in, then run logout-verify with the same app and profile.\n'
  exit 0
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-session.XXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

console_is_locked() {
  /usr/sbin/ioreg -n Root -d1 | grep -F -q '"IOConsoleLocked" = Yes'
}

(
  sleep 8
  set +e
  "$binary" --id "$profile" status >"$work_dir/probe.out" 2>&1
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
"$binary" --id "$profile" status >/dev/null
printf 'Verified %s denial before unlock. Confirm that the post-unlock operation required a fresh approval.\n' "$mode"
