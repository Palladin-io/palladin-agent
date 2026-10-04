#!/usr/bin/env bash

set -euo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
readonly PATH

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

[[ $# -eq 2 && "$1" == --app ]] || die 'expected --app PATH'
app_path="$2"
[[ -d "$app_path" && ! -L "$app_path" ]] || die 'signed app is unavailable'
binary="$app_path/Contents/MacOS/palladin"
require_regular_file "$binary" 'signed runtime binary'
require_regular_file "$SCRIPT_DIR/../tests/suspended-signed-runtime.c" 'suspended runtime source'
require_regular_file "$SCRIPT_DIR/../tests/task-port-probe.c" 'task-port probe source'
codesign --verify --strict "$app_path" >/dev/null 2>&1 || die 'signed app failed verification'
[[ "$(/usr/bin/csrutil status 2>/dev/null)" == 'System Integrity Protection status: enabled.' ]] ||
  die 'debugger acceptance requires fully enabled SIP'

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-debugger.XXXXXX")"
guardian_pid=''
target_pid=''
cleanup() {
  if [[ -n "$target_pid" ]]; then kill -KILL "$target_pid" >/dev/null 2>&1 || true; fi
  if [[ -n "$guardian_pid" ]]; then
    kill -TERM "$guardian_pid" >/dev/null 2>&1 || true
    wait "$guardian_pid" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

/usr/bin/xcrun clang -Wall -Wextra -Werror \
  "$SCRIPT_DIR/../tests/suspended-signed-runtime.c" -o "$work_dir/suspended-runtime"
/usr/bin/xcrun clang -Wall -Wextra -Werror \
  "$SCRIPT_DIR/../tests/task-port-probe.c" -o "$work_dir/task-port-probe"

"$work_dir/suspended-runtime" "$binary" >"$work_dir/pid" 2>"$work_dir/guardian.err" &
guardian_pid=$!
for _ in {1..50}; do
  [[ -s "$work_dir/pid" ]] && break
  kill -0 "$guardian_pid" >/dev/null 2>&1 || die 'suspended runtime launcher exited early'
  sleep 0.1
done
[[ -s "$work_dir/pid" ]] || die 'suspended runtime did not start'
target_pid="$(<"$work_dir/pid")"
[[ "$target_pid" =~ ^[1-9][0-9]*$ ]] || die 'suspended runtime PID is invalid'
kill -0 "$target_pid" >/dev/null 2>&1 || die 'suspended runtime exited before probes'

"$work_dir/task-port-probe" "$target_pid" >"$work_dir/task-port.out" 2>"$work_dir/task-port.err" ||
  die 'task port opened for the signed runtime'
if /usr/bin/xcrun lldb --batch --attach-pid "$target_pid" \
  -o 'process kill' -o quit \
  >"$work_dir/lldb.out" 2>"$work_dir/lldb.err"; then
  die 'debugger attached to the signed runtime'
fi
grep -Fq 'Not allowed to attach to process' "$work_dir/lldb.err" ||
  die 'debugger rejection was not confirmed'
kill -0 "$guardian_pid" >/dev/null 2>&1 || die 'suspended runtime launcher timed out'
printf 'Palladin debugger probe: PASS with SIP enabled.\n'
