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
Usage: test-security-boundary.sh --app PATH --entitlements PATH
                                 --homebrew-node PATH --architecture arm64|x86_64

Required environment:
  PALLADIN_APPLICATION_IDENTIFIER  Exact TEAMID.io.palladin.runtime value.
  PALLADIN_KEYCHAIN_ACCESS_GROUP   Exact TEAMID.io.palladin.runtime.session-v2 value.
  PALLADIN_SECURITY_TEST_CONFIRM   Must equal ephemeral-runner.

This noninteractive test creates and purges only synthetic Palladin state. It never approves a
LocalAuthentication prompt. Interactive approval and lock/sleep/logout transitions are covered by
the dedicated-lab procedure in packaging/macos/README.md.
USAGE
  exit 64
}

app_path=""
entitlements=""
homebrew_node=""
architecture=""
while (( $# > 0 )); do
  case "$1" in
    --app) [[ $# -ge 2 ]] || usage; app_path="$2"; shift 2 ;;
    --entitlements) [[ $# -ge 2 ]] || usage; entitlements="$2"; shift 2 ;;
    --homebrew-node) [[ $# -ge 2 ]] || usage; homebrew_node="$2"; shift 2 ;;
    --architecture) [[ $# -ge 2 ]] || usage; architecture="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "${PALLADIN_SECURITY_TEST_CONFIRM:-}" == "ephemeral-runner" ]] ||
  die "refusing to alter the current account without PALLADIN_SECURITY_TEST_CONFIRM=ephemeral-runner"
[[ "$architecture" == "arm64" || "$architecture" == "x86_64" ]] || usage
application_identifier="${PALLADIN_APPLICATION_IDENTIFIER:-}"
access_group="${PALLADIN_KEYCHAIN_ACCESS_GROUP:-}"
validate_contract_identifiers "$application_identifier" "$access_group"
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle is unavailable: $app_path"
require_regular_file "$homebrew_node" "Homebrew Node executable"
[[ -x "$homebrew_node" ]] || die "Homebrew Node is not executable"

binary="$app_path/Contents/MacOS/palladin"
require_regular_file "$binary" "signed runtime binary"
require_regular_file "$entitlements" "generated entitlements"
require_regular_file "$PACKAGING_DIR/tests/node-keyring-probe.mjs" "Node isolation probe"
require_regular_file "$PACKAGING_DIR/tests/untrusted-dpk-probe.swift" "Data Protection Keychain probe"
require_regular_file "$PACKAGING_DIR/tests/signed-client-probe.mjs" "signed-client probe"
require_regular_file "$PACKAGING_DIR/tests/dyld-injection-probe.c" "DYLD injection probe"
require_regular_file "$PACKAGING_DIR/tests/task-port-probe.c" "task-port probe"
assert_plist_contract "$entitlements" "$application_identifier" "$access_group"
assert_binary_session_contract "$binary"
test "$(uname -m)" = "$architecture"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-boundary.XXXXXX")"
target_pid=""
cleanup() {
  set +e
  if [[ -n "$target_pid" ]]; then
    kill -KILL "$target_pid" >/dev/null 2>&1 || true
    wait "$target_pid" >/dev/null 2>&1 || true
  fi
  exec 9>&- 2>/dev/null || true
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

"$binary" init >"$work_dir/init.out" 2>"$work_dir/init.err"

registry="$HOME/.palladin/registry.json"
require_regular_file "$registry" "native public registry"
identity_id="$(/usr/bin/plutil -extract agents.0.identityId raw -o - "$registry")" ||
  die "could not read the public identity reference"
[[ "$identity_id" =~ ^[0-9a-f]{32}$ ]] || die "public identity reference has an invalid format"
accounts=(
  "$identity_id:$PALLADIN_X25519_SLOT_SUFFIX"
  "$identity_id:$PALLADIN_ED25519_SLOT_SUFFIX"
  "$identity_id:$PALLADIN_INVOCATION_SLOT_SUFFIX"
)

"$homebrew_node" "$PACKAGING_DIR/tests/node-keyring-probe.mjs" \
  "$PALLADIN_IDENTITY_KEYCHAIN_SERVICE" "${accounts[@]}" \
  >"$work_dir/node-keyring.out" 2>"$work_dir/node-keyring.err"

swift_probe="$work_dir/untrusted-dpk-probe"
xcrun swiftc -O -warnings-as-errors "$PACKAGING_DIR/tests/untrusted-dpk-probe.swift" -o "$swift_probe"
"$swift_probe" "$access_group" "$PALLADIN_IDENTITY_KEYCHAIN_SERVICE" "${accounts[@]}" \
  >"$work_dir/untrusted-dpk.out" 2>"$work_dir/untrusted-dpk.err"

copied_app="$work_dir/PalladinCopied.app"
ditto "$app_path" "$copied_app"
codesign --verify --strict "$copied_app" >/dev/null 2>&1 ||
  die "intact copied app did not preserve its release signature"

"$homebrew_node" "$PACKAGING_DIR/tests/signed-client-probe.mjs" \
  "$binary" "$copied_app/Contents/MacOS/palladin" "$work_dir/signed-client-captures" \
  >"$work_dir/signed-client.out" 2>"$work_dir/signed-client.err"

unsigned_binary="$work_dir/palladin-unsigned"
cp "$binary" "$unsigned_binary"
codesign --remove-signature "$unsigned_binary"
if "$unsigned_binary" --id default security upgrade >"$work_dir/unsigned.out" 2>&1; then
  die "unsigned clone unexpectedly opened the identity"
fi

fork_app="$work_dir/PalladinFork.app"
ditto "$app_path" "$fork_app"
codesign --force --sign - --options runtime --entitlements "$entitlements" "$fork_app" >/dev/null
if "$fork_app/Contents/MacOS/palladin" --id default security upgrade >"$work_dir/fork.out" 2>&1; then
  die "differently signed fork unexpectedly opened the identity"
fi

modified_app="$work_dir/PalladinModified.app"
ditto "$app_path" "$modified_app"
printf '\0' >>"$modified_app/Contents/MacOS/palladin"
if codesign --verify --strict "$modified_app" >/dev/null 2>&1; then
  die "modified bundle unexpectedly retained a valid signature"
fi
if "$modified_app/Contents/MacOS/palladin" --id default security upgrade \
  >"$work_dir/modified.out" 2>&1; then
  die "modified bundle unexpectedly opened the identity"
fi

injection_library="$work_dir/palladin-dyld-probe.dylib"
injection_marker="$work_dir/dyld-injection-succeeded"
xcrun clang -dynamiclib -Wall -Wextra -Werror \
  "$PACKAGING_DIR/tests/dyld-injection-probe.c" -o "$injection_library"
if ! PALLADIN_DYLD_PROBE_MARKER="$injection_marker" \
  DYLD_INSERT_LIBRARIES="$injection_library" \
  "$binary" doctor >"$work_dir/dyld.out" 2>"$work_dir/dyld.err"; then
  die "signed runtime did not execute safely with a rejected DYLD injection request"
fi
[[ ! -e "$injection_marker" ]] || die "DYLD injection reached the signed runtime"
grep -F -q 'standalone-security-tier: Hardened' "$work_dir/dyld.out" ||
  die "DYLD probe changed the runtime security tier"

task_probe="$work_dir/task-port-probe"
xcrun clang -Wall -Wextra -Werror "$PACKAGING_DIR/tests/task-port-probe.c" -o "$task_probe"
input_fifo="$work_dir/connect-input"
mkfifo -m 0600 "$input_fifo"
"$binary" connect --api-key-stdin <"$input_fifo" \
  >"$work_dir/attach-target.out" 2>"$work_dir/attach-target.err" &
target_pid=$!
exec 9>"$input_fifo"
for _ in {1..50}; do
  kill -0 "$target_pid" >/dev/null 2>&1 && break
  sleep 0.1
done
kill -0 "$target_pid" >/dev/null 2>&1 || die "debug target exited before the attack probes"
"$task_probe" "$target_pid" >"$work_dir/task-port.out" 2>"$work_dir/task-port.err"

core_path="$work_dir/palladin.core"
if xcrun lldb --batch --attach-pid "$target_pid" \
  -o "process save-core $core_path" -o detach -o quit \
  >"$work_dir/lldb.out" 2>"$work_dir/lldb.err"; then
  die "debugger unexpectedly attached to the signed runtime"
fi
[[ ! -e "$core_path" ]] || die "debugger unexpectedly created a runtime core file"
kill -INT "$target_pid" >/dev/null 2>&1 || true
wait "$target_pid" >/dev/null 2>&1 || true
target_pid=""
exec 9>&-

"$binary" agents create build >"$work_dir/create-profile.out" 2>"$work_dir/create-profile.err"
"$binary" agents rename build build-renamed >"$work_dir/rename-profile.out" 2>"$work_dir/rename-profile.err"
"$binary" agents set-default build-renamed >"$work_dir/set-default-build.out" 2>"$work_dir/set-default-build.err"
"$binary" agents set-default default >"$work_dir/set-default.out" 2>"$work_dir/set-default.err"

if find "$work_dir" -type f \( -name 'core' -o -name 'core.*' -o -name '*.core' \) -print -quit |
  grep -q .; then
  die "boundary probe left a core file"
fi

printf 'Verified exact signed artifact storage, blind-spawn, copy, signature, DYLD, task-port, debugger, cancellation, replay, second-connection, and profile boundaries on %s.\n' "$architecture"
