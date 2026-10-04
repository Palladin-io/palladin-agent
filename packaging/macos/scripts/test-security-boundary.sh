#!/usr/bin/env bash

set -euo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
readonly PATH

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
PACKAGING_DIR="$(dirname -- "$SCRIPT_DIR")"
readonly PACKAGING_DIR
# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"
boundary_script="${BASH_SOURCE[0]}"
source "$SCRIPT_DIR/boundary-failure.sh"

usage() {
  cat >&2 <<'USAGE'
Usage: test-security-boundary.sh --app PATH --entitlements PATH
                                 --homebrew-node PATH --architecture arm64|x86_64

Required environment:
  PALLADIN_APPLICATION_IDENTIFIER  Exact TEAMID.io.palladin.runtime value.
  PALLADIN_KEYCHAIN_ACCESS_GROUP   Exact TEAMID.io.palladin.runtime.session-v2 value.
  PALLADIN_RUNNER_ENVIRONMENT      Must equal github-hosted.
  PALLADIN_SECURITY_TEST_CONFIRM   Must equal github-hosted-ephemeral-runner.

This noninteractive test creates only synthetic Palladin state on a fresh GitHub-hosted VM. Purge
requires LocalAuthentication and cannot honestly run headlessly, so the state is destroyed only
with the entire ephemeral VM. Interactive approval and lifecycle transitions are covered by the
dedicated-lab procedure in packaging/macos/README.md.
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

[[ "${PALLADIN_RUNNER_ENVIRONMENT:-}" == "github-hosted" ]] ||
  die "boundary fixtures require a disposable GitHub-hosted runner"
[[ "${PALLADIN_SECURITY_TEST_CONFIRM:-}" == "github-hosted-ephemeral-runner" ]] ||
  die "refusing to create state without PALLADIN_SECURITY_TEST_CONFIRM=github-hosted-ephemeral-runner"
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
require_regular_file "$SCRIPT_DIR/test-dyld-injection.sh" "DYLD injection probe"
require_regular_file "$PACKAGING_DIR/tests/task-port-probe.c" "task-port probe"
require_regular_file "$PACKAGING_DIR/tests/process-arguments-probe.c" "process arguments probe"
require_regular_file "$PACKAGING_DIR/tests/canary-tree-probe.mjs" "canary tree probe"
assert_plist_contract "$entitlements" "$application_identifier" "$access_group"
assert_binary_session_contract "$binary"
test "$(uname -m)" = "$architecture"
[[ ! -e "$HOME/.palladin" && ! -L "$HOME/.palladin" ]] ||
  die "boundary fixtures require a fresh account without Palladin state"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-boundary.XXXXXX")"
target_pid=""
control_pid=""
boundary_phase='initialization'
boundary_error="$work_dir/init.err"
boundary_failure_line=0
begin_boundary_test() {
  boundary_phase="$1"
  boundary_error="$work_dir/$2"
  boundary_failure_line=0
  printf 'Running signed boundary test: %s\n' "$boundary_phase"
}
cleanup() {
  local status=$?
  set +e
  trap - ERR
  if [[ $status -ne 0 ]]; then
    report_boundary_failure "$status" "$boundary_failure_line" "$boundary_error" "$boundary_phase"
  fi
  if [[ -n "$control_pid" ]]; then
    kill -KILL "$control_pid" >/dev/null 2>&1 || true
    wait "$control_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$target_pid" ]]; then
    kill -KILL "$target_pid" >/dev/null 2>&1 || true
    wait "$target_pid" >/dev/null 2>&1 || true
  fi
  exec 9>&- 2>/dev/null || true
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'boundary_failure_line=$LINENO' ERR

begin_boundary_test initialization init.err

"$binary" init >"$work_dir/init.out" 2>"$work_dir/init.err"

begin_boundary_test public-registry registry.err

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

begin_boundary_test foreign-node-keychain node-keyring.err

"$homebrew_node" "$PACKAGING_DIR/tests/node-keyring-probe.mjs" \
  "$PALLADIN_IDENTITY_KEYCHAIN_SERVICE" "${accounts[@]}" \
  >"$work_dir/node-keyring.out" 2>"$work_dir/node-keyring.err"

begin_boundary_test foreign-native-keychain untrusted-dpk.err

swift_probe="$work_dir/untrusted-dpk-probe"
xcrun swiftc -O -warnings-as-errors "$PACKAGING_DIR/tests/untrusted-dpk-probe.swift" -o "$swift_probe"
"$swift_probe" "$access_group" "$PALLADIN_IDENTITY_KEYCHAIN_SERVICE" "${accounts[@]}" \
  >"$work_dir/untrusted-dpk.out" 2>"$work_dir/untrusted-dpk.err"

begin_boundary_test intact-copy-and-client-authorization signed-client.err

copied_app="$work_dir/PalladinCopied.app"
ditto "$app_path" "$copied_app"
codesign --verify --strict "$copied_app" >/dev/null 2>&1 ||
  die "intact copied app did not preserve its release signature"

"$homebrew_node" "$PACKAGING_DIR/tests/signed-client-probe.mjs" \
  "$binary" "$copied_app/Contents/MacOS/palladin" "$work_dir/signed-client-captures" \
  >"$work_dir/signed-client.out" 2>"$work_dir/signed-client.err"

begin_boundary_test unsigned-clone unsigned.out

unsigned_binary="$work_dir/palladin-unsigned"
cp "$binary" "$unsigned_binary"
codesign --remove-signature "$unsigned_binary"
if "$unsigned_binary" --id default security upgrade >"$work_dir/unsigned.out" 2>&1; then
  die "unsigned clone unexpectedly opened the identity"
fi

begin_boundary_test differently-signed-fork fork.out

fork_app="$work_dir/PalladinFork.app"
ditto "$app_path" "$fork_app"
codesign --force --sign - --options runtime --entitlements "$entitlements" "$fork_app" >/dev/null
if "$fork_app/Contents/MacOS/palladin" --id default security upgrade >"$work_dir/fork.out" 2>&1; then
  die "differently signed fork unexpectedly opened the identity"
fi

begin_boundary_test modified-bundle modified.out

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

if [[ "$(lipo -archs "$binary" | wc -w | tr -d ' ')" == 2 ]]; then
  begin_boundary_test unsigned-inactive-slice inactive.out

  inactive_app="$work_dir/PalladinInactiveSlice.app"
  ditto "$app_path" "$inactive_app"
  inactive_architecture=arm64
  [[ "$architecture" != "arm64" ]] || inactive_architecture=x86_64
  inactive_binary="$work_dir/inactive-slice"
  lipo "$binary" -thin "$inactive_architecture" -output "$inactive_binary"
  codesign --remove-signature "$inactive_binary"
  lipo "$binary" -replace "$inactive_architecture" "$inactive_binary" \
    -output "$inactive_app/Contents/MacOS/palladin"
  chmod 0755 "$inactive_app/Contents/MacOS/palladin"
  if codesign --verify --strict --all-architectures "$inactive_app" >/dev/null 2>&1; then
    die "bundle with unsigned inactive slice unexpectedly retained a valid signature"
  fi
  if "$inactive_app/Contents/MacOS/palladin" doctor >"$work_dir/inactive.out" 2>&1; then
    grep -Fx 'standalone-security-tier: Unavailable' "$work_dir/inactive.out" >/dev/null ||
      die "bundle with unsigned inactive slice unexpectedly reported Hardened"
    grep -Fx 'identity-opened: no' "$work_dir/inactive.out" >/dev/null ||
      die "bundle with unsigned inactive slice unexpectedly opened identity"
  fi
fi

begin_boundary_test dyld-injection dyld.err

"$SCRIPT_DIR/test-dyld-injection.sh" --app "$app_path" --mode hosted \
  >"$work_dir/dyld.out" 2>"$work_dir/dyld.err"

begin_boundary_test argument-scanner-positive-control process-arguments.err

task_probe="$work_dir/task-port-probe"
xcrun clang -Wall -Wextra -Werror "$PACKAGING_DIR/tests/task-port-probe.c" -o "$task_probe"
process_arguments_probe="$work_dir/process-arguments-probe"
xcrun clang -Wall -Wextra -Werror \
  "$PACKAGING_DIR/tests/process-arguments-probe.c" -o "$process_arguments_probe"
control_canary="palladin-scan-control-$(openssl rand -hex 32)"
PALLADIN_SYNTHETIC_SCAN_CONTROL="$control_canary" /bin/sleep 30 &
control_pid=$!
set +e
printf '%s' "$control_canary" | "$process_arguments_probe" "$control_pid" /bin/sleep >/dev/null 2>&1
control_status=$?
set -e
[[ $control_status -eq 2 ]] || die "process argument scanner missed its synthetic positive control"
kill "$control_pid"
wait "$control_pid" >/dev/null 2>&1 || true
control_pid=""
control_canary=
begin_boundary_test connect-target attach-target.err

input_fifo="$work_dir/connect-input"
mkfifo -m 0600 "$input_fifo"
"$binary" connect --api-key-stdin <"$input_fifo" \
  >"$work_dir/attach-target.out" 2>"$work_dir/attach-target.err" &
target_pid=$!
exec 9>"$input_fifo"
process_canary="palladin-stdin-$(openssl rand -hex 32)"
printf '%s' "$process_canary" >&9
for _ in {1..50}; do
  kill -0 "$target_pid" >/dev/null 2>&1 && break
  sleep 0.1
done
kill -0 "$target_pid" >/dev/null 2>&1 || die "debug target exited before the attack probes"
begin_boundary_test process-arguments process-arguments.err

printf '%s' "$process_canary" | "$process_arguments_probe" "$target_pid" "$binary" \
  >"$work_dir/process-arguments.out" 2>"$work_dir/process-arguments.err"
begin_boundary_test task-port task-port.err

"$task_probe" "$target_pid" >"$work_dir/task-port.out" 2>"$work_dir/task-port.err"

begin_boundary_test debugger-and-core lldb.err

sip_status="$(/usr/bin/csrutil status 2>/dev/null)" || die "SIP status is unavailable"
if [[ "$sip_status" == 'System Integrity Protection status: enabled.' ]]; then
  if xcrun lldb --batch --attach-pid "$target_pid" \
    -o 'process kill' -o quit \
    >"$work_dir/lldb.out" 2>"$work_dir/lldb.err"; then
    die "debugger unexpectedly attached to the signed runtime"
  fi
  grep -Fq 'Not allowed to attach to process' "$work_dir/lldb.err" ||
    die "debugger rejection was not confirmed"
elif [[ "$sip_status" == 'System Integrity Protection status: disabled.' ]]; then
  : >"$work_dir/lldb.out"
  : >"$work_dir/lldb.err"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '| debugger-and-core | UNVERIFIED: SIP disabled; physical gate required | — | — | — | — |\n' >>"$GITHUB_STEP_SUMMARY"
  fi
else
  die "debugger acceptance requires fully enabled SIP"
fi
exec 9>&-
for _ in {1..100}; do
  kill -0 "$target_pid" >/dev/null 2>&1 || break
  sleep 0.1
done
kill -INT "$target_pid" >/dev/null 2>&1 || true
wait "$target_pid" >/dev/null 2>&1 || true
target_pid=""
begin_boundary_test secret-canary-files canary-tree.err

printf '%s' "$process_canary" | "$homebrew_node" \
  "$PACKAGING_DIR/tests/canary-tree-probe.mjs" \
  "$HOME/.palladin" \
  "$work_dir/attach-target.out" "$work_dir/attach-target.err" \
  "$work_dir/process-arguments.out" "$work_dir/process-arguments.err" \
  "$work_dir/task-port.out" "$work_dir/task-port.err" \
  "$work_dir/lldb.out" "$work_dir/lldb.err" \
  >"$work_dir/canary-tree.out" 2>"$work_dir/canary-tree.err"
process_canary=

begin_boundary_test create-profile create-profile.err

"$binary" agents create build >"$work_dir/create-profile.out" 2>"$work_dir/create-profile.err"
begin_boundary_test rename-profile rename-profile.err

"$binary" agents rename build build-renamed >"$work_dir/rename-profile.out" 2>"$work_dir/rename-profile.err"
begin_boundary_test set-default-profile set-default-build.err

"$binary" agents set-default build-renamed >"$work_dir/set-default-build.out" 2>"$work_dir/set-default-build.err"
begin_boundary_test restore-default-profile set-default.err

"$binary" agents set-default default >"$work_dir/set-default.out" 2>"$work_dir/set-default.err"

begin_boundary_test residual-core-files residual-core.err

if find "$work_dir" -type f \( -name 'core' -o -name 'core.*' -o -name '*.core' \) -print -quit |
  grep -q .; then
  die "boundary probe left a core file"
fi

printf 'Verified applicable exact signed artifact storage, blind-spawn, copy, signature, task-port, debugger, cancellation, second-connection, and profile boundaries on %s; see the job summary for SIP-dependent coverage.\n' "$architecture"
