#!/usr/bin/env bash

# Proves on a fresh disposable VM that the exact signed candidate upgrades Keychain
# items written by an older signed release, and writes new items with the new class.
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

[[ $# -eq 2 ]] || die "usage: test-protection-upgrade.sh OLD_BINARY CANDIDATE_BINARY"
[[ "${PALLADIN_RUNNER_ENVIRONMENT:-}" == "github-hosted" &&
  "${PALLADIN_SECURITY_TEST_CONFIRM:-}" == "github-hosted-ephemeral-runner" ]] ||
  die "protection upgrade requires a disposable GitHub-hosted runner"
old="$1"
candidate="$2"
require_regular_file "$old" "older signed runtime"
require_regular_file "$candidate" "candidate signed runtime"
[[ ! -e "$HOME/.palladin" && ! -L "$HOME/.palladin" ]] || die "a fresh account is required"

expect_report() {
  local report
  report="$("$candidate" doctor | grep '^keychain-protection-upgrade: ')" ||
    die "doctor reported no protection state: $1"
  [[ "$report" =~ ^keychain-protection-upgrade:\ upgraded=$2,\ failed=0$ ]] ||
    die "unexpected protection report: $1: $report"
}

"$old" agents create upgrade-fixture >/dev/null
"$old" browser install >/dev/null
expect_report "upgrade of older shared items" '[1-9][0-9]*'
expect_report "repeated run is a no-op" 0
"$candidate" agents list | grep -F -q upgrade-fixture || die "profile was lost by the upgrade"
"$candidate" browser install >/dev/null
"$candidate" browser status >/dev/null

"$candidate" purge --confirm >/dev/null
"$candidate" agents create fresh-fixture >/dev/null
"$candidate" browser install >/dev/null
expect_report "new items already use the current class" 0
printf 'Verified signed Keychain protection upgrade, idempotence, retained state and fresh install.\n'
