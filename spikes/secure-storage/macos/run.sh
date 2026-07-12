#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
build=$(mktemp -d)
trap '"$build/writer" delete >/dev/null 2>&1 || true; rm -rf "$build"' EXIT

run_attacker_without_approval() {
  local binary=$1
  "$binary" attack &
  local pid=$!
  for _ in 1 2 3 4 5; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid"
      return $?
    fi
    sleep 0.2
  done
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 124
}

swiftc "$root/KeychainSpike.swift" -framework Security -framework LocalAuthentication -o "$build/writer"
swiftc "$root/KeychainSpike.swift" -framework Security -framework LocalAuthentication -o "$build/attacker"

codesign --force --sign - "$build/writer"
codesign --force --sign - "$build/attacker"

export PALLADIN_SPIKE_DATA_PROTECTION=false
unset PALLADIN_SPIKE_ACCESS_GROUP
"$build/writer" write
"$build/writer" read
set +e
run_attacker_without_approval "$build/attacker"
ordinary_attacker_status=$?
"$build/writer" attack
authorized_oracle_status=$?
set -e
[[ $ordinary_attacker_status -eq 0 || $ordinary_attacker_status -eq 124 ]]
[[ $authorized_oracle_status -eq 10 ]]
"$build/writer" delete >/dev/null
echo "result=DIRECT_READ_BLOCKED attacker=different-binary status=$ordinary_attacker_status"
echo "expected=NOT_ISOLATED reason=authorized-runtime-can-be-invoked-as-oracle"

export PALLADIN_SPIKE_DATA_PROTECTION=true
set +e
"$build/writer" write
data_protection_status=$?
set -e
[[ $data_protection_status -ne 0 ]]
echo "result=HARDENED_BLOCKED reason=provisioned-keychain-entitlement-required"
