#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo 'error=linux-host-required'
  exit 64
fi

root=$(mktemp -d)
trap 'sudo -n userdel palladin-spike-owner >/dev/null 2>&1 || true; sudo -n userdel palladin-spike-attacker >/dev/null 2>&1 || true; rm -rf "$root"' EXIT

same_uid_file="$root/same-uid.identity"
umask 077
printf '%s' 'synthetic-agent-identity-not-production' > "$same_uid_file"

if ! bash -c 'test -r "$1" && test "$(wc -c < "$1")" -gt 0' _ "$same_uid_file"; then
  echo 'unexpected=same-uid-read-failed'
  exit 1
fi
echo 'result=NOT_ISOLATED attacker-read=success scope=same-uid-mode-0600'

if ! sudo -n true >/dev/null 2>&1; then
  echo 'result=UNTESTED boundary=dedicated-uid reason=passwordless-sudo-unavailable'
  exit 0
fi

sudo -n useradd --system --no-create-home --shell /usr/sbin/nologin palladin-spike-owner
sudo -n useradd --system --no-create-home --shell /usr/sbin/nologin palladin-spike-attacker
owner_dir="$root/owner"
sudo -n install -d -m 0700 -o palladin-spike-owner -g palladin-spike-owner "$owner_dir"
printf '%s' 'synthetic-agent-identity-not-production' | sudo -n tee "$owner_dir/identity" >/dev/null
sudo -n chown palladin-spike-owner:palladin-spike-owner "$owner_dir/identity"
sudo -n chmod 0600 "$owner_dir/identity"

if sudo -n -u palladin-spike-attacker test -r "$owner_dir/identity"; then
  echo 'unexpected=dedicated-uid-attacker-read-success'
  exit 1
fi
echo 'result=ISOLATED attacker-read=denied boundary=dedicated-uid'
