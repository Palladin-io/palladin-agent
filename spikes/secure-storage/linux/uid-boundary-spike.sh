#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo 'error=linux-host-required'
  exit 64
fi

root=$(mktemp -d)
suffix=$(printf '%x%x' "$$" "$RANDOM")
owner_user="ps-owner-$suffix"
attacker_user="ps-attack-$suffix"
owner_created=false
attacker_created=false

cleanup() {
  sudo -n rm -rf "$root" >/dev/null 2>&1 || rm -rf "$root"
  if $owner_created; then
    sudo -n userdel "$owner_user" >/dev/null 2>&1 || true
  fi
  if $attacker_created; then
    sudo -n userdel "$attacker_user" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

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

if getent passwd "$owner_user" >/dev/null || getent passwd "$attacker_user" >/dev/null; then
  echo 'unexpected=random-test-user-collision'
  exit 1
fi
sudo -n useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$owner_user"
owner_created=true
sudo -n useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$attacker_user"
attacker_created=true
chmod 0711 "$root"
owner_dir="$root/owner"
sudo -n install -d -m 0700 -o "$owner_user" -g "$owner_user" "$owner_dir"
printf '%s' 'synthetic-agent-identity-not-production' | sudo -n tee "$owner_dir/identity" >/dev/null
sudo -n chown "$owner_user:$owner_user" "$owner_dir/identity"
sudo -n chmod 0600 "$owner_dir/identity"

if ! sudo -n -u "$owner_user" test -r "$owner_dir/identity"; then
  echo 'unexpected=dedicated-uid-owner-read-failed'
  exit 1
fi
echo 'positive-control=owner-read-success boundary=dedicated-uid'

if sudo -n -u "$attacker_user" test -r "$owner_dir/identity"; then
  echo 'unexpected=dedicated-uid-attacker-read-success'
  exit 1
fi
echo 'result=ISOLATED attacker-read=denied boundary=dedicated-uid'
