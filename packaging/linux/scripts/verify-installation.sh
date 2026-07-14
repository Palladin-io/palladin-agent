#!/usr/bin/env bash
set -euo pipefail

fail() { echo "Error: $*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || fail 'verification must run as root'

for binary in palladin-linux-client palladin-linux-service palladin-linux-executor palladin-linux-admin-purge palladin-worker; do
  path=/usr/lib/palladin/runtime/$binary
  [[ -f $path && ! -L $path && -x $path ]] || fail "$path is missing or not executable"
  [[ $(stat -c '%U:%G:%a:%h' "$path") == 'root:root:755:1' ]] || fail "$path permissions are invalid"
done

[[ $(stat -c '%U:%G:%a:%h' /etc/palladin/runtime-v1) == 'root:root:644:1' ]] || fail 'install marker permissions are invalid'
[[ $(stat -c '%U:%G:%a:%h:%s' /var/lib/palladin-runtime/v1/master.key) == 'palladin-runtime:palladin-runtime:400:1:32' ]] || fail 'master key permissions are invalid'
executor_record=$(getent group palladin-executor) || fail 'executor group is unavailable'
IFS=: read -r executor_name _ executor_gid executor_members <<< "$executor_record"
[[ $executor_name == palladin-executor && $executor_gid =~ ^[1-9][0-9]*$ && -z $executor_members ]] || fail 'executor group membership is invalid'
grep -Fxq "executor_gid=$executor_gid" /etc/palladin/runtime-v1 || fail 'executor group marker is invalid'
systemd-analyze verify \
  /usr/lib/systemd/system/palladin-runtime.service \
  /usr/lib/systemd/system/palladin-executor.socket \
  /usr/lib/systemd/system/palladin-executor@.service
systemctl is-active --quiet palladin-runtime.service palladin-executor.socket || fail 'services are not active'
[[ $(stat -c '%U:%G:%a' /run/palladin-executor/executor.sock) == 'root:palladin-executor:660' ]] || fail 'executor socket permissions are invalid'
broker_pid=$(systemctl show -p MainPID --value palladin-runtime.service)
grep -Eq "^Groups:.*(^|[[:space:]])$executor_gid([[:space:]]|$)" "/proc/$broker_pid/status" || fail 'broker lacks the executor supplementary group'
