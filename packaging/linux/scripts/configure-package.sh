#!/usr/bin/env bash
set -euo pipefail

systemd_version=$(systemctl --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
if [[ ! $systemd_version =~ ^[0-9]+$ || $systemd_version -lt 252 ]]; then
  echo 'Error: Palladin Hardened requires systemd 252 or newer' >&2
  exit 78
fi

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo 'Error: package configuration must run as root' >&2
  exit 77
fi

install -d -m 0755 -o root -g root /etc/palladin /etc/palladin/agents.d
install -d -m 0700 -o palladin-runtime -g palladin-runtime /var/lib/palladin-runtime/v1

master_key=/var/lib/palladin-runtime/v1/master.key
if [[ ! -e $master_key ]]; then
  umask 077
  temporary=$(mktemp /var/lib/palladin-runtime/v1/.master-key.XXXXXX)
  trap 'rm -f "$temporary"' EXIT
  dd if=/dev/urandom of="$temporary" bs=32 count=1 status=none
  chown palladin-runtime:palladin-runtime "$temporary"
  chmod 0400 "$temporary"
  mv -T "$temporary" "$master_key"
  trap - EXIT
fi

if [[ ! -f $master_key || -L $master_key ]]; then
  echo 'Error: Palladin master key path is invalid' >&2
  exit 78
fi
owner=$(stat -c '%U:%G:%a:%h:%s' "$master_key")
if [[ $owner != 'palladin-runtime:palladin-runtime:400:1:32' ]]; then
  echo 'Error: Palladin master key permissions are invalid' >&2
  exit 78
fi

broker_uid=$(id -u palladin-runtime)
broker_gid=$(id -g palladin-runtime)
executor_record=$(getent group palladin-executor) || {
  echo 'Error: Palladin executor group is unavailable' >&2
  exit 78
}
IFS=: read -r executor_name _ executor_gid executor_members <<< "$executor_record"
if [[ $executor_name != palladin-executor || ! $executor_gid =~ ^[1-9][0-9]*$ \
  || $executor_gid == "$broker_gid" || -n $executor_members ]]; then
  echo 'Error: Palladin executor group identity is invalid' >&2
  exit 78
fi
marker=$(mktemp /etc/palladin/.runtime-v1.XXXXXX)
trap 'rm -f "$marker"' EXIT
printf 'broker_uid=%s\nbroker_gid=%s\nexecutor_gid=%s\n' \
  "$broker_uid" "$broker_gid" "$executor_gid" > "$marker"
chown root:root "$marker"
chmod 0644 "$marker"
mv -T "$marker" /etc/palladin/runtime-v1
trap - EXIT

systemctl daemon-reload
systemctl enable palladin-executor.socket palladin-runtime.service
# Upgrades replace a matched broker/worker/executor set. Restart the trust boundary so an
# old in-memory broker can never execute a newly replaced worker or executor protocol.
systemctl restart palladin-executor.socket
systemctl restart palladin-runtime.service
for _ in $(seq 1 50); do
  if systemctl is-active --quiet palladin-runtime.service \
    && [[ -S /run/palladin-runtime/broker.sock ]]; then
    exit 0
  fi
  sleep 0.1
done
echo 'Error: the Palladin broker did not become ready after installation' >&2
exit 78
