#!/usr/bin/env bash
set -euo pipefail

format=${1:-}
package=${2:-}
agent=${3:-}
[[ $(id -u) -eq 0 && -f $package && -n $agent ]] || exit 64
root=$(mktemp -d /var/tmp/palladin-upgrade.XXXXXX)
launcher=
cleanup() {
  [[ -z $launcher ]] || kill "$launcher" >/dev/null 2>&1 || true
  rm -rf "$root"
}
trap cleanup EXIT
case "$format" in
  deb) dpkg-deb --control "$package" "$root/control" ;;
  rpm)
    mkdir "$root/control"
    rpm -qp --qf '%{PREIN}\n' "$package" > "$root/control/preinst"
    ;;
  *) exit 64 ;;
esac
[[ -s $root/control/preinst ]] || { echo 'Package has no pre-unpack quiescence hook' >&2; exit 1; }

mkfifo "$root/stdin"
exec 9<>"$root/stdin"
runuser -u "$agent" -- /usr/lib/palladin/runtime/palladin-linux-client mcp serve \
  <"$root/stdin" >"$root/stdout" 2>"$root/stderr" &
launcher=$!
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"upgrade-boundary","version":"1"}}}' >&9
for _ in $(seq 1 100); do
  grep -q '"protocolVersion"' "$root/stdout" && break
  sleep 0.1
done
grep -q '"protocolVersion"' "$root/stdout"
broker_pid=$(systemctl show -p MainPID --value palladin-runtime.service)
mapfile -t worker_pids < <(pgrep -P "$broker_pid")
[[ ${#worker_pids[@]} -gt 0 ]]
# Execute the shipped pre-install hook at the package-manager's pre-unpack phase.
# The old MCP generation must be gone before any new executable can be written.
sh "$root/control/preinst" upgrade
! systemctl is-active --quiet palladin-runtime.service
! systemctl is-active --quiet palladin-executor.socket
for pid in "$broker_pid" "${worker_pids[@]}"; do
  [[ ! -d /proc/$pid ]] || { echo 'Old runtime generation survived pre-unpack' >&2; exit 1; }
done
for _ in $(seq 1 100); do
  kill -0 "$launcher" >/dev/null 2>&1 || break
  sleep 0.1
done
if kill -0 "$launcher" >/dev/null 2>&1; then
  echo 'MCP client did not close after its broker generation stopped' >&2
  exit 1
fi
wait "$launcher" || true
launcher=
exec 9>&-
echo 'upgrade-pre-unpack=quiesced existing-mcp-generation=terminated'
