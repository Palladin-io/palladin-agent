#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo 'Usage: test-convenience-boundary.sh --launcher-root PATH' >&2
  exit 64
}

launcher_root=
while (( $# > 0 )); do
  case "$1" in
    --launcher-root) [[ $# -ge 2 ]] || usage; launcher_root=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ $(uname -s) == Linux && -n $launcher_root ]] || usage
launcher_root=$(realpath "$launcher_root")
launcher="$launcher_root/dist/bin/palladin.js"
[[ -f $launcher && ! -L $launcher ]] || { echo 'Error: exact staged launcher is missing' >&2; exit 1; }
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
umask 077
printf '%s' 'synthetic-secret-not-production' > "$root/secret"

bash -c 'test -r "$1" && cmp -s "$1" "$2"' _ "$root/secret" <(printf '%s' 'synthetic-secret-not-production')
echo 'tier=Convenience same-uid-file-read=success expected=not-isolated'
echo 'tier=Convenience secret-service-boundary=same-uid expected=not-process-isolated'

cc -Wall -Wextra -Werror -shared -fPIC \
  -DPALLADIN_PROBE_DIRECTORY="\"$root\"" \
  "$(dirname "$0")/ld-preload-probe.c" -o "$root/preload.so"
LD_PRELOAD="$root/preload.so" node "$launcher" doctor >/dev/null
[[ -f $root/node.hit ]]
[[ -f $root/client.hit ]]
[[ ! -e $root/worker.hit ]]
echo 'tier=Convenience ld-preload=node-and-client expected=same-uid-loader-control'
echo 'tier=Convenience ld-preload=sealed-worker-denied expected=env-cleared-before-secret-bearing-worker'
