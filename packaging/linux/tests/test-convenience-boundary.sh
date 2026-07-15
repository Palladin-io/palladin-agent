#!/usr/bin/env bash
set -euo pipefail

[[ $(uname -s) == Linux ]] || { echo 'Error: Linux is required' >&2; exit 64; }
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
umask 077
printf '%s' 'synthetic-secret-not-production' > "$root/secret"

bash -c 'test -r "$1" && cmp -s "$1" "$2"' _ "$root/secret" <(printf '%s' 'synthetic-secret-not-production')
echo 'tier=Convenience same-uid-file-read=success expected=not-isolated'
echo 'tier=Convenience secret-service-boundary=same-uid expected=not-process-isolated'

cc -shared -fPIC -DPALLADIN_PROBE_PATH="\"$root/ld-preload-hit\"" \
  "$(dirname "$0")/ld-preload-probe.c" -o "$root/preload.so"
LD_PRELOAD="$root/preload.so" /bin/true
[[ -f $root/ld-preload-hit ]]
echo 'tier=Convenience ld-preload-constructor=executed expected=client-holds-no-hardened-secret'
