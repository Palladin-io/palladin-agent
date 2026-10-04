#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  printf 'usage: run-linux-secret-service.sh CONTRACT_JSON\n' >&2
  exit 2
fi

test "$(uname -m)" = "$EXPECTED_MACHINE"
# shellcheck source=/dev/null
. /etc/os-release
test "$ID" = "$EXPECTED_DISTRIBUTION"
case "$EXPECTED_DISTRIBUTION:$VERSION_ID" in
  ubuntu:24.04|ubuntu:24.04.*|alpine:3.22|alpine:3.22.*) ;;
  *) printf 'unexpected Linux distribution version\n' >&2; exit 1 ;;
esac
runtime_dir=$(mktemp -d)
chmod 700 "$runtime_dir"
mkdir -m 700 "$runtime_dir/home"
export HOME="$runtime_dir/home"
export XDG_RUNTIME_DIR="$runtime_dir"
trap 'rm -rf "$runtime_dir"' EXIT HUP INT TERM

# shellcheck disable=SC2016
dbus-run-session -- sh -eu -c '
  password=$(node -e "process.stdout.write(require(\"node:crypto\").randomBytes(32).toString(\"hex\"))")
  daemon_environment=$(printf "%s\n" "$password" | gnome-keyring-daemon --unlock --components=secrets)
  eval "$daemon_environment"
  unset daemon_environment
  unset password
  exec node security/lifecycle/run-physical-target.mjs "$1"
' sh "$1"
