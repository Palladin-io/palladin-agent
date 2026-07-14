#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo 'Usage: test-package-family.sh <debian|fedora|rocky9> BASE_PACKAGE UPGRADE_PACKAGE STATE_FIXTURE VERSION_POLICY' >&2
  exit 64
}

family=${1:-}
base=${2:-}
upgrade=${3:-}
state_fixture=${4:-}
version_policy=${5:-}
[[ $family == debian || $family == fedora || $family == rocky9 ]] || usage
[[ -f $base && -f $upgrade && -x $state_fixture && -f $version_policy ]] || usage

root=$(cd "$(dirname "$0")/../../.." && pwd)
image=palladin-runtime-$family-test
container=palladin-runtime-$family-$RANDOM-$$
extension=deb
[[ $family == fedora || $family == rocky9 ]] && extension=rpm
cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    docker exec "$container" journalctl --no-pager -n 200 2>/dev/null || true
  fi
  docker rm --force "$container" >/dev/null 2>&1 || true
  docker image rm --force "$image" >/dev/null 2>&1 || true
  return "$status"
}
trap cleanup EXIT

docker build \
  --file "$root/packaging/linux/tests/containers/$family.Dockerfile" \
  --tag "$image" "$root/packaging/linux/tests/containers"
docker run --detach \
  --name "$container" \
  --privileged \
  --cgroupns=private \
  --tmpfs /tmp \
  --tmpfs /run \
  --tmpfs /run/lock \
  --volume "$root:/source:ro" \
  --volume "$(realpath "$base"):/packages/base.$extension:ro" \
  --volume "$(realpath "$upgrade"):/packages/upgrade.$extension:ro" \
  --volume "$(realpath "$state_fixture"):/state-fixture:ro" \
  --volume "$(realpath "$version_policy"):/version-policy.json:ro" \
  "$image" >/dev/null

state=initializing
for _ in $(seq 1 30); do
  state=$(docker exec "$container" systemctl is-system-running 2>&1 || true)
  if [[ $state == running || $state == degraded ]]; then
    break
  fi
  sleep 1
done
if [[ $state != running && $state != degraded ]]; then
  echo "Error: $family systemd did not become ready (state: $state)" >&2
  docker exec "$container" systemctl --failed --no-pager >&2 || true
  docker logs "$container" >&2 || true
  exit 1
fi

compat_agent=palladin-package-state
compat_uid=
compat_principal=
compat_master_hash=
compat_state_hash=

seed_compatible_state() {
  local agents_root broker_gid broker_uid policy_cache policy_digest
  docker exec "$container" useradd --system --no-create-home --shell /usr/sbin/nologin "$compat_agent"
  docker exec "$container" /usr/lib/palladin/runtime/palladin-manage-agent-uid \
    authorize "$compat_agent" package-state https://api.stage.palladin.io --dedicated
  compat_uid=$(docker exec "$container" id -u "$compat_agent")
  compat_principal=$(docker exec "$container" sed -n 's/^principal=//p' "/etc/palladin/agents.d/$compat_uid")
  [[ $compat_principal =~ ^[0-9a-f]{32}$ ]]
  policy_digest=$(docker exec "$container" sha256sum /version-policy.json | cut -d' ' -f1)
  [[ $policy_digest =~ ^[0-9a-f]{64}$ ]]
  agents_root=/var/lib/palladin-runtime/v1/agents
  docker exec "$container" install -d -m 0700 -o palladin-runtime -g palladin-runtime "$agents_root"
  policy_cache="$agents_root/.$compat_principal.palladin-policy-cache-v1"
  docker exec "$container" install -d -m 0700 -o palladin-runtime -g palladin-runtime "$policy_cache"
  docker exec "$container" install -m 0600 -o palladin-runtime -g palladin-runtime \
    /version-policy.json "$policy_cache/1-$policy_digest.json"
  docker exec "$container" runuser -u "$compat_agent" -- \
    /usr/lib/palladin/runtime/palladin-linux-client init \
    | grep -F 'Palladin initialized: package-state'
  broker_uid=$(docker exec "$container" id -u palladin-runtime)
  broker_gid=$(docker exec "$container" id -g palladin-runtime)
  docker exec "$container" setpriv \
    --reuid "$broker_uid" --regid "$broker_gid" --clear-groups -- \
    /state-fixture seed \
    "/var/lib/palladin-runtime/v1/agents/$compat_principal" \
    /var/lib/palladin-runtime/v1/master.key \
    "$compat_principal"
  compat_master_hash=$(docker exec "$container" sha256sum /var/lib/palladin-runtime/v1/master.key | cut -d' ' -f1)
  compat_state_hash=$(docker exec "$container" sh -c \
    "find '/var/lib/palladin-runtime/v1/agents/$compat_principal' -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1")
}

verify_compatible_state() {
  local broker_gid broker_uid current_state_hash
  [[ $(docker exec "$container" id -u "$compat_agent") == "$compat_uid" ]]
  [[ $(docker exec "$container" sed -n 's/^principal=//p' "/etc/palladin/agents.d/$compat_uid") == "$compat_principal" ]]
  [[ $(docker exec "$container" sha256sum /var/lib/palladin-runtime/v1/master.key | cut -d' ' -f1) == "$compat_master_hash" ]]
  docker exec "$container" runuser -u "$compat_agent" -- \
    /usr/lib/palladin/runtime/palladin-linux-client init \
    | grep -F 'Palladin already initialized: package-state'
  broker_uid=$(docker exec "$container" id -u palladin-runtime)
  broker_gid=$(docker exec "$container" id -g palladin-runtime)
  docker exec "$container" setpriv \
    --reuid "$broker_uid" --regid "$broker_gid" --clear-groups -- \
    /state-fixture verify \
    "/var/lib/palladin-runtime/v1/agents/$compat_principal" \
    /var/lib/palladin-runtime/v1/master.key \
    "$compat_principal"
  current_state_hash=$(docker exec "$container" sh -c \
    "find '/var/lib/palladin-runtime/v1/agents/$compat_principal' -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1")
  [[ $current_state_hash == "$compat_state_hash" ]]
}

case "$family" in
  debian)
    docker exec "$container" apt-get install --yes /packages/base.deb
    docker exec "$container" /usr/lib/palladin/runtime/verify-installation
    seed_compatible_state
    docker exec "$container" apt-get install --yes /packages/upgrade.deb
    docker exec "$container" /usr/lib/palladin/runtime/verify-installation
    verify_compatible_state
    docker exec "$container" apt-get install --yes --allow-downgrades /packages/base.deb
    ;;
  fedora|rocky9)
    docker exec "$container" dnf install --assumeyes /packages/base.rpm
    docker exec "$container" /usr/lib/palladin/runtime/verify-installation
    seed_compatible_state
    docker exec "$container" dnf upgrade --assumeyes /packages/upgrade.rpm
    docker exec "$container" /usr/lib/palladin/runtime/verify-installation
    verify_compatible_state
    docker exec "$container" rpm --upgrade --oldpackage --replacepkgs /packages/base.rpm
    ;;
esac

docker exec "$container" /usr/lib/palladin/runtime/verify-installation
verify_compatible_state
docker exec "$container" /source/packaging/linux/tests/test-hardened-boundary.sh

case "$family" in
  debian)
    docker exec "$container" apt-get remove --yes palladin-runtime
    docker exec "$container" test -f /var/lib/palladin-runtime/v1/master.key
    docker exec "$container" apt-get install --yes /packages/upgrade.deb
    ;;
  fedora|rocky9)
    docker exec "$container" dnf remove --assumeyes palladin-runtime
    docker exec "$container" test -f /var/lib/palladin-runtime/v1/master.key
    docker exec "$container" dnf install --assumeyes /packages/upgrade.rpm
    ;;
esac
docker exec "$container" /usr/lib/palladin/runtime/verify-installation
verify_compatible_state
