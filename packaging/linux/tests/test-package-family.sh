#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo 'Usage: test-package-family.sh <ubuntu|debian|fedora|rocky9|native-ubuntu> BASE_PACKAGE UPGRADE_PACKAGE STATE_FIXTURE VERSION_POLICY' >&2
  exit 64
}

family=${1:-}
native=false
if [[ $family == native-ubuntu ]]; then
  native=true
  family=ubuntu
  [[ $(id -u) -eq 0 && $(cat /proc/1/comm) == systemd ]] || usage
  ! systemd-detect-virt --container --quiet || usage
fi
base=${2:-}
upgrade=${3:-}
state_fixture=${4:-}
version_policy=${5:-}
[[ $family == ubuntu || $family == debian || $family == fedora || $family == rocky9 ]] || usage
[[ -f $base && -f $upgrade && -x $state_fixture && -f $version_policy ]] || usage

root=$(cd "$(dirname "$0")/../../.." && pwd)
image=palladin-runtime-$family-test
container=palladin-runtime-$family-$RANDOM-$$
extension=deb
[[ $family == fedora || $family == rocky9 ]] && extension=rpm
cleanup() {
  status=$?
  if $native; then
    userdel palladin-package-state >/dev/null 2>&1 || true
    return "$status"
  fi
  if [[ $status -ne 0 ]]; then
    docker exec "$container" journalctl --no-pager -n 200 2>/dev/null || true
  fi
  docker rm --force "$container" >/dev/null 2>&1 || true
  docker image rm --force "$image" >/dev/null 2>&1 || true
  return "$status"
}
trap cleanup EXIT

if ! $native; then
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

fi

target_exec() {
  if $native; then
    "$@"
  else
    docker exec "$container" "$@"
  fi
}
base_target=/packages/base.$extension
upgrade_target=/packages/upgrade.$extension
fixture_target=/state-fixture
policy_target=/version-policy.json
source_target=/source
if $native; then
  base_target=$(realpath "$base")
  upgrade_target=$(realpath "$upgrade")
  fixture_target=$(realpath "$state_fixture")
  policy_target=$(realpath "$version_policy")
  source_target=$root
fi

if $native; then
  installer_stages_before=$(find /var/tmp -maxdepth 1 -type d -name 'palladin-install.*' -printf '%f\n' | sort)
  invalid_bundle=$(mktemp /var/tmp/palladin-invalid-attestation.XXXXXX)
  printf '%s\n' '{"invalid":"test fixture"}' > "$invalid_bundle"
  package_version=$(dpkg-deb --field "$base_target" Version)
  package_version=${package_version%-*}
  if "$source_target/packaging/linux/scripts/install-hardened.sh" \
    "$package_version" "$(git -c safe.directory="$source_target" -C "$source_target" rev-parse HEAD)" \
    "$base_target" "$invalid_bundle"; then
    rm -f "$invalid_bundle"
    echo 'Administrator installer accepted an invalid provenance bundle' >&2
    exit 1
  else
    status=$?
  fi
  [[ $(find /var/tmp -maxdepth 1 -type d -name 'palladin-install.*' -printf '%f\n' | sort) == "$installer_stages_before" ]]
  [[ $status -eq 1 ]] || { echo 'Installer failed before its provenance check' >&2; exit 1; }
  rm -f "$invalid_bundle"
  [[ ! -e /var/lib/palladin-runtime/v1/master.key ]]
  [[ ! -e /usr/lib/palladin/runtime/palladin-worker ]]
  echo 'administrator-installer=invalid-provenance-denied-before-package-execution'
fi

compat_agent=palladin-package-state
compat_uid=
compat_principal=
compat_master_hash=
compat_state_hash=
compat_policy_state_hash=

seed_compatible_state() {
  local agents_root broker_gid broker_uid
  target_exec useradd --system --no-create-home --shell /usr/sbin/nologin "$compat_agent"
  target_exec /usr/lib/palladin/runtime/palladin-manage-agent-uid \
    authorize "$compat_agent" package-state https://api.stage.palladin.io --dedicated
  compat_uid=$(target_exec id -u "$compat_agent")
  compat_principal=$(target_exec sed -n 's/^principal=//p' "/etc/palladin/agents.d/$compat_uid")
  [[ $compat_principal =~ ^[0-9a-f]{32}$ ]]
  target_exec cmp "$policy_target" /usr/lib/palladin/runtime/release-signature.json
  agents_root=/var/lib/palladin-runtime/v1/agents
  target_exec install -d -m 0700 -o palladin-runtime -g palladin-runtime "$agents_root"
  target_exec runuser -u "$compat_agent" -- \
    /usr/lib/palladin/runtime/palladin-linux-client init \
    | grep -F 'Palladin initialized: package-state'
  broker_uid=$(target_exec id -u palladin-runtime)
  broker_gid=$(target_exec id -g palladin-runtime)
  target_exec setpriv \
    --reuid "$broker_uid" --regid "$broker_gid" --clear-groups -- \
    "$fixture_target" seed \
    "/var/lib/palladin-runtime/v1/agents/$compat_principal" \
    /var/lib/palladin-runtime/v1/master.key \
    "$compat_principal"
  compat_master_hash=$(target_exec sha256sum /var/lib/palladin-runtime/v1/master.key | cut -d' ' -f1)
  compat_state_hash=$(target_exec sh -c \
    "find '/var/lib/palladin-runtime/v1/agents/$compat_principal' -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1")
  compat_policy_state_hash=$(target_exec sh -c \
    "sha256sum /usr/lib/palladin/runtime/release-signature.json | cut -d' ' -f1")
}

verify_compatible_state() {
  local broker_gid broker_uid current_policy_state_hash current_state_hash
  [[ $(target_exec id -u "$compat_agent") == "$compat_uid" ]]
  [[ $(target_exec sed -n 's/^principal=//p' "/etc/palladin/agents.d/$compat_uid") == "$compat_principal" ]]
  [[ $(target_exec sha256sum /var/lib/palladin-runtime/v1/master.key | cut -d' ' -f1) == "$compat_master_hash" ]]
  target_exec runuser -u "$compat_agent" -- \
    /usr/lib/palladin/runtime/palladin-linux-client init \
    | grep -F 'Palladin already initialized: package-state'
  broker_uid=$(target_exec id -u palladin-runtime)
  broker_gid=$(target_exec id -g palladin-runtime)
  target_exec setpriv \
    --reuid "$broker_uid" --regid "$broker_gid" --clear-groups -- \
    "$fixture_target" verify \
    "/var/lib/palladin-runtime/v1/agents/$compat_principal" \
    /var/lib/palladin-runtime/v1/master.key \
    "$compat_principal"
  current_state_hash=$(target_exec sh -c \
    "find '/var/lib/palladin-runtime/v1/agents/$compat_principal' -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1")
  [[ $current_state_hash == "$compat_state_hash" ]]
  current_policy_state_hash=$(target_exec sh -c \
    "sha256sum /usr/lib/palladin/runtime/release-signature.json | cut -d' ' -f1")
  [[ $current_policy_state_hash == "$compat_policy_state_hash" ]]
  target_exec runuser -u "$compat_agent" -- \
    node "$source_target/packaging/linux/tests/mcp-stdio-smoke.mjs" \
    /usr/lib/palladin/runtime/palladin-linux-client
}

case "$family" in
  ubuntu|debian)
    target_exec apt-get install --yes "$base_target"
    target_exec /usr/lib/palladin/runtime/verify-installation
    seed_compatible_state
    target_exec "$source_target/packaging/linux/tests/test-upgrade-quiescence.sh" \
      "$extension" "$upgrade_target" "$compat_agent"
    target_exec apt-get install --yes "$upgrade_target"
    target_exec /usr/lib/palladin/runtime/verify-installation
    verify_compatible_state
    target_exec apt-get install --yes --allow-downgrades "$base_target"
    ;;
  fedora|rocky9)
    target_exec dnf install --assumeyes "$base_target"
    target_exec /usr/lib/palladin/runtime/verify-installation
    seed_compatible_state
    target_exec "$source_target/packaging/linux/tests/test-upgrade-quiescence.sh" \
      "$extension" "$upgrade_target" "$compat_agent"
    target_exec dnf upgrade --assumeyes "$upgrade_target"
    target_exec /usr/lib/palladin/runtime/verify-installation
    verify_compatible_state
    target_exec rpm --upgrade --oldpackage --replacepkgs "$base_target"
    ;;
esac

target_exec /usr/lib/palladin/runtime/verify-installation
verify_compatible_state
target_exec rm /usr/lib/palladin/runtime/palladin-linux-client
target_exec bash -c 'source "$1"; install_verified_package "$2" "$3"' -- \
  "$source_target/packaging/linux/scripts/install-hardened.sh" "$extension" "$base_target"
target_exec /usr/lib/palladin/runtime/verify-installation
verify_compatible_state
echo 'same-version-package-repair=passed identity=preserved'
target_exec "$source_target/packaging/linux/tests/test-hardened-boundary.sh"

case "$family" in
  ubuntu|debian)
    target_exec apt-get remove --yes palladin-runtime
    target_exec test -f /var/lib/palladin-runtime/v1/master.key
    target_exec apt-get install --yes "$upgrade_target"
    ;;
  fedora|rocky9)
    target_exec dnf remove --assumeyes palladin-runtime
    target_exec test -f /var/lib/palladin-runtime/v1/master.key
    target_exec dnf install --assumeyes "$upgrade_target"
    ;;
esac
target_exec /usr/lib/palladin/runtime/verify-installation
verify_compatible_state
target_exec /usr/lib/palladin/runtime/palladin-manage-agent-uid \
  revoke-purge "$compat_agent" --confirm-purge
target_exec grep -Fxq 'status=revoked' "/etc/palladin/agents.d/$compat_uid"
target_exec test ! -e "/var/lib/palladin-runtime/v1/agents/$compat_principal"
case "$family" in
  ubuntu|debian)
    target_exec apt-get purge --yes palladin-runtime
    if target_exec dpkg-query --show palladin-runtime >/dev/null 2>&1; then
      echo 'DEB remained installed after final purge' >&2
      exit 1
    fi
    ;;
  fedora|rocky9)
    target_exec dnf remove --assumeyes palladin-runtime
    if target_exec rpm --query --quiet palladin-runtime; then
      echo 'RPM remained installed after final removal' >&2
      exit 1
    fi
    ;;
esac
target_exec systemctl daemon-reload
for path in \
  /usr/lib/palladin/runtime \
  /usr/lib/systemd/system/palladin-runtime.service \
  /usr/lib/systemd/system/palladin-executor.socket \
  /usr/lib/systemd/system/palladin-executor@.service \
  /usr/lib/sysusers.d/palladin-runtime.conf \
  /usr/lib/tmpfiles.d/palladin-runtime.conf \
  /usr/share/polkit-1/actions/io.palladin.runtime.policy \
  /run/palladin-runtime/broker.sock; do
  target_exec test ! -e "$path"
done
for unit in palladin-runtime.service palladin-executor.socket palladin-executor@uninstall-probe.service; do
  [[ $(target_exec systemctl show --property=LoadState --value "$unit") == not-found ]]
done
target_exec test -d /var/lib/palladin-runtime
target_exec test -d /etc/palladin
echo "platform-lifecycle=$family native=$native install=passed enroll=synthetic-state mcp=passed update=passed rollback=passed reinstall=passed identity=preserved grants=preserved-by-agent-identity purge=passed uninstall=passed"
