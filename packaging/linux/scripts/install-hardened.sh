#!/bin/bash
set -euo pipefail

supported_platform() {
  local distribution=$1 version=$2 systemd_version=$3 architecture=$4 init=$5 container=$6
  if [[ ! $systemd_version =~ ^[0-9]+$ || $systemd_version -lt 252 \
    || $init != systemd || $container != none ]]; then
    echo 'Error: Hardened requires a native systemd 252+ host or VM; application containers and OpenRC are unsupported' >&2
    return 78
  fi
  case "$architecture" in x86_64|aarch64) ;; *) echo 'Error: Hardened supports only x64 and ARM64' >&2; return 78 ;; esac
  case "$distribution:$version" in
    ubuntu:24.04|debian:13) echo deb ;;
    fedora:44|rocky:9|rocky:9.*) echo rpm ;;
    *) echo 'Error: this distribution/version is outside the Linux Hardened support matrix' >&2; return 78 ;;
  esac
}

main() {
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin
  if [[ $# -ne 4 || ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ || ! $2 =~ ^[0-9a-f]{40}$ ]]; then
    echo 'Usage: install-hardened.sh VERSION SOURCE_SHA PACKAGE ATTESTATION_BUNDLE' >&2
    return 64
  fi
  [[ $EUID -eq 0 ]] || { echo 'Error: run this verified installer explicitly as an administrator; npm never elevates privileges' >&2; return 77; }
  local version=$1 source_sha=$2 package=$3 bundle=$4
  [[ -f $package && ! -L $package && -f $bundle && ! -L $bundle ]] || return 65
  [[ -x /usr/bin/gh ]] || { echo 'Error: install the GitHub CLI with attestation verification support at /usr/bin/gh first' >&2; return 78; }
  local ID VERSION_ID systemd_version architecture init container format filename
  # /etc/os-release is administrator-owned operating-system configuration.
  source /etc/os-release
  systemd_version=$(systemctl --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
  architecture=$(uname -m)
  init=$(cat /proc/1/comm)
  container=$(systemd-detect-virt --container || true)
  format=$(supported_platform "$ID" "$VERSION_ID" "$systemd_version" "$architecture" "$init" "$container") || return $?
  if [[ $format == deb ]]; then
    local deb_arch=amd64
    [[ $architecture != aarch64 ]] || deb_arch=arm64
    filename="palladin-runtime_${version}-1_${deb_arch}.deb"
  else
    filename="palladin-runtime-${version}-1.${architecture}.rpm"
  fi
  [[ $(basename "$package") == "$filename" ]] || { echo 'Error: package does not match the requested version and host architecture' >&2; return 65; }
  umask 077
  local stage
  stage=$(mktemp -d /var/tmp/palladin-install.XXXXXX)
  trap 'rm -rf "$stage"' EXIT
  install -m 0600 -- "$package" "$stage/$filename"
  install -m 0600 -- "$bundle" "$stage/attestation.jsonl"
  # Verify the root-owned snapshot, not the caller-writable download, before any package script runs.
  env -i PATH="$PATH" HOME=/root /usr/bin/gh attestation verify "$stage/$filename" \
    --bundle "$stage/attestation.jsonl" --repo Palladin-io/palladin-agent \
    --signer-workflow Palladin-io/palladin-agent/.github/workflows/release-meta.yml \
    --source-ref "refs/tags/v$version" --source-digest "$source_sha" --deny-self-hosted-runners
  if [[ $format == deb ]]; then
    apt-get install --yes "$stage/$filename"
  else
    # Local packages use the verified GitHub provenance signature; repository dependency GPG checks remain enabled.
    dnf install --assumeyes --setopt=localpkg_gpgcheck=0 "$stage/$filename"
  fi
  /usr/lib/palladin/runtime/verify-installation
  rm -rf "$stage"
  trap - EXIT
  echo 'Hardened system components installed. Authorize a dedicated Agent account before using credentials; existing identities were preserved.'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
