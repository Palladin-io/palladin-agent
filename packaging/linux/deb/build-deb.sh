#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo 'Usage: build-deb.sh --version VERSION --architecture x64|arm64 --binaries DIR --output DIR' >&2
  exit 64
}

version=''
architecture=''
binaries=''
output=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version=${2:-}; shift 2 ;;
    --architecture) architecture=${2:-}; shift 2 ;;
    --binaries) binaries=${2:-}; shift 2 ;;
    --output) output=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n $version && -n $architecture && -d $binaries && -n $output ]] || usage
case "$architecture" in x64) deb_arch=amd64 ;; arm64) deb_arch=arm64 ;; *) usage ;; esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
install -d "$stage/DEBIAN" "$stage/usr/lib/palladin/runtime" "$stage/usr/lib/systemd/system" \
  "$stage/usr/lib/sysusers.d" "$stage/usr/lib/tmpfiles.d" "$stage/usr/share/polkit-1/actions"
sed -e "s/@VERSION@/$version/g" -e "s/@ARCHITECTURE@/$deb_arch/g" "$root/deb/control.in" > "$stage/DEBIAN/control"
install -m 0755 "$root/deb/postinst" "$root/deb/prerm" "$root/deb/postrm" "$stage/DEBIAN/"
install -m 0755 \
  "$binaries/palladin-linux-client" "$binaries/palladin-linux-service" \
  "$binaries/palladin-linux-executor" "$binaries/palladin-worker" \
  "$stage/usr/lib/palladin/runtime/"
install -m 0755 "$root/scripts/configure-package.sh" "$stage/usr/lib/palladin/runtime/configure-package"
install -m 0755 "$root/scripts/manage-agent-uid.sh" "$stage/usr/lib/palladin/runtime/palladin-manage-agent-uid"
install -m 0755 "$root/scripts/verify-installation.sh" "$stage/usr/lib/palladin/runtime/verify-installation"
install -m 0644 "$root/systemd/"* "$stage/usr/lib/systemd/system/"
install -m 0644 "$root/sysusers.d/palladin-runtime.conf" "$stage/usr/lib/sysusers.d/"
install -m 0644 "$root/tmpfiles.d/palladin-runtime.conf" "$stage/usr/lib/tmpfiles.d/"
install -m 0644 "$root/polkit/io.palladin.runtime.policy" "$stage/usr/share/polkit-1/actions/"
mkdir -p "$output"
dpkg-deb --root-owner-group --build "$stage" "$output/palladin-runtime_${version}_${deb_arch}.deb"
