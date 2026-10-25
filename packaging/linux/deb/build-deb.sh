#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo 'Usage: build-deb.sh --version VERSION --architecture x64|arm64 --binaries DIR --output DIR --release-manifest FILE --public-key BASE64 --source-sha SHA [--revision NUMBER] [--development-loopback]' >&2
  exit 64
}

version=''
architecture=''
binaries=''
output=''
release_manifest=''
public_key=''
source_sha=''
revision=1
loopback_policy=production
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version=${2:-}; shift 2 ;;
    --revision) revision=${2:-}; shift 2 ;;
    --architecture) architecture=${2:-}; shift 2 ;;
    --binaries) binaries=${2:-}; shift 2 ;;
    --output) output=${2:-}; shift 2 ;;
    --release-manifest) release_manifest=${2:-}; shift 2 ;;
    --public-key) public_key=${2:-}; shift 2 ;;
    --source-sha) source_sha=${2:-}; shift 2 ;;
    --development-loopback) loopback_policy=development; shift ;;
    *) usage ;;
  esac
done
[[ -n $version && -n $architecture && -d $binaries && -n $output ]] || usage
[[ $revision =~ ^[1-9][0-9]*$ ]] || usage
runtime_version=$version
if [[ $loopback_policy == development ]]; then
  if [[ ! $version =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.dev[0-9A-Za-z.]*$ ]]; then
    echo 'Error: development loopback packages require an explicitly .dev-labelled version' >&2
    exit 64
  fi
  runtime_version=${BASH_REMATCH[1]}
fi
[[ -f $release_manifest && -n $public_key && -n $source_sha ]] || usage
case "$architecture" in x64) deb_arch=amd64 ;; arm64) deb_arch=arm64 ;; *) usage ;; esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
node "$root/scripts/verify-runtime-manifest.mjs" \
  --manifest "$release_manifest" --public-key "$public_key" \
  --version "$runtime_version" --source-sha "$source_sha" \
  --architecture "$architecture" --binaries "$binaries"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
install -d "$stage/DEBIAN" "$stage/usr/lib/palladin/runtime" "$stage/usr/lib/systemd/system" \
  "$stage/usr/lib/sysusers.d" "$stage/usr/lib/tmpfiles.d" "$stage/usr/share/polkit-1/actions"
sed -e "s/@VERSION@/${version}-${revision}/g" -e "s/@ARCHITECTURE@/$deb_arch/g" "$root/deb/control.in" > "$stage/DEBIAN/control"
install -m 0755 "$root/deb/postinst" "$root/deb/prerm" "$root/deb/postrm" "$stage/DEBIAN/"
install -m 0755 \
  "$binaries/palladin-linux-client" "$binaries/palladin-linux-service" \
  "$binaries/palladin-linux-executor" "$binaries/palladin-linux-admin-purge" \
  "$binaries/palladin-worker" \
  "$stage/usr/lib/palladin/runtime/"
install -m 0644 "$release_manifest" "$stage/usr/lib/palladin/runtime/release-signature.json"
install -m 0755 "$root/scripts/configure-package.sh" "$stage/usr/lib/palladin/runtime/configure-package"
sed "s/@PALLADIN_LOOPBACK_POLICY@/$loopback_policy/g" \
  "$root/scripts/manage-agent-uid.sh" > "$stage/usr/lib/palladin/runtime/palladin-manage-agent-uid"
chmod 0755 "$stage/usr/lib/palladin/runtime/palladin-manage-agent-uid"
if grep -Fq '@PALLADIN_LOOPBACK_POLICY@' "$stage/usr/lib/palladin/runtime/palladin-manage-agent-uid"; then
  echo 'Error: the packaged authorization helper contains an unresolved origin policy' >&2
  exit 1
fi
install -m 0755 "$root/scripts/verify-installation.sh" "$stage/usr/lib/palladin/runtime/verify-installation"
install -m 0644 "$root/systemd/"* "$stage/usr/lib/systemd/system/"
install -m 0644 "$root/sysusers.d/palladin-runtime.conf" "$stage/usr/lib/sysusers.d/"
install -m 0644 "$root/tmpfiles.d/palladin-runtime.conf" "$stage/usr/lib/tmpfiles.d/"
install -m 0644 "$root/polkit/io.palladin.runtime.policy" "$stage/usr/share/polkit-1/actions/"
mkdir -p "$output"
dpkg-deb --root-owner-group --build "$stage" "$output/palladin-runtime_${version}-${revision}_${deb_arch}.deb"
