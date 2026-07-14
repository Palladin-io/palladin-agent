#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo 'Usage: build-rpm.sh --version VERSION --architecture x64|arm64 --binaries DIR --output DIR' >&2
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
case "$architecture" in x64) rpm_arch=x86_64 ;; arm64) rpm_arch=aarch64 ;; *) usage ;; esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
top=$(mktemp -d)
stage=$(mktemp -d)
trap 'rm -rf "$top" "$stage"' EXIT
install -d "$top/BUILD" "$top/BUILDROOT" "$top/RPMS" "$top/SOURCES" "$top/SPECS" "$top/SRPMS"
install -d "$stage/usr/lib/palladin/runtime" "$stage/usr/lib/systemd/system" \
  "$stage/usr/lib/sysusers.d" "$stage/usr/lib/tmpfiles.d" "$stage/usr/share/polkit-1/actions"
install -m 0755 \
  "$binaries/palladin-linux-client" "$binaries/palladin-linux-service" \
  "$binaries/palladin-linux-executor" "$binaries/palladin-linux-admin-purge" \
  "$binaries/palladin-worker" \
  "$stage/usr/lib/palladin/runtime/"
install -m 0755 "$root/scripts/configure-package.sh" "$stage/usr/lib/palladin/runtime/configure-package"
install -m 0755 "$root/scripts/manage-agent-uid.sh" "$stage/usr/lib/palladin/runtime/palladin-manage-agent-uid"
install -m 0755 "$root/scripts/verify-installation.sh" "$stage/usr/lib/palladin/runtime/verify-installation"
install -m 0644 "$root/systemd/"* "$stage/usr/lib/systemd/system/"
install -m 0644 "$root/sysusers.d/palladin-runtime.conf" "$stage/usr/lib/sysusers.d/"
install -m 0644 "$root/tmpfiles.d/palladin-runtime.conf" "$stage/usr/lib/tmpfiles.d/"
install -m 0644 "$root/polkit/io.palladin.runtime.policy" "$stage/usr/share/polkit-1/actions/"
tar -C "$stage" -czf "$top/SOURCES/palladin-runtime-stage.tar.gz" .
sed -e "s/@VERSION@/$version/g" -e "s/@ARCHITECTURE@/$rpm_arch/g" \
  "$root/rpm/palladin-runtime.spec.in" > "$top/SPECS/palladin-runtime.spec"
rpmbuild --define "_topdir $top" -bb "$top/SPECS/palladin-runtime.spec"
mapfile -t packages < <(find "$top/RPMS" -type f -name '*.rpm')
[[ ${#packages[@]} -eq 1 ]]
package=${packages[0]}
payload_digests=$(rpm -qp --qf '[%{FILENAMES}\t%{FILEDIGESTS}\n]' "$package")
for binary in palladin-linux-client palladin-linux-service palladin-linux-executor \
  palladin-linux-admin-purge palladin-worker; do
  expected=$(sha256sum "$binaries/$binary" | cut -d' ' -f1)
  installed="/usr/lib/palladin/runtime/$binary"
  actual=$(awk -F '\t' -v path="$installed" '$1 == path { print $2 }' <<< "$payload_digests")
  if [[ ! $actual =~ ^[0-9a-f]{64}$ || $actual != "$expected" ]]; then
    echo "RPM payload changed the attested $binary bytes" >&2
    exit 1
  fi
done
mkdir -p "$output"
cp "$package" "$output/"
