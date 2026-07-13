#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo 'Usage: stage-npm-platform-package.sh --architecture x64|arm64 --libc glibc|musl --binaries DIR --output DIR' >&2
  exit 64
}

architecture=''
libc_family=''
binaries=''
output=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --architecture) architecture=${2:-}; shift 2 ;;
    --libc) libc_family=${2:-}; shift 2 ;;
    --binaries) binaries=${2:-}; shift 2 ;;
    --output) output=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done
[[ $architecture == x64 || $architecture == arm64 ]] || usage
[[ $libc_family == glibc || $libc_family == musl ]] || usage
[[ -d $binaries && -n $output ]] || usage

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
package_suffix=musl
[[ $libc_family == glibc ]] && package_suffix=gnu
template="$root/packages/runtime-linux-${architecture}-${package_suffix}"
[[ -f $template/package.json ]] || { echo 'Error: Linux package template is missing' >&2; exit 1; }
rm -rf "$output"
install -d "$output/bin"
install -m 0755 "$binaries/palladin-linux-client" "$output/bin/palladin-linux-client"
install -m 0755 "$binaries/palladin-worker" "$output/bin/palladin-worker"
install -m 0644 "$template/README.md" "$output/README.md"
install -m 0644 "$root/LICENSE" "$output/LICENSE"
node - "$template/package.json" "$output/package.json" "$architecture" "$libc_family" <<'NODE'
const [source, output, architecture, libc] = process.argv.slice(2);
const fs = require('node:fs');
const manifest = JSON.parse(fs.readFileSync(source, 'utf8'));
if (manifest.private !== true) throw new Error('platform workspace must remain private');
for (const field of ['scripts', 'dependencies', 'optionalDependencies']) {
  if (Object.hasOwn(manifest, field)) throw new Error(`platform package must not contain ${field}`);
}
delete manifest.private;
manifest.os = ['linux'];
manifest.cpu = [architecture];
manifest.libc = [libc];
manifest.files = ['bin/palladin-linux-client', 'bin/palladin-worker', 'README.md', 'LICENSE'];
fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
NODE
node "$root/packaging/npm/verify-platform-package.mjs" \
  --package "$output" \
  --name "@palladin/runtime-linux-${architecture}-${package_suffix}" \
  --os linux \
  --cpu "$architecture" \
  --libc "$libc_family" \
  --files '["bin/palladin-linux-client","bin/palladin-worker","README.md","LICENSE"]'
