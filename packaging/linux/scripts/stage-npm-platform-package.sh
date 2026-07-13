#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo 'Usage: stage-npm-platform-package.sh --architecture x64|arm64 --binaries DIR --output DIR' >&2
  exit 64
}

architecture=''
binaries=''
output=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --architecture) architecture=${2:-}; shift 2 ;;
    --binaries) binaries=${2:-}; shift 2 ;;
    --output) output=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done
[[ $architecture == x64 || $architecture == arm64 ]] || usage
[[ -d $binaries && -n $output ]] || usage

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
template="$root/packages/runtime-linux-${architecture}-gnu"
[[ -f $template/package.json ]] || { echo 'Error: Linux package template is missing' >&2; exit 1; }
rm -rf "$output"
install -d "$output/bin"
install -m 0755 "$binaries/palladin-linux-client" "$output/bin/palladin-linux-client"
install -m 0755 "$binaries/palladin-worker" "$output/bin/palladin-worker"
install -m 0644 "$template/README.md" "$output/README.md"
install -m 0644 "$root/LICENSE" "$output/LICENSE"
node - "$template/package.json" "$output/package.json" "$architecture" <<'NODE'
const [source, output, architecture] = process.argv.slice(2);
const fs = require('node:fs');
const manifest = JSON.parse(fs.readFileSync(source, 'utf8'));
delete manifest.private;
manifest.os = ['linux'];
manifest.cpu = [architecture];
manifest.libc = ['glibc'];
manifest.files = ['bin/palladin-linux-client', 'bin/palladin-worker', 'README.md', 'LICENSE'];
fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
NODE
