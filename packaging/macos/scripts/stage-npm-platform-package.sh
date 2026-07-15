#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd -P)"
readonly SCRIPT_DIR REPOSITORY_ROOT

# shellcheck source=packaging/macos/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  printf 'usage: %s --architecture arm64|x64 --app PATH --output-dir PATH\n' "$(basename "$0")" >&2
  exit 64
}

app_path=''
output_dir=''
architecture=''

while (($# > 0)); do
  case "$1" in
    --architecture)
      (($# >= 2)) || usage
      architecture="$2"
      shift 2
      ;;
    --app)
      (($# >= 2)) || usage
      app_path="$2"
      shift 2
      ;;
    --output-dir)
      (($# >= 2)) || usage
      output_dir="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ "$architecture" == 'arm64' || "$architecture" == 'x64' ]] || usage
[[ -n "$app_path" && -n "$output_dir" ]] || usage
[[ -d "$app_path" && ! -L "$app_path" ]] || die "app bundle is not a directory: $app_path"
require_empty_output_path "$output_dir" "npm staging directory"
require_command ditto
require_command node

readonly package_source="$REPOSITORY_ROOT/packages/runtime-darwin-$architecture"
require_regular_file "$package_source/package.json" "private workspace manifest"
require_regular_file "$package_source/README.md" "platform package README"
require_regular_file "$REPOSITORY_ROOT/LICENSE" "repository license"

mkdir -p "$output_dir"
cp "$package_source/package.json" "$package_source/README.md" "$REPOSITORY_ROOT/LICENSE" "$output_dir/"
ditto "$app_path" "$output_dir/PalladinRuntime.app"

node - "$output_dir/package.json" "$architecture" <<'NODE'
const fs = require('node:fs');

const path = process.argv[2];
const architecture = process.argv[3];
const manifest = JSON.parse(fs.readFileSync(path, 'utf8'));
if (manifest.private !== true) {
  throw new Error('platform workspace manifest must remain private');
}
if (manifest.scripts || manifest.dependencies || manifest.optionalDependencies) {
  throw new Error('platform package must not execute lifecycle code or contain dependencies');
}

delete manifest.private;
manifest.os = ['darwin'];
manifest.cpu = [architecture];
manifest.publishConfig = { access: 'public', provenance: true };
fs.writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
NODE
node "$REPOSITORY_ROOT/packaging/npm/verify-platform-package.mjs" \
  --package "$output_dir" \
  --name "@palladin/runtime-darwin-$architecture" \
  --os darwin \
  --cpu "$architecture" \
  --libc none \
  --files '["PalladinRuntime.app/","README.md","LICENSE"]'
