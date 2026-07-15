#!/usr/bin/env bash

set -euo pipefail

PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
readonly PATH

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  die 'usage: compare-bundles.sh REFERENCE_APP CANDIDATE_APP'
}

[[ $# -eq 2 ]] || usage
reference_root="${1%/}"
candidate_root="${2%/}"
[[ -d "$reference_root" && ! -L "$reference_root" ]] ||
  die 'reference app must be a real directory'
[[ -d "$candidate_root" && ! -L "$candidate_root" ]] ||
  die 'candidate app must be a real directory'

scratch="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/palladin-bundle-compare.XXXXXX")"
cleanup() {
  /bin/rm -rf -- "$scratch"
}
trap cleanup EXIT

append_xattrs() {
  local path="$1"
  local output="$2"
  local attribute
  local value

  while IFS= read -r attribute; do
    [[ -n "$attribute" ]] || continue
    value="$(/usr/bin/xattr -psx "$attribute" "$path" | /usr/bin/tr -d ' \n')" ||
      die 'could not read an app extended attribute'
    printf 'X\0%s\0%s\0' "$attribute" "$value" >>"$output"
  done < <(/usr/bin/xattr -s "$path" | LC_ALL=C /usr/bin/sort)
}

write_manifest() {
  local root="$1"
  local output="$2"
  local path
  local relative
  local entry_type
  local mode
  local digest
  local target

  : >"$output"
  while IFS= read -r -d '' path; do
    if [[ "$path" == "$root" ]]; then
      relative='.'
    else
      relative="${path#"$root"/}"
    fi
    entry_type="$(/usr/bin/stat -f '%HT' "$path")" || die 'could not inspect an app entry type'
    mode="$(/usr/bin/stat -f '%Lp' "$path")" || die 'could not inspect app permissions'
    printf 'P\0%s\0T\0%s\0M\0%s\0' "$relative" "$entry_type" "$mode" >>"$output"

    case "$entry_type" in
      'Regular File')
        digest="$(/usr/bin/shasum -a 256 "$path" | /usr/bin/cut -d ' ' -f 1)" ||
          die 'could not hash an app file'
        printf 'H\0%s\0' "$digest" >>"$output"
        ;;
      'Symbolic Link')
        target="$(/usr/bin/readlink "$path")" || die 'could not inspect an app symlink'
        printf 'L\0%s\0' "$target" >>"$output"
        ;;
      'Directory') ;;
      *) die 'app contains an unsupported filesystem entry type' ;;
    esac
    append_xattrs "$path" "$output"
  done < <(/usr/bin/find -s "$root" -print0)
}

write_manifest "$reference_root" "$scratch/reference.manifest"
write_manifest "$candidate_root" "$scratch/candidate.manifest"
/usr/bin/cmp -s "$scratch/reference.manifest" "$scratch/candidate.manifest" ||
  die 'candidate app filesystem manifest differs from the notarized reference'

printf 'Verified identical app paths, entry types, modes, symlinks, file bytes, and extended attributes.\n'
