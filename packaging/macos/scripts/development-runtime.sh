#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly RUNTIME_DIR="$REPOSITORY_ROOT/runtime"
readonly RUNTIME_BINARY="$RUNTIME_DIR/target/debug/palladin"
readonly DEVELOPMENT_HELPER_BUILD_BINARY="$RUNTIME_DIR/target/debug/palladin-macos-keychain-helper"
readonly DEVELOPMENT_MIGRATOR_SOURCE="$REPOSITORY_ROOT/packaging/macos/tools/development-keychain-migrator.c"
readonly DEVELOPMENT_MIGRATOR_BINARY="$RUNTIME_DIR/target/debug/palladin-development-keychain-migrator"
readonly DEVELOPMENT_IDENTITY="Palladin Local Development"
readonly DEVELOPMENT_IDENTIFIER="io.palladin.runtime.development"
readonly DEVELOPMENT_HELPER_IDENTIFIER="io.palladin.runtime.development.keychain-helper.v1"
readonly DEVELOPMENT_HELPER_FILENAME="palladin-keychain-helper-v1"
readonly DEVELOPMENT_KEYCHAIN_FILENAME="palladin-development.keychain-db"
readonly TEMPORARY_IMPORT_PASSWORD="palladin-local-import"

BOOTSTRAP_TEMP_DIR=""
BOOTSTRAP_KEYCHAIN=""
BOOTSTRAP_CERTIFICATE=""
BOOTSTRAP_CREATED=0
BOOTSTRAP_TRUSTED=0
BOOTSTRAP_COMMITTED=0

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat >&2 <<'USAGE'
Usage:
  development-runtime.sh bootstrap
  development-runtime.sh build [--local-development]
  development-runtime.sh sign
  development-runtime.sh run [--local-development] -- [PALLADIN_ARGUMENTS...]
  development-runtime.sh verify
  development-runtime.sh migrate-keychain-access
  development-runtime.sh install-launcher [--force] ABSOLUTE_PATH
  development-runtime.sh reset --confirm

The development identity is local-only. It never enables the macos-hardened
feature, release entitlements, Hardened Runtime, notarization or a Team ID.
USAGE
  exit 64
}

remove_bootstrap_temp_dir() {
  if [[ -n "$BOOTSTRAP_TEMP_DIR" && -d "$BOOTSTRAP_TEMP_DIR" &&
        "$BOOTSTRAP_TEMP_DIR" == "${TMPDIR:-/tmp}/palladin-development-signing."* ]]; then
    rm -rf -- "$BOOTSTRAP_TEMP_DIR"
    BOOTSTRAP_TEMP_DIR=""
    BOOTSTRAP_CERTIFICATE=""
  fi
}

cleanup() {
  local status=$?
  if (( status != 0 && BOOTSTRAP_CREATED == 1 && BOOTSTRAP_COMMITTED == 0 )); then
    if (( BOOTSTRAP_TRUSTED == 1 )) && [[ -f "$BOOTSTRAP_CERTIFICATE" ]]; then
      security remove-trusted-cert "$BOOTSTRAP_CERTIFICATE" >/dev/null 2>&1 || true
    fi
    security delete-keychain "$BOOTSTRAP_KEYCHAIN" >/dev/null 2>&1 || true
  fi
  remove_bootstrap_temp_dir || true
  exit "$status"
}
trap cleanup EXIT

require_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || die "local development signing is available only on macOS"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_signing_tools() {
  require_macos
  require_command security
  require_command codesign
  require_command /usr/bin/openssl
}

build_keychain_migrator() {
  require_command xcrun
  [[ -f "$DEVELOPMENT_MIGRATOR_SOURCE" && ! -L "$DEVELOPMENT_MIGRATOR_SOURCE" ]] ||
    die "the development Keychain migrator source is unavailable"
  mkdir -p "$(dirname -- "$DEVELOPMENT_MIGRATOR_BINARY")"
  xcrun clang \
    -std=c17 \
    -O2 \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -Wall \
    -Wextra \
    -Werror \
    -Wformat=2 \
    -Wshadow \
    -Wconversion \
    -Wno-deprecated-declarations \
    -framework CoreFoundation \
    -framework Security \
    "$DEVELOPMENT_MIGRATOR_SOURCE" \
    -o "$DEVELOPMENT_MIGRATOR_BINARY"
  chmod 700 "$DEVELOPMENT_MIGRATOR_BINARY"
}

account_home() {
  local account record home
  account="$(id -un)" || die "the current account name is unavailable"
  record="$(/usr/bin/dscl . -read "/Users/$account" NFSHomeDirectory 2>/dev/null)" ||
    die "the current account directory is unavailable"
  home="${record#NFSHomeDirectory: }"
  [[ "$home" == /* && -d "$home" && ! -L "$home" ]] ||
    die "the current account directory is invalid"
  printf '%s\n' "$home"
}

development_keychain() {
  local configured home keychain parent parent_physical
  configured="${PALLADIN_DEVELOPMENT_KEYCHAIN_PATH:-}"
  if [[ -n "$configured" ]]; then
    [[ "$configured" == /* && "$(basename -- "$configured")" == "$DEVELOPMENT_KEYCHAIN_FILENAME" ]] ||
      die "PALLADIN_DEVELOPMENT_KEYCHAIN_PATH must be an absolute path ending in $DEVELOPMENT_KEYCHAIN_FILENAME"
    keychain="$configured"
  else
    home="$(account_home)"
    keychain="$home/Library/Keychains/$DEVELOPMENT_KEYCHAIN_FILENAME"
  fi
  parent="$(dirname -- "$keychain")"
  [[ -d "$parent" ]] || die "development Keychain directory is unavailable: $parent"
  parent_physical="$(CDPATH='' cd -- "$parent" && pwd -P)" ||
    die "development Keychain directory could not be resolved: $parent"
  printf '%s/%s\n' "$parent_physical" "$DEVELOPMENT_KEYCHAIN_FILENAME"
}

development_helper() {
  local configured home root helper parent parent_physical
  configured="${PALLADIN_DEVELOPMENT_HELPER_PATH:-}"
  if [[ -n "$configured" ]]; then
    [[ "$configured" == /* && "$(basename -- "$configured")" == "$DEVELOPMENT_HELPER_FILENAME" ]] ||
      die "PALLADIN_DEVELOPMENT_HELPER_PATH must be an absolute path ending in $DEVELOPMENT_HELPER_FILENAME"
    helper="$configured"
  else
    home="$(account_home)"
    root="$home/.palladin"
    if [[ ! -e "$root" ]]; then
      mkdir -m 700 "$root"
    fi
    [[ -d "$root" && ! -L "$root" ]] || die "the Palladin root is invalid: $root"
    parent="$root/development"
    if [[ ! -e "$parent" ]]; then
      mkdir -m 700 "$parent"
    fi
    [[ -d "$parent" && ! -L "$parent" ]] || die "the development helper directory is invalid: $parent"
    helper="$parent/$DEVELOPMENT_HELPER_FILENAME"
  fi
  parent="$(dirname -- "$helper")"
  [[ -d "$parent" && ! -L "$parent" ]] || die "development helper directory is unavailable: $parent"
  parent_physical="$(CDPATH='' cd -- "$parent" && pwd -P)" ||
    die "development helper directory could not be resolved: $parent"
  printf '%s/%s\n' "$parent_physical" "$DEVELOPMENT_HELPER_FILENAME"
}

read_user_keychains() {
  local line path
  USER_KEYCHAINS=()
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    path="${line#\"}"
    path="${path%\"}"
    [[ -n "$path" ]] && USER_KEYCHAINS+=("$path")
  done < <(security list-keychains -d user)
}

add_to_user_keychain_search_list() {
  local keychain="$1"
  local candidate
  read_user_keychains
  for candidate in "${USER_KEYCHAINS[@]}"; do
    [[ "$candidate" == "$keychain" ]] && return
  done
  security list-keychains -d user -s "${USER_KEYCHAINS[@]}" "$keychain"
}

remove_from_user_keychain_search_list() {
  local keychain="$1"
  local candidate
  local -a remaining=()
  read_user_keychains
  for candidate in "${USER_KEYCHAINS[@]}"; do
    [[ "$candidate" != "$keychain" ]] && remaining+=("$candidate")
  done
  if (( ${#remaining[@]} > 0 )); then
    security list-keychains -d user -s "${remaining[@]}"
  fi
}

identity_hash() {
  local keychain="$1"
  local fingerprint
  fingerprint="$(security find-certificate -c "$DEVELOPMENT_IDENTITY" -Z "$keychain" 2>/dev/null |
    awk '/^SHA-1 hash: / { print $3; exit }')"
  [[ "$fingerprint" =~ ^[0-9A-F]{40}$ ]] || return 1
  printf '%s\n' "$fingerprint"
}

verify_identity() {
  local keychain="$1"
  local identities fingerprint mode
  [[ -f "$keychain" && ! -L "$keychain" ]] || return 1
  mode="$(stat -f '%Lp' "$keychain")" || return 1
  (( (8#$mode & 077) == 0 )) || return 1
  security unlock-keychain -p '' "$keychain" >/dev/null 2>&1 || return 1
  add_to_user_keychain_search_list "$keychain" || return 1
  fingerprint="$(identity_hash "$keychain")" || return 1
  identities="$(security find-identity -v -p codesigning "$keychain" 2>/dev/null)" || return 1
  grep -F -q "$fingerprint \"$DEVELOPMENT_IDENTITY\"" <<<"$identities" || return 1
  grep -F -q '1 valid identities found' <<<"$identities"
}

create_identity() {
  local keychain="$1"
  local parent
  parent="$(dirname -- "$keychain")"
  [[ -d "$parent" && ! -L "$parent" ]] || die "development Keychain directory is unavailable: $parent"
  [[ ! -e "$keychain" && ! -L "$keychain" ]] ||
    die "development Keychain already exists but is invalid; run reset --confirm after reviewing it"

  umask 077
  BOOTSTRAP_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/palladin-development-signing.XXXXXX")"
  BOOTSTRAP_KEYCHAIN="$keychain"
  BOOTSTRAP_CERTIFICATE="$BOOTSTRAP_TEMP_DIR/identity.crt"

  /usr/bin/openssl req -new -newkey rsa:3072 -x509 -sha256 -days 3650 -nodes -batch \
    -subj "/CN=$DEVELOPMENT_IDENTITY/O=Palladin Local Development" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=critical,codeSigning' \
    -keyout "$BOOTSTRAP_TEMP_DIR/identity.key" \
    -out "$BOOTSTRAP_CERTIFICATE" >/dev/null 2>&1
  /usr/bin/openssl pkcs12 -export \
    -inkey "$BOOTSTRAP_TEMP_DIR/identity.key" \
    -in "$BOOTSTRAP_CERTIFICATE" \
    -name "$DEVELOPMENT_IDENTITY" \
    -passout "pass:$TEMPORARY_IMPORT_PASSWORD" \
    -out "$BOOTSTRAP_TEMP_DIR/identity.p12"

  security create-keychain -p '' "$keychain"
  BOOTSTRAP_CREATED=1
  security set-keychain-settings -lut 21600 "$keychain"
  security unlock-keychain -p '' "$keychain"
  security import "$BOOTSTRAP_TEMP_DIR/identity.p12" \
    -k "$keychain" \
    -f pkcs12 \
    -P "$TEMPORARY_IMPORT_PASSWORD" \
    -x \
    -T /usr/bin/codesign >/dev/null
  security set-key-partition-list -S apple-tool:,apple: -s -k '' "$keychain" >/dev/null
  printf 'macOS may request one-time approval for the local code-signing trust setting.\n' >&2
  security add-trusted-cert -r trustRoot -p codeSign -k "$keychain" "$BOOTSTRAP_CERTIFICATE"
  BOOTSTRAP_TRUSTED=1
  add_to_user_keychain_search_list "$keychain"
  verify_identity "$keychain" || die "the local development signing identity could not be verified"
  remove_bootstrap_temp_dir || die "the temporary development signing material could not be removed"
  BOOTSTRAP_COMMITTED=1
  printf 'Created local macOS development signing identity: %s\n' "$DEVELOPMENT_IDENTITY" >&2
}

ensure_identity() {
  local keychain
  require_signing_tools
  keychain="$(development_keychain)"
  if [[ -e "$keychain" || -L "$keychain" ]]; then
    verify_identity "$keychain" ||
      die "the development signing identity is invalid; review it and run reset --confirm before recreating it"
  else
    create_identity "$keychain"
  fi
  printf '%s\n' "$keychain"
}

require_runtime_binary() {
  require_command file
  [[ -f "$RUNTIME_BINARY" && ! -L "$RUNTIME_BINARY" && -x "$RUNTIME_BINARY" ]] ||
    die "the debug Palladin runtime is unavailable: $RUNTIME_BINARY"
  [[ "$(file -b "$RUNTIME_BINARY")" == *'Mach-O'* ]] ||
    die "the debug Palladin runtime is not a Mach-O executable"
}

verify_runtime_signature() {
  local keychain="$1"
  local fingerprint fingerprint_lower details requirement entitlements
  require_runtime_binary
  fingerprint="$(identity_hash "$keychain")" || die "the development signing certificate is unavailable"
  fingerprint_lower="$(tr '[:upper:]' '[:lower:]' <<<"$fingerprint")"
  codesign --verify --strict --verbose=2 "$RUNTIME_BINARY" >/dev/null 2>&1 ||
    die "the local development runtime signature is invalid"
  details="$(codesign -d --verbose=4 "$RUNTIME_BINARY" 2>&1)" ||
    die "the local development runtime signature details are unavailable"
  grep -F -x -q "Identifier=$DEVELOPMENT_IDENTIFIER" <<<"$details" ||
    die "the local development runtime identifier is invalid"
  grep -F -x -q "Authority=$DEVELOPMENT_IDENTITY" <<<"$details" ||
    die "the local development runtime authority is invalid"
  grep -F -x -q 'TeamIdentifier=not set' <<<"$details" ||
    die "the local development runtime unexpectedly has a Team ID"
  grep -E -q '^CodeDirectory .*flags=0x0\(none\)' <<<"$details" ||
    die "the local development runtime unexpectedly enables signing flags"
  if grep -F -q 'Signature=adhoc' <<<"$details"; then
    die "the local development runtime still has an ad hoc signature"
  fi

  requirement="$(codesign -d -r- "$RUNTIME_BINARY" 2>&1)" ||
    die "the local development runtime requirement is unavailable"
  grep -F -q "designated => identifier \"$DEVELOPMENT_IDENTIFIER\" and certificate root = H\"$fingerprint_lower\"" \
    <<<"$requirement" || die "the local development runtime requirement is not stable"
  if grep -F -q 'designated => cdhash ' <<<"$requirement"; then
    die "the local development runtime requirement still depends on CDHash"
  fi

  entitlements="$(codesign -d --entitlements :- "$RUNTIME_BINARY" 2>&1)" ||
    die "the local development runtime entitlements could not be inspected"
  if grep -F -q '<key>' <<<"$entitlements"; then
    die "the local development runtime must not carry release entitlements"
  fi
}

verify_helper_signature() {
  local helper="$1"
  local keychain="$2"
  local fingerprint fingerprint_lower details requirement entitlements mode owner
  [[ -f "$helper" && ! -L "$helper" ]] || die "the development Keychain helper is unavailable: $helper"
  mode="$(stat -f '%Lp' "$helper")" || die "the development Keychain helper mode is unavailable"
  [[ "$mode" == 500 ]] || die "the development Keychain helper must have mode 0500"
  owner="$(stat -f '%u' "$helper")" || die "the development Keychain helper owner is unavailable"
  [[ "$owner" == "$(id -u)" ]] || die "the development Keychain helper owner is invalid"
  [[ "$(file -b "$helper")" == *'Mach-O'* ]] ||
    die "the development Keychain helper is not a Mach-O executable"
  fingerprint="$(identity_hash "$keychain")" || die "the development signing certificate is unavailable"
  fingerprint_lower="$(tr '[:upper:]' '[:lower:]' <<<"$fingerprint")"
  codesign --verify --strict --verbose=2 "$helper" >/dev/null 2>&1 ||
    die "the development Keychain helper signature is invalid"
  details="$(codesign -d --verbose=4 "$helper" 2>&1)" ||
    die "the development Keychain helper signature details are unavailable"
  grep -F -x -q "Identifier=$DEVELOPMENT_HELPER_IDENTIFIER" <<<"$details" ||
    die "the development Keychain helper identifier is invalid"
  grep -F -x -q "Authority=$DEVELOPMENT_IDENTITY" <<<"$details" ||
    die "the development Keychain helper authority is invalid"
  grep -F -x -q 'TeamIdentifier=not set' <<<"$details" ||
    die "the development Keychain helper unexpectedly has a Team ID"
  grep -E -q '^CodeDirectory .*flags=0x0\(none\)' <<<"$details" ||
    die "the development Keychain helper unexpectedly enables signing flags"
  requirement="$(codesign -d -r- "$helper" 2>&1)" ||
    die "the development Keychain helper requirement is unavailable"
  grep -F -q "designated => identifier \"$DEVELOPMENT_HELPER_IDENTIFIER\" and certificate root = H\"$fingerprint_lower\"" \
    <<<"$requirement" || die "the development Keychain helper requirement is not stable"
  entitlements="$(codesign -d --entitlements :- "$helper" 2>&1)" ||
    die "the development Keychain helper entitlements could not be inspected"
  if grep -F -q '<key>' <<<"$entitlements"; then
    die "the development Keychain helper must not carry release entitlements"
  fi
}

sign_helper_build() {
  local keychain="$1"
  local fingerprint
  [[ -f "$DEVELOPMENT_HELPER_BUILD_BINARY" && ! -L "$DEVELOPMENT_HELPER_BUILD_BINARY" &&
     -x "$DEVELOPMENT_HELPER_BUILD_BINARY" ]] ||
    die "the development Keychain helper build is unavailable"
  fingerprint="$(identity_hash "$keychain")" || die "the development signing certificate is unavailable"
  codesign --force \
    --sign "$fingerprint" \
    --keychain "$keychain" \
    --identifier "$DEVELOPMENT_HELPER_IDENTIFIER" \
    --timestamp=none \
    "$DEVELOPMENT_HELPER_BUILD_BINARY"
}

ensure_development_helper() {
  local keychain="$1"
  local helper helper_dir temporary_helper
  helper="$(development_helper)"
  if [[ -e "$helper" || -L "$helper" ]]; then
    verify_helper_signature "$helper" "$keychain"
    printf '%s\n' "$helper"
    return
  fi

  (cd "$RUNTIME_DIR" && cargo build --locked -p palladin-macos-keychain-helper)
  sign_helper_build "$keychain"
  helper_dir="$(dirname -- "$helper")"
  temporary_helper="$(mktemp "$helper_dir/.palladin-keychain-helper.XXXXXX")"
  cp "$DEVELOPMENT_HELPER_BUILD_BINARY" "$temporary_helper"
  chmod 500 "$temporary_helper"
  mv "$temporary_helper" "$helper"
  verify_helper_signature "$helper" "$keychain"
  printf 'Installed stable local Keychain helper: %s\n' "$helper" >&2
  printf '%s\n' "$helper"
}

replace_development_helper_for_migration() {
  local keychain="$1"
  local helper helper_dir temporary_helper
  [[ $# -eq 1 ]] || die "invalid internal Keychain helper migration invocation"
  require_command cargo
  helper="$(development_helper)"
  if [[ -e "$helper" || -L "$helper" ]]; then
    verify_helper_signature "$helper" "$keychain"
  fi
  (cd "$RUNTIME_DIR" && cargo build --locked -p palladin-macos-keychain-helper)
  sign_helper_build "$keychain"
  if [[ -f "$helper" && ! -L "$helper" ]] && cmp -s "$DEVELOPMENT_HELPER_BUILD_BINARY" "$helper"; then
    verify_helper_signature "$helper" "$keychain"
    printf '%s\n' "$helper"
    return
  fi
  helper_dir="$(dirname -- "$helper")"
  temporary_helper="$(mktemp "$helper_dir/.palladin-keychain-helper.XXXXXX")"
  cp "$DEVELOPMENT_HELPER_BUILD_BINARY" "$temporary_helper"
  chmod 500 "$temporary_helper"
  mv -f -- "$temporary_helper" "$helper"
  verify_helper_signature "$helper" "$keychain"
  printf 'Installed the explicitly upgraded stable local Keychain helper.\n' >&2
  printf '%s\n' "$helper"
}

sign_runtime() {
  local keychain fingerprint
  keychain="$(ensure_identity)"
  require_runtime_binary
  fingerprint="$(identity_hash "$keychain")" || die "the development signing certificate is unavailable"
  security unlock-keychain -p '' "$keychain"
  add_to_user_keychain_search_list "$keychain"
  codesign --force \
    --sign "$fingerprint" \
    --keychain "$keychain" \
    --identifier "$DEVELOPMENT_IDENTIFIER" \
    --timestamp=none \
    "$RUNTIME_BINARY"
  verify_runtime_signature "$keychain"
}

build_runtime() {
  local enable_local_development="${1:-0}"
  local keychain
  local -a cargo_arguments=(build --locked -p palladin-cli)
  [[ $# -eq 1 && ( "$enable_local_development" == 0 || "$enable_local_development" == 1 ) ]] ||
    die "invalid internal local-development build mode"
  [[ -z "${CARGO_TARGET_DIR:-}" ]] ||
    die "CARGO_TARGET_DIR is unsupported because the signed runtime path must remain deterministic"
  require_command cargo
  if [[ "$enable_local_development" == 1 ]]; then
    cargo_arguments+=(--features local-development)
  fi
  (cd "$RUNTIME_DIR" && cargo "${cargo_arguments[@]}")
  sign_runtime
  keychain="$(development_keychain)"
  ensure_development_helper "$keychain" >/dev/null
}

migrate_keychain_access() {
  local keychain helper home login_keychain
  require_signing_tools
  keychain="$(development_keychain)"
  verify_identity "$keychain" || die "the local development signing identity is invalid"
  helper="$(replace_development_helper_for_migration "$keychain")"
  home="$(account_home)"
  login_keychain="$home/Library/Keychains/login.keychain-db"
  [[ -f "$login_keychain" && ! -L "$login_keychain" ]] ||
    die "the Login Keychain is unavailable"
  build_keychain_migrator
  printf 'macOS may show one authorization dialog per existing Palladin item. Approve each one-time read.\n' >&2
  if ! "$DEVELOPMENT_MIGRATOR_BINARY" "$login_keychain" "$helper"; then
    die "one-time Login Keychain migration did not complete; rerun it and approve every existing Palladin item"
  fi
}

install_launcher() {
  local force=0
  local launcher launcher_dir temporary_launcher
  if [[ "${1:-}" == "--force" ]]; then
    force=1
    shift
  fi
  [[ $# -eq 1 ]] || usage
  launcher="$1"
  [[ "$launcher" == /* ]] || die "launcher path must be absolute"
  launcher_dir="$(dirname -- "$launcher")"
  [[ -d "$launcher_dir" && ! -L "$launcher_dir" ]] ||
    die "launcher directory is unavailable: $launcher_dir"
  [[ ! -L "$launcher" ]] || die "refusing to replace a symlinked launcher"
  if [[ -e "$launcher" && $force -ne 1 ]]; then
    die "launcher already exists; pass --force after reviewing it"
  fi
  temporary_launcher="$(mktemp "$launcher_dir/.palladin-development-launcher.XXXXXX")"
  {
    printf '#!/usr/bin/env bash\n\nset -euo pipefail\n\n'
    # Launcher arguments must expand when the generated launcher runs.
    # shellcheck disable=SC2016
    printf 'if [[ "${1:-}" == "--local-development" ]]; then\n  shift\n  exec '
    printf '%q' "$SCRIPT_DIR/development-runtime.sh"
    printf ' run --local-development -- "$@"\nfi\n\nexec '
    printf '%q' "$SCRIPT_DIR/development-runtime.sh"
    printf ' run -- "$@"\n'
  } >"$temporary_launcher"
  chmod 700 "$temporary_launcher"
  mv -f -- "$temporary_launcher" "$launcher"
  printf 'Installed Palladin development launcher: %s\n' "$launcher"
}

reset_identity() {
  local keychain helper certificate_dir certificate
  [[ "${1:-}" == "--confirm" && $# -eq 1 ]] || usage
  require_signing_tools
  keychain="$(development_keychain)"
  [[ -f "$keychain" && ! -L "$keychain" ]] || die "the development Keychain is unavailable"
  certificate_dir="$(mktemp -d "${TMPDIR:-/tmp}/palladin-development-signing.XXXXXX")"
  BOOTSTRAP_TEMP_DIR="$certificate_dir"
  certificate="$certificate_dir/identity.crt"
  security find-certificate -c "$DEVELOPMENT_IDENTITY" -p "$keychain" >"$certificate" 2>/dev/null ||
    die "the development signing certificate is unavailable"
  helper="$(development_helper)"
  if [[ -e "$helper" || -L "$helper" ]]; then
    verify_helper_signature "$helper" "$keychain"
    rm -f -- "$helper"
  fi
  security remove-trusted-cert "$certificate" >/dev/null 2>&1 || true
  remove_from_user_keychain_search_list "$keychain"
  security delete-keychain "$keychain"
  printf 'Removed local macOS development signing identity and helper.\n'
}

command_name="${1:-}"
[[ -n "$command_name" ]] || usage
shift

case "$command_name" in
  bootstrap)
    [[ $# -eq 0 ]] || usage
    ensure_identity >/dev/null
    printf 'Local macOS development signing is ready.\n'
    ;;
  build)
    build_local_development=0
    if [[ "${1:-}" == "--local-development" ]]; then
      build_local_development=1
      shift
    fi
    [[ $# -eq 0 ]] || usage
    build_runtime "$build_local_development"
    printf 'Built and signed local Palladin runtime: %s\n' "$RUNTIME_BINARY"
    ;;
  sign)
    [[ $# -eq 0 ]] || usage
    sign_runtime
    printf 'Signed local Palladin runtime: %s\n' "$RUNTIME_BINARY"
    ;;
  run)
    run_local_development=0
    if [[ "${1:-}" == "--local-development" ]]; then
      run_local_development=1
      shift
    fi
    [[ "${1:-}" == "--" ]] || usage
    shift
    build_runtime "$run_local_development"
    exec "$RUNTIME_BINARY" "$@"
    ;;
  verify)
    [[ $# -eq 0 ]] || usage
    keychain="$(development_keychain)"
    verify_identity "$keychain" || die "the local development signing identity is invalid"
    verify_runtime_signature "$keychain"
    helper="$(development_helper)"
    verify_helper_signature "$helper" "$keychain"
    printf 'Verified stable local Palladin runtime and Keychain helper signatures.\n'
    ;;
  migrate-keychain-access)
    [[ $# -eq 0 ]] || usage
    migrate_keychain_access
    ;;
  install-launcher)
    install_launcher "$@"
    ;;
  reset)
    reset_identity "$@"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    ;;
esac
