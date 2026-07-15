#!/usr/bin/env bash
set -euo pipefail

readonly PALLADIN_LOOPBACK_POLICY='@PALLADIN_LOOPBACK_POLICY@'

usage() {
  echo 'Usage: palladin-manage-agent-uid <authorize USER PROFILE HOST --dedicated|revoke USER|revoke-purge USER --confirm-purge>' >&2
  exit 64
}

fail_account() {
  echo "Error: $*" >&2
  exit 65
}

valid_loopback_host() {
  local host=$1 port
  if [[ $host =~ ^http://127\.0\.0\.1:([0-9]{1,5})$ \
    || $host =~ ^http://\[::1\]:([0-9]{1,5})$ ]]; then
    port=${BASH_REMATCH[1]}
    (( 10#$port >= 1 && 10#$port <= 65535 ))
    return
  fi
  return 1
}

valid_record_host() {
  local host=$1
  case "$host" in
    https://api.palladin.io|https://api.stage.palladin.io) return 0 ;;
  esac
  # A historical development record must remain revocable after installing a
  # production helper. This parser is never used to grant authorization.
  valid_loopback_host "$host"
}

valid_authorization_host() {
  local host=$1
  case "$host" in
    https://api.palladin.io|https://api.stage.palladin.io) return 0 ;;
  esac
  [[ $PALLADIN_LOOPBACK_POLICY == development ]] && valid_loopback_host "$host"
}

validate_service_account() {
  local record name password account_uid gid _gecos _home shell shadow broker_gid
  record=$(getent passwd "$user") || fail_account 'the dedicated Agent account does not exist'
  IFS=: read -r name password account_uid gid _gecos _home shell <<< "$record"
  [[ $name == "$user" && $account_uid == "$uid" && $uid != 0 && $user != palladin-runtime ]] \
    || fail_account 'root and the broker account cannot be authorized as Agents'
  broker_gid=$(getent group palladin-runtime | cut -d: -f3)
  [[ $gid != "$broker_gid" ]] \
    || fail_account 'the Agent account cannot use the broker group as its primary group'
  [[ $user =~ ^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$ ]] \
    || fail_account 'the Agent account name is outside the hardened record format'
  case "$shell" in
    /usr/sbin/nologin|/sbin/nologin|/bin/false) ;;
    *) fail_account 'the Agent account must use a nologin shell' ;;
  esac
  shadow=$(getent shadow "$user") || fail_account 'the Agent account must have a locked password'
  password=${shadow#*:}
  password=${password%%:*}
  [[ $password == '!'* || $password == '*'* ]] \
    || fail_account 'the Agent account password must be locked'
}

uid_has_live_processes() {
  local status process_uid
  for status in /proc/[0-9]*/status; do
    [[ -r $status ]] || continue
    process_uid=$(sed -n 's/^Uid:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$status" 2>/dev/null) || continue
    [[ $process_uid == "$uid" ]] && return 0
  done
  return 1
}

has_runtime_membership() {
  local broker_gid
  broker_gid=$(getent group palladin-runtime | cut -d: -f3)
  id -G "$user" | tr ' ' '\n' | grep -Fxq "$broker_gid"
}

remove_runtime_membership() {
  if has_runtime_membership; then
    gpasswd -d "$user" palladin-runtime >/dev/null \
      || fail_account 'could not remove the Agent account from the broker access group'
  fi
  ! has_runtime_membership \
    || fail_account 'the Agent account still belongs to the broker access group'
}

restart_broker() {
  systemctl restart palladin-runtime.service
  for _ in $(seq 1 50); do
    if systemctl is-active --quiet palladin-runtime.service \
      && [[ -S /run/palladin-runtime/broker.sock ]]; then
      return 0
    fi
    sleep 0.1
  done
  fail_account 'the broker did not become ready after the authorization boundary changed'
}

stop_broker() {
  systemctl stop palladin-runtime.service
  ! systemctl is-active --quiet palladin-runtime.service \
    || fail_account 'the broker remained active during principal purge'
  [[ ! -S /run/palladin-runtime/broker.sock ]] \
    || fail_account 'the broker socket remained available during principal purge'
}

main() {
  case "$PALLADIN_LOOPBACK_POLICY" in
    production|development) ;;
    *) fail_account 'the installed origin policy is invalid; reinstall the Palladin runtime package' ;;
  esac

  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo 'Error: run this root-owned helper through pkexec or sudo' >&2
    exit 77
  fi

  exec 9>/run/lock/palladin-manage-agent-uid.lock
  flock -x 9

  action=${1:-}
  user=${2:-}
  [[ -n $action && -n $user ]] || usage
  uid=$(id -u -- "$user" 2>/dev/null) || fail_account 'the dedicated Agent account does not exist'
  mapping=/etc/palladin/agents.d/$uid

  case "$action" in
  authorize)
    [[ $# -eq 5 && $5 == --dedicated ]] || usage
    profile=$3
    host=$4
    [[ $profile =~ ^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$ ]] \
      || fail_account 'profile must contain only letters, digits, underscore, and hyphen'
    valid_authorization_host "$host" \
      || fail_account 'host must be the exact Palladin production/staging origin; loopback requires an explicitly development-labelled package'
    validate_service_account
    ! uid_has_live_processes \
      || fail_account 'the Agent UID still has live processes; stop them before authorization or UID reuse'
    ! has_runtime_membership \
      || fail_account 'the Agent account already belongs to the broker access group'
    if [[ -e $mapping ]]; then
      [[ -f $mapping && ! -L $mapping ]] || fail_account 'the existing Agent principal record is invalid'
      if grep -Fxq 'status=active' "$mapping"; then
        fail_account 'this UID is already active; revoke it before creating a new principal'
      fi
      grep -Fxq 'status=revoked' "$mapping" \
        || fail_account 'the existing Agent principal record is invalid'
    fi
    principal=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    [[ $principal =~ ^[0-9a-f]{32}$ ]] || fail_account 'could not generate an immutable principal ID'
    temporary=$(mktemp /etc/palladin/agents.d/.agent.XXXXXX)
    group_added=false
    cleanup_authorize() {
      rm -f "$temporary"
      if [[ $group_added == true ]]; then
        gpasswd -d "$user" palladin-runtime >/dev/null 2>&1 || true
      fi
    }
    trap cleanup_authorize EXIT
    printf 'version=1\nstatus=active\nuid=%s\naccount=%s\nprincipal=%s\nprofile=%s\nhost=%s\n' \
      "$uid" "$user" "$principal" "$profile" "$host" > "$temporary"
    chown root:root "$temporary"
    chmod 0644 "$temporary"
    usermod -a -G palladin-runtime "$user"
    group_added=true
    has_runtime_membership \
      || fail_account 'could not add the Agent account to the broker access group'
    ! uid_has_live_processes \
      || fail_account 'the Agent UID started a process during authorization; authorization was rolled back'
    validate_service_account
    [[ $(id -u -- "$user") == "$uid" ]] \
      || fail_account 'the Agent UID changed during authorization'
    # Restart while the old missing/revoked mapping still fails closed. Only
    # publish active authorization after every fallible readiness check passes.
    restart_broker
    has_runtime_membership \
      || fail_account 'the Agent account lost broker access during authorization'
    ! uid_has_live_processes \
      || fail_account 'the Agent UID started a process during authorization; authorization was rolled back'
    validate_service_account
    [[ $(id -u -- "$user") == "$uid" ]] \
      || fail_account 'the Agent UID changed during authorization'
    mv -T "$temporary" "$mapping"
    group_added=false
    trap - EXIT
    ;;
  revoke|revoke-purge)
    if [[ $action == revoke ]]; then
      [[ $# -eq 2 ]] || usage
    else
      [[ $# -eq 3 && $3 == --confirm-purge ]] || usage
    fi
    [[ -f $mapping && ! -L $mapping ]] || fail_account 'the active Agent principal record is missing'
    mapfile -t record < "$mapping"
    [[ ${#record[@]} -eq 7 \
      && ${record[0]} == version=1 \
      && ${record[1]} =~ ^status=(active|revoked)$ \
      && ${record[2]} == "uid=$uid" \
      && ${record[3]} == "account=$user" \
      && ${record[4]} =~ ^principal=[0-9a-f]{32}$ \
      && ${record[5]} =~ ^profile=[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$ \
      && ${record[6]} == host=* ]] || fail_account 'the active Agent principal record is invalid'
    valid_record_host "${record[6]#host=}" || fail_account 'the active Agent principal host is invalid'
    if [[ ${record[1]} == status=active ]]; then
      temporary=$(mktemp /etc/palladin/agents.d/.agent.XXXXXX)
      trap 'rm -f "$temporary"' EXIT
      record[1]=status=revoked
      printf '%s\n' "${record[@]}" > "$temporary"
      chown root:root "$temporary"
      chmod 0644 "$temporary"
      mv -T "$temporary" "$mapping"
      trap - EXIT
    elif [[ $action == revoke ]]; then
      fail_account 'the Agent principal is already revoked'
    fi
    if [[ $action == revoke-purge ]]; then
      # Keep the broker stopped while root inspects and deletes its state tree.
      # This closes authenticated sessions and prevents a broker write from
      # racing the fail-closed filesystem preflight.
      stop_broker
      trap 'systemctl start palladin-runtime.service >/dev/null 2>&1 || true' EXIT
      remove_runtime_membership
      principal=${record[4]#principal=}
      /usr/lib/palladin/runtime/palladin-linux-admin-purge \
        "$principal" --confirm-purge \
        || fail_account 'the revoked Agent principal state could not be purged'
      grep -Fxq 'status=revoked' "$mapping" \
        || fail_account 'the durable UID-reuse tombstone was not preserved'
      restart_broker
      trap - EXIT
    else
      # Kill sessions authenticated under the active record before changing
      # the supplementary group metadata.
      restart_broker
      remove_runtime_membership
    fi
    ;;
    *) usage ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
