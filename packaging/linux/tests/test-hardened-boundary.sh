#!/usr/bin/env bash
set -euo pipefail

[[ $(uname -s) == Linux && $(id -u) -eq 0 ]] || {
  echo 'Error: run on a privileged native Linux test host' >&2
  exit 64
}
root=$(mktemp -d /var/tmp/palladin-boundary.XXXXXX)
agent=palladin-boundary-agent
attacker=palladin-boundary-attacker
login_user=palladin-boundary-login
stale_pid=
cleanup() {
  systemctl unset-environment LD_PRELOAD >/dev/null 2>&1 || true
  rm -f /run/palladin-runtime/ld-preload-hit
  [[ -z $stale_pid ]] || kill "$stale_pid" >/dev/null 2>&1 || true
  userdel "$agent" >/dev/null 2>&1 || true
  userdel "$attacker" >/dev/null 2>&1 || true
  userdel --remove "$login_user" >/dev/null 2>&1 || true
  rm -rf "$root"
}
trap cleanup EXIT

/usr/lib/palladin/runtime/verify-installation
useradd --system --no-create-home --shell /usr/sbin/nologin "$agent"
useradd --system --no-create-home --shell /usr/sbin/nologin "$attacker"
useradd --create-home --shell /bin/bash "$login_user"
if /usr/lib/palladin/runtime/palladin-manage-agent-uid \
  authorize "$login_user" login-agent http://127.0.0.1:5000 --dedicated; then
  echo 'Error: a login-capable desktop account was authorized as Hardened' >&2
  exit 1
fi
echo 'login-capable-account=denied'
/usr/lib/palladin/runtime/palladin-manage-agent-uid \
  authorize "$agent" boundary-agent http://127.0.0.1:5000 --dedicated
usermod -a -G palladin-runtime "$attacker"

for user in "$agent" "$attacker"; do
  if id -G "$user" | tr ' ' '\n' | grep -Fxq "$(getent group palladin-executor | cut -d: -f3)"; then
    echo "Error: $user inherited the broker-only executor group" >&2
    exit 1
  fi
  if runuser -u "$user" -- python3 -c \
    "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/palladin-executor/executor.sock')"; then
    echo "Error: $user connected directly to the broker-only executor socket" >&2
    exit 1
  fi
done
echo 'executor-socket=broker-group-only agent-connect=denied attacker-connect=denied'

python3 <<'PY'
import socket

s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect('/run/palladin-executor/executor.sock')
assert s.recv(1) == b'', 'executor accepted root instead of the installed broker UID'
PY
echo 'executor-peer=root-rejected-by-so-peercred'

broker_uid=$(id -u palladin-runtime)
broker_gid=$(id -g palladin-runtime)
executor_gid=$(getent group palladin-executor | cut -d: -f3)
setpriv --reuid "$broker_uid" --regid "$broker_gid" --groups "$executor_gid" -- python3 <<'PY'
import json, socket, struct

def recv_exact(stream, length):
    chunks = []
    while length:
        chunk = stream.recv(length)
        assert chunk, 'executor closed the broker connection before its response'
        chunks.append(chunk)
        length -= len(chunk)
    return b''.join(chunks)

payload = json.dumps({
    'version': 2,
    'request': {
        'kind': 'command',
        'command': ['/usr/bin/true'],
        'environment': [],
    },
}, separators=(',', ':')).encode()
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect('/run/palladin-executor/executor.sock')
s.sendall(struct.pack('>I', len(payload)) + payload)
length = struct.unpack('>I', recv_exact(s, 4))[0]
frame = json.loads(recv_exact(s, length))
assert frame == {'type': 'exited', 'code': 0}, frame
PY
echo 'executor-peer=broker-uid-accepted'

attacker_uid=$(id -u "$attacker")
python3 - "$attacker_uid" <<'PY'
import json, os, socket, struct, subprocess, sys
uid = int(sys.argv[1])
payload = json.dumps({
    "type": "start", "version": 2, "request_id": [1] * 16,
    "arguments": ["doctor"], "interactive": False,
}, separators=(",", ":")).encode()
code = subprocess.run([
    "runuser", "-u", "palladin-boundary-attacker", "--", "python3", "-c",
    "import socket,struct,sys; s=socket.socket(socket.AF_UNIX); s.connect('/run/palladin-runtime/broker.sock'); p=sys.stdin.buffer.read(); s.sendall(struct.pack('>I',len(p))+p); n=struct.unpack('>I',s.recv(4))[0]; print(s.recv(n).decode())"
], input=payload, capture_output=True, check=True).stdout.decode()
result = json.loads(code)
assert result["type"] == "rejected" and result["code"] == "unauthorized-peer", result
PY
echo 'peer-identity=dedicated-uid-mapping forged-group-peer=denied'

if runuser -u "$attacker" -- /usr/lib/palladin/runtime/palladin-linux-client doctor; then
  echo 'Error: the system client downgraded an unmapped UID to Convenience' >&2
  exit 1
fi
echo 'system-client-missing-mapping=fail-closed'

doctor=$(runuser -u "$agent" -- /usr/lib/palladin/runtime/palladin-linux-client doctor)
grep -F 'standalone-security-tier: Hardened' <<<"$doctor"
grep -F 'dedicated Agent UID' <<<"$doctor"

broker_pid=$(systemctl show -p MainPID --value palladin-runtime.service)
[[ $broker_pid =~ ^[1-9][0-9]*$ ]] || { echo 'Error: broker PID unavailable' >&2; exit 1; }
cc "$(dirname "$0")/security-boundary-probe.c" -o "$root/security-boundary-probe"
chmod 0755 "$root" "$root/security-boundary-probe"
runuser -u "$agent" -- "$root/security-boundary-probe" "$broker_pid"

cc -shared -fPIC "$(dirname "$0")/ld-preload-probe.c" -o "$root/preload.so"
chmod 0755 "$root/preload.so"
rm -f /run/palladin-runtime/ld-preload-hit
systemctl set-environment LD_PRELOAD="$root/preload.so"
systemctl restart palladin-runtime.service
[[ ! -e /run/palladin-runtime/ld-preload-hit ]] || {
  echo 'Error: systemd passed LD_PRELOAD into the secret-bearing broker' >&2
  exit 1
}
echo 'ld-preload=removed-before-broker-start'

principal=$(sed -n 's/^principal=//p' "/etc/palladin/agents.d/$(id -u "$agent")")
[[ $principal =~ ^[0-9a-f]{32}$ ]]
state=/var/lib/palladin-runtime/v1/agents/$principal
[[ $(stat -c '%U:%G:%a' "$state") == 'palladin-runtime:palladin-runtime:700' ]]
if runuser -u "$agent" -- env \
  PALLADIN_LINUX_HARDENED=1 \
  PALLADIN_LINUX_BROKER_ROOT="$state" \
  /usr/lib/palladin/runtime/palladin-worker doctor; then
  echo 'Error: the Agent UID forged a direct Hardened worker invocation' >&2
  exit 1
fi
if runuser -u "$agent" -- test -r /var/lib/palladin-runtime/v1/master.key; then
  echo 'Error: dedicated Agent UID read the broker master key' >&2
  exit 1
fi
echo 'state-permissions=broker-only direct-worker=denied agent-read=denied'

recycled_uid=$(id -u "$agent")
broker_access_gid=$(getent group palladin-runtime | cut -d: -f3)
stale_pid_file="$root/stale.pid"
install -o "$agent" -g "$(id -gn "$agent")" -m 0600 /dev/null "$stale_pid_file"
runuser -u "$agent" -- sh -c "echo \$\$ > '$stale_pid_file'; exec sleep 300" &
stale_launcher=$!
for _ in $(seq 1 50); do
  [[ -s $stale_pid_file ]] && break
  sleep 0.1
done
stale_pid=$(cat "$stale_pid_file")
[[ $stale_pid =~ ^[1-9][0-9]*$ && -d /proc/$stale_pid ]]
grep -Eq "^Groups:.*(^|[[:space:]])$broker_access_gid([[:space:]]|$)" "/proc/$stale_pid/status"

/usr/lib/palladin/runtime/palladin-manage-agent-uid revoke "$agent"
grep -Fxq 'status=revoked' "/etc/palladin/agents.d/$(id -u "$agent")"
if runuser -u "$agent" -- /usr/lib/palladin/runtime/palladin-linux-client doctor; then
  echo 'Error: a revoked dedicated UID downgraded to Convenience' >&2
  exit 1
fi
[[ -d $state ]] || { echo 'Error: revocation reused or deleted the principal tombstone state' >&2; exit 1; }
userdel --force "$agent"
useradd --system --uid "$recycled_uid" --no-create-home --shell /usr/sbin/nologin "$agent"
if /usr/lib/palladin/runtime/palladin-manage-agent-uid \
  authorize "$agent" recycled-agent http://127.0.0.1:5000 --dedicated; then
  echo 'Error: a live process survived revocation and crossed into a recycled UID principal' >&2
  exit 1
fi
kill "$stale_pid"
wait "$stale_launcher" 2>/dev/null || true
/usr/lib/palladin/runtime/palladin-manage-agent-uid \
  authorize "$agent" recycled-agent http://127.0.0.1:5000 --dedicated
recycled_principal=$(sed -n 's/^principal=//p' "/etc/palladin/agents.d/$recycled_uid")
[[ $recycled_principal =~ ^[0-9a-f]{32}$ && $recycled_principal != "$principal" ]]
runuser -u "$agent" -- /usr/lib/palladin/runtime/palladin-linux-client doctor \
  | grep -F 'standalone-security-tier: Hardened'
/usr/lib/palladin/runtime/palladin-manage-agent-uid revoke "$agent"
echo 'revoked-principal=tombstoned live-uid-reuse=denied new-principal=isolated'
