# Linux runtime tiers

Palladin supports two explicit Linux glibc tiers on x64 and arm64. The Hardened
system package requires systemd 252 or newer: Debian 12+, Ubuntu 24.04+,
Fedora, and RHEL/Rocky/AlmaLinux 9+. RHEL 8 and Ubuntu 22.04 are not supported
by this boundary.

| Tier | Installation | Trust boundary |
|---|---|---|
| Convenience | `npm install -g @palladin/agent` | Linux Secret Service protects data at rest. Another process under the same UID is inside the trust domain. PolKit does not turn this into process isolation. |
| Hardened headless | Install the signed `palladin-runtime` DEB or RPM, then authorize one dedicated OS account per Agent | A dedicated Agent UID reaches a broker under `palladin-runtime` through `SO_PEERCRED`. A root-owned record binds the UID and account to one immutable random principal namespace, fixed profile, and approved API origin. Secret-bearing state is broker-only. Credential execution runs through a broker-only socket and a one-shot systemd service with a fresh `DynamicUser` UID. |

The system package is optional and is never installed by an npm lifecycle hook. A dedicated or revoked Agent UID never falls back to Secret Service, a file, an environment variable, or the npm Convenience worker when the broker installation is incomplete. Revocation preserves a root-owned tombstone. Reauthorization is refused while any process with the numeric UID remains alive, and successful UID reuse creates a new random principal namespace instead of reopening old state.

Linux Hardened protects against ordinary processes under other UIDs. It does not protect against root, the kernel, disk-offline attacks without full-disk encryption, or malicious code deliberately run inside the dedicated Agent UID. The complete dedicated UID or container is the trust domain.

## Build packages

Build the four glibc binaries for the native target and stage the CLI as `palladin-worker`:

```bash
cd runtime
cargo build --release --locked \
  -p palladin-cli -p palladin-linux-broker -p palladin-linux-executor --bins
cp target/release/palladin target/release/palladin-worker
cd ..
packaging/linux/deb/build-deb.sh \
  --version 0.1.0 --architecture x64 --binaries runtime/target/release --output artifacts
packaging/linux/rpm/build-rpm.sh \
  --version 0.1.0 --architecture x64 --binaries runtime/target/release --output artifacts
```

Use `arm64` on a native arm64 builder. QEMU user-mode is sufficient for a build smoke test, but is not accepted as proof for UID, systemd, `/proc`, or ptrace isolation.

The protected production build accepts only the exact Palladin production and staging HTTPS origins. While the project is local-only, build `palladin-cli` with `--features local-development`; that build additionally accepts literal `127.0.0.1` or `[::1]` HTTP with an explicit port. Never enable that feature in a production candidate.

## Install and authorize a headless Agent

```bash
sudo apt install ./artifacts/palladin-runtime_0.1.0_amd64.deb
# or: sudo dnf install ./artifacts/palladin-runtime-0.1.0-1.x86_64.rpm

sudo useradd --system --create-home --shell /usr/sbin/nologin palladin-agent-prod
pkexec /usr/lib/palladin/runtime/palladin-manage-agent-uid \
  authorize palladin-agent-prod production https://api.stage.palladin.io --dedicated
sudo -u palladin-agent-prod /usr/lib/palladin/runtime/palladin-linux-client init
sudo -u palladin-agent-prod /usr/lib/palladin/runtime/palladin-linux-client connect
sudo -u palladin-agent-prod sh -c \
  'umask 077; read -r api_key; printf "%s" "$api_key" | /usr/lib/palladin/runtime/palladin-linux-client connect --api-key-stdin'
```

The first `connect` form uses a masked prompt in the trusted native system client. The second is the headless pipe form. Do not place the API key in argv, an environment variable, a unit file, or a shell history. For unattended provisioning, deliver it once through a root-controlled systemd credential or an anonymous pipe and remove the source immediately.

`authorize` refuses login-capable or password-enabled accounts and requires the explicit `--dedicated` acknowledgement. In Hardened mode, profile creation, rename, deletion, default switching, force-init, and purge are blocked because they could rebind the root-owned principal. Revoke through the administrative helper before replacing an Agent account.

Run the MCP server under the same dedicated UID:

```ini
[Service]
User=palladin-agent-prod
ExecStart=/usr/lib/palladin/runtime/palladin-linux-client mcp serve
StandardInput=socket
StandardOutput=socket
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
```

## Container and CI runbook

The Hardened boundary requires a real systemd instance and distinct kernel UIDs. A plain application container without systemd is unsupported and fails closed. Use a dedicated VM for the release gate. A privileged systemd container is useful only as a package integration test:

```bash
podman run --rm --privileged --systemd=always \
  -v "$PWD/artifacts:/artifacts:ro" ubuntu:24.04 /sbin/init
podman run --rm --privileged --systemd=always \
  -v "$PWD/artifacts:/artifacts:ro" fedora:42 /sbin/init
```

For each supported Debian/Ubuntu, Fedora, and RHEL 9-family image on native x64 and arm64:

1. Install the DEB or RPM and run `verify-installation`.
2. Create one authorized Agent UID and one unauthorized UID.
3. Run `tests/test-convenience-boundary.sh` as an ordinary user.
4. Set `kernel.yama.ptrace_scope=0`, drop `CAP_SYS_PTRACE`, and run `tests/test-hardened-boundary.sh` as root.
5. Verify encrypted Agent identity round-trips across update, rollback, uninstall, and reinstall. Before the first production release, the base and upgrade packages exercise packaging compatibility from the initial schema. After the first release, the base package must be the frozen previously published artifact.
6. Revoke the principal, recycle the numeric UID, remove the socket, and corrupt one permission at a time; confirm every designated or tombstoned principal receives an error without a Convenience fallback.

Use a dedicated container per Agent when the workload platform already provides an immutable image and unique UID. Never share the Agent UID with unrelated Node applications.
