# Secure-storage boundary spike

Native negative tests for CVT-301. Every payload is synthetic and the scripts print only pass/fail metadata.

## What the tests prove

| Platform | Convenience result | Hardened candidate |
|---|---|---|
| macOS | Login Keychain blocks a different binary's non-interactive direct read, but the authorized executable remains an oracle; Data Protection Keychain rejects an unprovisioned CLI | Trusted signed bundle plus provisioned app-scoped Keychain access group and negative oracle tests; not claimable until the signed test passes |
| Windows | DPAPI `CurrentUser` ciphertext is decryptable by another process under the same Windows user | AppContainer/MSIX or service-SID broker; DPAPI alone is Convenience |
| Linux | `0600` protects from other UIDs, not another process under the same UID | Dedicated runtime UID/container/system boundary; Secret Service under the same UID is not sufficient |

The macOS test uses `Security.framework` and `kSecUseDataProtectionKeychain`. The Windows test uses native DPAPI. The Linux test exercises the kernel UID/file-permission boundary. These are native host tests, not storage mocks.

The default macOS run never launches a differently signed process against the user's Login Keychain. That ACL check can cause macOS to display a confirmation dialog naming the negative-test executable even when the query requests non-interactive behavior. It is therefore opt-in and must run only in a disposable macOS test account or an unattended CI runner:

```bash
PALLADIN_SPIKE_ALLOW_KEYCHAIN_UI_TEST=true ./spikes/secure-storage/macos/run.sh
```

Normal development and automated local test commands must leave this variable unset. Each run also uses a unique synthetic service name so it never queries a stale item from an earlier execution.

## Platform mechanism decision

The negative tests answer whether the simplest native store creates a process boundary. The comparison below records why the implementation tasks may or may not add another OS component.

### macOS

| Mechanism | Security boundary | Install/runtime cost | Decision |
|---|---|---|---|
| Login Keychain ACL | A second ad-hoc binary cannot read unattended, but an allowed runtime remains an oracle | Works with the standalone npm-delivered binary | Convenience only |
| Data Protection Keychain plus app-scoped access group and user presence | Access groups come from code-signing entitlements authorized by a provisioning profile; user presence can gate item use | Requires an app-like bundle, stable signing and a provisioned profile | Selected interactive Hardened candidate; blocked until CVT-317 runs the signed negative matrix |
| Background broker alone | Moves storage out of the CLI, but a callable same-user IPC service is still an oracle unless it authenticates code and/or user presence | Adds lifecycle, update and IPC complexity | Rejected for the first macOS implementation; reconsider only if the provisioned bundle cannot meet CVT-317 |

Apple documents that the Data Protection Keychain derives access groups from signed entitlements and requires a provisioning profile for a command-line tool wrapped in an app-like bundle: [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) and [distribution-signed macOS code](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/).

### Windows

| Mechanism | Security boundary | Install/runtime cost | Decision |
|---|---|---|---|
| DPAPI `CurrentUser` | Protects data for the Windows account, not from another process under that account; the native test decrypts successfully from the attacker process | No extra component | Convenience only |
| NCrypt/Windows Hello | Can make a signing key non-exportable and user-gesture protected, but does not store the organization bearer API key or provide Palladin's X25519 decryption operation; a callable signing/decryption API still needs an authorization boundary | Windows Hello provisioning and interactive PIN/biometric flow; unsuitable for unattended Agents | Rejected as the complete Agent Identity store; may later gate an interactive unwrap key |
| MSIX/AppContainer | Windows recognizes AppContainer as a process/resource boundary with a package SID and explicit capabilities | Requires package identity/capability work and constrains CLI filesystem/network integration | Valid fallback, not selected for the first CLI-compatible Hardened path |
| Restricted Windows service SID broker | A distinct per-service principal can exclusively own ACL-protected state and expose narrow IPC | Requires an optional installer, service lifecycle and authenticated bounded IPC | Selected Windows Hardened candidate for CVT-318; npm standalone remains Convenience |

Microsoft documents DPAPI as scoped to matching user logon credentials, not an executable: [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata). [Windows Hello](https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello) exposes non-exportable key operations tied to user verification. [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer) uses package/capability SIDs as an isolation boundary, while [per-service SIDs](https://learn.microsoft.com/en-us/sql/relational-databases/security/using-service-sids-to-grant-permissions-to-services-in-sql-server) grant resources to one service principal.

### Linux

| Mechanism | Security boundary | Install/runtime cost | Decision |
|---|---|---|---|
| User file mode `0600` or Secret Service | Protects against other UIDs, not another process with the Agent user's UID | No extra component | Convenience only |
| Root-owned/setgid helper or group-readable state | A helper remains a privileged oracle; group access extends to every process in that group | Requires privileged install and increases privileged attack surface | Rejected |
| PolKit authorization | Lets a privileged daemon ask whether a process/user may perform an action; it is policy and user authorization, not a storage principal | Requires daemon/policy/authentication-agent integration | Optional interactive gate only, not the storage boundary |
| systemd service with dedicated UID and owner-only state | Kernel UID/DAC boundary; native positive/negative test passes | Requires optional system package and service lifecycle | Selected Linux Hardened host path for CVT-319/CVT-320 |
| Dedicated Agent container/VM | Separate process/user namespace and deployment trust boundary when configured without host secret exposure | Requires container/VM deployment | Selected Hardened alternative for headless Agents |

PolKit is designed for privileged daemons or setuid helpers to authorize requests from untrusted clients, so it cannot replace the daemon/UID boundary: [PolKit authority](https://polkit.pages.freedesktop.org/polkit/PolkitAuthority.html). The kernel test therefore selects a distinct UID; systemd can synthesize service users through `DynamicUser=` as documented by [systemd user records](https://www.freedesktop.org/software/systemd/man/devel/userdbctl.html).

These choices do not alter Palladin authentication. The API key remains organization-scoped and may be shared by multiple Agents. Each runtime profile stores that shared value together with only that Agent's X25519/Ed25519 private keys; Node receives none of them.

## Run

```bash
./spikes/secure-storage/macos/run.sh
pwsh -File spikes/secure-storage/windows/dpapi-spike.ps1
./spikes/secure-storage/linux/uid-boundary-spike.sh
```

The scripts exit successfully when the observed result matches the documented platform boundary. A result named `NOT_ISOLATED` is an expected negative finding, not a passing Hardened guarantee.

## macOS signed access-group follow-up

The local development machine has no Apple Development/Developer ID identity or provisioning profile. The native test proves that the ordinary Login Keychain blocks a different binary's unattended direct query (the process is denied or stalls awaiting explicit Keychain approval), while the authorized executable can still read the item and would become an oracle if it exposed a raw-read operation. Data Protection Keychain refuses the unprovisioned CLI with `errSecMissingEntitlement`; attempting to self-assert the application identifier is rejected by macOS `taskgated`. This spike deliberately has no pretend real-signing path. CVT-317 must build the provisioned harness and reject differently entitled, forged-group and oracle attacker variants on native arm64 and x64 hosts.
