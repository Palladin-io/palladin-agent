# Secure-storage boundary spike

Native negative tests for CVT-301. Every payload is synthetic and the scripts print only pass/fail metadata.

## What the tests prove

| Platform | Convenience result | Hardened candidate |
|---|---|---|
| macOS | Login Keychain blocks a different binary's non-interactive direct read, but the authorized executable remains an oracle; Data Protection Keychain rejects an unprovisioned CLI | Trusted signed bundle plus provisioned app-scoped Keychain access group and negative oracle tests; not claimable until the signed test passes |
| Windows | DPAPI `CurrentUser` ciphertext is decryptable by another process under the same Windows user | AppContainer/MSIX or service-SID broker; DPAPI alone is Convenience |
| Linux | `0600` protects from other UIDs, not another process under the same UID | Dedicated runtime UID/container/system boundary; Secret Service under the same UID is not sufficient |

The macOS test uses `Security.framework` and `kSecUseDataProtectionKeychain`. The Windows test uses native DPAPI. The Linux test exercises the kernel UID/file-permission boundary. These are native host tests, not storage mocks.

## Run

```bash
./spikes/secure-storage/macos/run.sh
pwsh -File spikes/secure-storage/windows/dpapi-spike.ps1
./spikes/secure-storage/linux/uid-boundary-spike.sh
```

The scripts exit successfully when the observed result matches the documented platform boundary. A result named `NOT_ISOLATED` is an expected negative finding, not a passing Hardened guarantee.

## macOS signed access-group follow-up

The local development machine has no Apple Development/Developer ID identity or provisioning profile. The native test proves that the ordinary Login Keychain blocks a different binary's unattended direct query (the process is denied or stalls awaiting explicit Keychain approval), while the authorized executable can still read the item and would become an oracle if it exposed a raw-read operation. Data Protection Keychain refuses the unprovisioned CLI with `errSecMissingEntitlement`; attempting to self-assert the application identifier is rejected by macOS `taskgated`. This spike deliberately has no pretend real-signing path. CVT-317 must build the provisioned harness and reject differently entitled, forged-group and oracle attacker variants on native arm64 and x64 hosts.
