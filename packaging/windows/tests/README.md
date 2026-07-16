# Windows signed-runtime adversarial evidence

The signed GitHub workflow runs hosted smoke probes on native x64 and ARM64. It
proves the fresh Windows Hello consent denial and exact dispatcher rejection of a
modified client. Named-pipe denial is recorded only when the attacker receives
`ACCESS_DENIED`; a missing or unavailable pipe is an explicit hosted limitation.
The workflow also checks known legacy Credential Manager target names without
dereferencing a credential blob.

GitHub-hosted runners do not provide a provisioned Palladin identity and may use
an elevated token. A missing broker-owned ProgramData profile and an elevated or
partial process probe therefore emit `evidence-status: incomplete-hosted-*`.
They never count as successful process or protected-profile evidence. The hosted
artifact gate writes the missing dedicated-hardware cells to the job summary;
those manual release-report cells remain mandatory before production release.

No probe seeds an identity, adds a broker test identity, enables a runtime test
backdoor, reads raw process memory, or creates a process dump. The process probe
only requests the access rights required for VM reads, handle duplication,
debugger attachment, and full-memory dumps. Every secret-process denial must be
the exact Win32 `ERROR_ACCESS_DENIED` value. A public signed client is the positive
control only for obtaining a `VM_READ` process handle.

## Dedicated physical hardware

Run both the foreign-Node probe and unsigned native probe as a normal,
non-elevated user on dedicated physical Windows 11 x64 and ARM64 devices. Before
dropping elevation, a trusted administrator must confirm that:

- the exact per-user `ProgramData\Palladin\Runtime\v1\<SID>` profile exists;
- the named pipe belongs to the running `PalladinRuntime` LocalService service;
- `service`, `companion`, and `worker` PIDs are live and their image signatures
  match the protected Palladin publisher and thumbprint.

Pass `present` as the final foreign-Node argument only after that trusted profile
preflight. `dedicated-hardware` mode rejects a missing profile, a missing or
unavailable pipe, and every error class other than access denial.

Invoke `Palladin.AdversarialProbe.exe` with `--mode dedicated-hardware`, the signed
public client path, and all three live targets:

```text
Palladin.AdversarialProbe.exe --mode dedicated-hardware --client <signed-client> \
  --target service:<pid> --target companion:<pid> --target worker:<pid>
```

The probe independently keeps a query handle open to prevent PID reuse, verifies
that every target is still active, checks the exact role-specific executable path
under the expected protected MSIX package, and checks LocalService/AppContainer
token identity. It fails for a stale, unrelated, incorrectly packaged, or
incorrectly tokened PID. Creation of a new identity and the positive Windows
Hello prompt remain dedicated-hardware evidence and are never claimed by hosted
CI.
