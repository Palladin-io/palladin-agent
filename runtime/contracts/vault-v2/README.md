# Vault protocol 2 fixtures

This directory is a byte-identical vendored copy of the canonical synthetic
fixtures from the private Palladin architecture repository. `fixtures/v2/SOURCE`
pins the source repository commit and manifest digest.

Do not edit expected bytes here. A protocol fixture update requires an explicit
protocol-version decision in the root repository, followed by replacing the
complete fixture set and updating the pin. Rust integration tests verify every
manifest file digest and never print private fixture fields.
