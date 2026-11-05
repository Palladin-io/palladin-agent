# Federated sign-in v2 consumer fixtures

`contract.json` and `fixtures.json` are copied from
`palladin-protocol/contracts/federated-signin/v2`. Runtime discovery tests consume
all positive and negative vectors. Refresh both files together when that public
contract changes.

Credential `signInMethods` is an account-free collection of stable custom-field
IDs, providers and optional Entry references. Preserve UUID hex spelling in IDs;
require case-sensitive ordinal ordering and uniqueness. Provider reference UUIDs
remain lowercase. Malformed or unknown versions fail closed without falling
back to a competing legacy singleton. References do not convey grants.
