# Palladin Playwright MCP provider (disabled fixture)

This unshipped package is retained only for non-secret build and contract fixtures. Its historical
private-pipe adapter invokes `--provider-transport-stdio`; the Rust CLI rejects that flag in every
build before profile, grant, runtime session, or credential access. There is no `local-development`
exception and this package must not be configured or published as an Inject provider.

The pipe cannot authenticate the receiving provider process. Enabling Playwright Inject requires a
separately reviewed one-shot authenticated capability; a hidden flag, nonce, owner-only pipe, CDP
endpoint, or Playwright WebSocket endpoint is not sufficient. The only code-enabled browser Inject
direction is the authenticated macOS Chrome extension route documented in the root runtime README.
