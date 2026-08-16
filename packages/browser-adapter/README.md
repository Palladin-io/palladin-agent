# Palladin browser adapter contract (disabled fixture)

This unshipped package records an earlier embedded-provider design and remains only for non-secret
contract tests. Its `--provider-transport-stdio` path is unauthenticated and the Rust CLI rejects it
in every build before profile, grant, runtime session, or credential access. It is not a supported
Playwright, Agent Browser, Claude Browser, Codex Browser, or OpenClaw integration.

Future non-extension providers require a separately reviewed authenticated one-shot transport and
atomic element-bound fill primitive. Raw CDP endpoints, remote-debugging ports, Playwright WebSocket
endpoints, private plaintext pipes, owner-only sockets, and hidden flags are not authentication
boundaries. The code-enabled route is the macOS Chrome extension provider; AgentBrowser Inject and
these historical wrappers remain fail-closed.
