# OpenClaw local Palladin launcher

Set the OpenClaw command to the absolute path of `scripts/palladin-openclaw`:

```text
/Users/patryk/Repository/claw-vault/.worktrees/node-agent-browser-bridge/scripts/palladin-openclaw
```

The wrapper selects this checkout and exports `PALLADIN_AGENT_PACKAGE_ROOT` and
`PALLADIN_AGENT_LAUNCHER`. It does not disable runtime signature, artifact hash,
origin, or grant validation. For browser injection, OpenClaw must use the private
provider-stdio handshake and keep ownership of the existing Playwright page.
