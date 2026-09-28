# Agent assignment and browser pairing

## Resolve the assignment

Check the host's trusted agent/workspace memory for a confirmed Palladin profile
alias, API host and credential-surface connection reference. Memory identifies a
connection; it is not authentication. Validate the selected runtime connection
before using it. Do not read native profile files or secret storage yourself.

If no assignment exists, ask whether to use an existing Agent or pair a new one.
With CLI access, `palladin agents list` lists aliases and
`palladin --id <selected-alias> status` verifies the chosen connection. Listing
is read-only; do not choose the first result or a global default without the
user's selection. Without local CLI access, ask for the intended configured MCP
connection or new-Agent setup. Do not invent an MCP profile-list/status tool.

An invalid or inactive saved assignment is not permission to recreate it. Report
the status and ask whether to repair/select another connection or pair anew.
Preserve other profiles and the global default.

## Pair a new Agent

Ask for the intended environment/API host and local alias (where the host can
configure one), or the value-free `PALLADIN_AGENT_SETUP_V1` descriptor from
Palladin Add Agent. The descriptor carries setup metadata, not API-host authority:
confirm the target environment separately. Never request an API key, password,
private key, session token or mnemonic in chat, argv or environment variables.

For MCP, configure the host-managed server connection to the selected alias and
host using argument values `--id <alias> mcp serve --host <api-host>`, then restart
that connection through the host's supported mechanism before calling `pair_agent`.
The tool pairs the profile selected when that MCP process started; a tool argument
cannot switch its alias or host. Pass the descriptor if provided, and `type:
"openclaw"` for a new OpenClaw Agent when it does not conflict with that descriptor.
If the host cannot change the connection, explain the exact required setup instead
of pairing the currently running default or another user's Agent.

For a CLI adapter, use the installed supported `palladin` executable:

```text
palladin --id <new-alias> pair-agent --host <api-host> --type <agent-type>
```

Use `openclaw` as the type for OpenClaw, or the actual host type for another adapter.
Add `--setup-descriptor <descriptor>` when supplied; do not override its metadata
with conflicting declarations. Let the native runtime create the new profile and
open browser pairing. User approval happens in Palladin. Wait for confirmed active
status; cancellation, denial or pending approval is not success. Never silently
use `connect` with an API key as fallback.

For an existing MCP assignment, pin the confirmed alias in the host connection
configuration before Search/Inject. A manifest's generic launch command is a
bootstrap, not a remembered account assignment. If a host supports multiple named
MCP connections, retain the selected connection reference as well as its alias/host.

## Remember only the confirmed connection

After successful pairing or existing-profile status verification, write to the
host's normal agent/workspace memory: local alias, exact API host, credential
surface and connection reference, plus confirmed display name/type when available.
Do not save secret material, pairing descriptors, approval URLs, tab IDs, grants or
site passwords. Reuse this assignment on later requests without asking again;
verify it belongs to the same configured runtime. Changes require the user's choice.

Use release defaults. Do not hardcode an owner's alias, workstation path, staging
host, `--local-development` or experimental live-form environment flags. An explicit
development installation is separate local configuration, not a production default.
