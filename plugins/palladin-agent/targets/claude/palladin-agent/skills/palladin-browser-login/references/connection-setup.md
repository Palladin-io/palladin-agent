# Agent assignment and browser pairing

Follow https://palladin.io/agents/setup.md as the canonical CLI discovery,
installation and pairing procedure. Preserve the user-provided profile and API
host; if the CLI is missing and no supported release is available, stop. The host-specific
MCP configuration and memory rules below supplement that procedure.

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

For MCP, launch one `palladin mcp serve` process without `--id`. Pass the
user-selected alias as required `profile` in `pair_agent` and every subsequent
tool call. Pairing uses the server's configured `--host <api-host>` (production
by default); verify it matches the separately confirmed environment before
pairing. Existing profiles always use their own saved API host for operations.
Pass the descriptor if provided, and `type: "openclaw"` for a new OpenClaw Agent
when it does not conflict with that descriptor. Do not re-pair an existing profile
just because a tool call fails.

For a CLI adapter, follow the canonical setup procedure linked above using the
user's exact pairing command. Use `openclaw` as the runtime type for OpenClaw
unless it conflicts with supplied descriptor metadata. Do not invent installation
commands or fall back to API-key-based `connect`.

For an existing MCP assignment, send the remembered alias as `profile` on every
call. Keep it unchanged across Search, Inject and approval retries. The server
has no mutable active profile and never falls back to the machine's default.
Missing or invalid `profile` is an argument error; an unknown profile must be
resolved with the user rather than silently substituted or created.

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
