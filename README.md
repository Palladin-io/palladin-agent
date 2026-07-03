# @palladin/agent

CLI + MCP server for Palladin. Manages agent identity (X25519 keypair), authenticates with the backend, and exposes vault tools to AI assistants.

## Prerequisites

- Node.js ≥ 20
- Running Palladin backend (`dotnet run` or staging URL)
- An API key generated in the Palladin panel (`pl_...`)

## Setup

### 1. Build

```bash
npm install
npm run build
```

Link globally to get the `palladin` command:

```bash
npm link
```

### 2. Generate keypair

```bash
palladin init
```

Creates `~/.palladin/agent.key` (private, chmod 600) and `agent.pub`.

### 3. Connect to server

```bash
palladin connect pl_YOUR_API_KEY --host http://localhost:5000
```

Registers the agent with the server. The agent appears as **Pending** in the panel immediately.

### 4. Approve in panel

Open the Palladin web panel → Agents → approve the agent. Status changes to **Active**.

### 5. Verify

```bash
palladin status
```

Expected output when active:

```
Keypair:  ✓ ~/.palladin/agent.key
Config:   ✓ ~/.palladin/config.json
Host:     http://localhost:5000
Key:      <base64 public key>

Agent:    ✓ active
          ID:   <agent-id>
```

## Commands

| Command | Description |
|---------|-------------|
| `palladin init` | Generate X25519 keypair. Use `--force` to overwrite. |
| `palladin connect <api-key> --host <host>` | Save config and register agent with server. |
| `palladin status` | Show keypair, config, and live agent status from server. |
| `palladin list` | List accessible vaults. |
| `palladin get <vault>/<entry>` | Fetch a credential. |
| `palladin mcp serve` | Start MCP server (for AI assistant integration). |

## MCP server

### Claude Desktop

Edit the config file for your platform:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "palladin": {
      "command": "palladin",
      "args": ["mcp", "serve"]
    }
  }
}
```

Restart Claude Desktop. The agent must be **Active** before tools work.

### Cursor / other MCP clients

```json
{
  "mcpServers": {
    "palladin": {
      "command": "palladin",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Without npm link (dev mode)

```json
{
  "mcpServers": {
    "palladin": {
      "command": "node",
      "args": ["/absolute/path/to/agent/dist/bin/palladin.js", "mcp", "serve"]
    }
  }
}
```

## Available MCP tools

| Tool | Description |
|------|-------------|
| `list_vaults` | List all vaults accessible to this agent |
| `list_entries` | List entries in a vault (requires `vaultId`) |

## Security notes

- **HTTPS only.** `connect --host` (and every request) rejects `http://` to a remote host — the API key is a bearer secret and must never travel in cleartext. `http://` is allowed only for loopback hosts (`localhost`, `127.0.0.1`, `::1`) for local development; use `https://` everywhere else.
- **`exec_with_credential` withholds command output.** The secret is injected into the child's environment, but the command's stdout/stderr are **not** returned to the model — a prompt-injected agent could make the command re-encode the secret (base64/hex/reverse) to defeat any output filter. The model receives only the exit code and a note; the human operator sees the output on the terminal (CLI) or the server's stderr (MCP), and a best-effort masked tail is written to `~/.palladin/exec-logs/` (opt out with `PALLADIN_NO_DIAGNOSTICS=1`). Judge success from the exit code.
- **`inject` field-readback is an inherent limitation.** Because the agent controls its own browser, after the CLI types the password it can read the field's value back with its own JavaScript. This cannot be removed without taking browser control away from the agent, and it is not a regression: the origin/domain binding remains a solid control (the secret only ever reaches the real bound domain, never a phishing page), and `inject` protects against accidental leakage into a hosted-LLM context — not against a malicious agent that already holds the secret it is logging in with.
- **Config/key files are private.** The Palladin home and its subdirectories are created with mode `0700`; key/config files with mode `0600`.

## Config files

| File | Contents |
|------|----------|
| `~/.palladin/agent.key` | X25519 private key (base64, chmod 600) |
| `~/.palladin/agent.pub` | X25519 public key (base64) |
| `~/.palladin/config.json` | `{ "apiKey": "pl_...", "host": "https://..." }` |

Override the default directory with `PALLADIN_HOME=/custom/path`.

## Windows notes

- File permissions: `icacls` is used to restrict `agent.key` to the current user only. If `icacls` fails, a warning is printed — protect the file manually.
- PowerShell / cmd both work for running `palladin` commands after `npm link`.
- Line endings: no issues — all files are written as UTF-8 text.

## Development

```bash
npm run build       # compile TypeScript → dist/
npm run dev         # watch mode
npm run lint        # type-check only (no emit)
```
