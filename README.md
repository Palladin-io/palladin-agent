# @claw-vault/agent

CLI + MCP server for Claw Vault. Manages agent identity (X25519 keypair), authenticates with the backend, and exposes vault tools to AI assistants.

## Prerequisites

- Node.js ≥ 20
- Running Claw Vault backend (`dotnet run` or staging URL)
- An API key generated in the Claw Vault panel (`cv_...`)

## Setup

### 1. Build

```bash
npm install
npm run build
```

Link globally to get the `claw-vault` command:

```bash
npm link
```

### 2. Generate keypair

```bash
claw-vault init
```

Creates `~/.claw-vault/agent.key` (private, chmod 600) and `agent.pub`.

### 3. Connect to server

```bash
claw-vault connect cv_YOUR_API_KEY --host http://localhost:5000
```

Registers the agent with the server. The agent appears as **Pending** in the panel immediately.

### 4. Approve in panel

Open the Claw Vault web panel → Agents → approve the agent. Status changes to **Active**.

### 5. Verify

```bash
claw-vault status
```

Expected output when active:

```
Keypair:  ✓ ~/.claw-vault/agent.key
Config:   ✓ ~/.claw-vault/config.json
Host:     http://localhost:5000
Key:      <base64 public key>

Agent:    ✓ active
          ID:   <agent-id>
```

## Commands

| Command | Description |
|---------|-------------|
| `claw-vault init` | Generate X25519 keypair. Use `--force` to overwrite. |
| `claw-vault connect <api-key> --host <host>` | Save config and register agent with server. |
| `claw-vault status` | Show keypair, config, and live agent status from server. |
| `claw-vault list` | List accessible vaults. |
| `claw-vault get <vault>/<entry>` | Fetch a credential. |
| `claw-vault mcp serve` | Start MCP server (for AI assistant integration). |

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
    "claw-vault": {
      "command": "claw-vault",
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
    "claw-vault": {
      "command": "claw-vault",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Without npm link (dev mode)

```json
{
  "mcpServers": {
    "claw-vault": {
      "command": "node",
      "args": ["/absolute/path/to/agent/dist/bin/claw-vault.js", "mcp", "serve"]
    }
  }
}
```

## Available MCP tools

| Tool | Description |
|------|-------------|
| `list_vaults` | List all vaults accessible to this agent |
| `list_entries` | List entries in a vault (requires `vaultId`) |

## Config files

| File | Contents |
|------|----------|
| `~/.claw-vault/agent.key` | X25519 private key (base64, chmod 600) |
| `~/.claw-vault/agent.pub` | X25519 public key (base64) |
| `~/.claw-vault/config.json` | `{ "apiKey": "cv_...", "host": "https://..." }` |

Override the default directory with `CLAW_VAULT_HOME=/custom/path`.

## Windows notes

- File permissions: `icacls` is used to restrict `agent.key` to the current user only. If `icacls` fails, a warning is printed — protect the file manually.
- PowerShell / cmd both work for running `claw-vault` commands after `npm link`.
- Line endings: no issues — all files are written as UTF-8 text.

## Development

```bash
npm run build       # compile TypeScript → dist/
npm run dev         # watch mode
npm run lint        # type-check only (no emit)
```
