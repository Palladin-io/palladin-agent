import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AgentConfig } from '../config/config.js';
import { Keypair, publicKeyBase64 } from '../crypto/keypair.js';

function buildHeaders(config: AgentConfig, keypair: Keypair): Headers {
  const headers = new Headers();
  headers.set('X-Api-Key', config.apiKey);
  headers.set('X-Agent-Key', publicKeyBase64(keypair));
  headers.set('Content-Type', 'application/json');
  return headers;
}

export function registerTools(server: McpServer, config: AgentConfig, keypair: Keypair): void {
  const base = config.host;
  const headers = buildHeaders(config, keypair);

  server.registerTool(
    'list_vaults',
    {
      description: 'List all vaults accessible to this agent',
      inputSchema: z.object({}),
    },
    async () => {
      const res = await fetch(`${base}/api/vaults`, { headers });
      const data = await res.json();
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );

  server.registerTool(
    'list_entries',
    {
      description: 'List entries in a vault',
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
      }),
    },
    async ({ vaultId }) => {
      const res = await fetch(`${base}/api/vaults/${encodeURIComponent(vaultId)}/entries`, { headers });
      const data = await res.json();
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }
  );
}
