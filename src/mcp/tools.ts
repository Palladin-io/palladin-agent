import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AgentConfig } from '../config/config.js';
import { Keypair } from '../crypto/keypair.js';
import {
  AgentApiError,
  searchEntries,
  getCredential,
} from '../http/agent-api.js';
import { decryptCredential } from '../crypto/decrypt.js';

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

function ok(text: string): ToolResult {
  return { content: [{ type: 'text', text }] };
}

function fail(text: string): ToolResult {
  return { content: [{ type: 'text', text }], isError: true };
}

function errorMessage(err: unknown): string {
  if (err instanceof AgentApiError) return err.message;
  return `Unexpected error: ${(err as Error).message ?? String(err)}`;
}

// Discovery is org-wide via GET /api/agent/entries (agent-auth, metadata only).
// The legacy CVT-44 placeholders list_vaults / list_entries called JwtBearer (user)
// endpoints and returned 401 under agent-auth — they are intentionally not exposed.
export function registerTools(server: McpServer, config: AgentConfig, keypair: Keypair): void {
  server.registerTool(
    'search_entries',
    {
      description:
        "Search vault entries by name/url/description (e.g. 'facebook') across the agent's organization. " +
        'Returns candidates (id, vaultId, name, url, description) — metadata only, no secrets. ' +
        'Pick one and call get_credential with its vaultId+entryId.',
      inputSchema: z.object({
        query: z.string().min(2).describe('Search term — matched against entry name, url and description (min 2 chars)'),
      }),
    },
    async ({ query }) => {
      try {
        const result = await searchEntries(config, keypair, query.trim());
        return ok(JSON.stringify(result, null, 2));
      } catch (err) {
        return fail(errorMessage(err));
      }
    }
  );

  server.registerTool(
    'get_credential',
    {
      description:
        "Get a credential. If the agent has no grant yet, this requests one (user approves in the panel) and returns access:'pending' — call again shortly. Returns access:'granted' with the decrypted secret once approved.",
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID'),
        reason: z.string().optional().describe('Justification shown to the approving user (required when first requesting access)'),
      }),
    },
    async ({ vaultId, entryId, reason }) => {
      try {
        const result = await getCredential(config, keypair, vaultId, entryId, reason?.trim());
        if (result.access === 'granted') {
          const secret = await decryptCredential(result, keypair);
          return ok(JSON.stringify(
            { access: 'granted', entryId: result.entryId, label: result.label, secret },
            null,
            2,
          ));
        }
        // pending / denied / revoked / expired / consumed / unavailable / blocked:
        // return the discriminated status as-is (no secret).
        return ok(JSON.stringify(result, null, 2));
      } catch (err) {
        return fail(errorMessage(err));
      }
    }
  );
}
