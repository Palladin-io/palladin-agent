import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AgentConfig } from '../config/config.js';
import { Keypair } from '../crypto/keypair.js';
import {
  AgentApiError,
  searchEntries,
  requestAccess,
  getGrantStatus,
  deliverCredential,
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
        'Pick one and call request_access with its vaultId+entryId.',
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
    'request_access',
    {
      description:
        'Request user approval to access a single credential entry. Creates a pending grant the user must approve in the Claw Vault panel. Returns { grantId, status }. Poll get_grant_status until the status is "Active", then call retrieve_credential.',
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID to request access to'),
        reason: z.string().describe('Human-readable justification shown to the approving user'),
      }),
    },
    async ({ vaultId, entryId, reason }) => {
      try {
        const result = await requestAccess(config, keypair, vaultId, entryId, reason.trim());
        return ok(JSON.stringify(result, null, 2));
      } catch (err) {
        return fail(errorMessage(err));
      }
    }
  );

  server.registerTool(
    'get_grant_status',
    {
      description:
        'Check the status of a previously requested grant. Returns { grantId, status, expiresAt, queryLimit }. Status is one of Pending, Active, Denied, Revoked, Expired, Consumed. When Active, call retrieve_credential. This does NOT block — poll it yourself (e.g. every few seconds) while waiting for the user to approve.',
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        grantId: z.string().describe('Grant ID returned by request_access'),
      }),
    },
    async ({ vaultId, grantId }) => {
      try {
        const result = await getGrantStatus(config, keypair, vaultId, grantId);
        return ok(JSON.stringify(result, null, 2));
      } catch (err) {
        return fail(errorMessage(err));
      }
    }
  );

  server.registerTool(
    'retrieve_credential',
    {
      description:
        'Retrieve and locally decrypt a credential for an entry the agent has an active grant for. The secret is decrypted on this machine with the agent private key (which never leaves it) and returned as plaintext. Requires an Active grant — call request_access first if you get "no active grant". Each retrieval may count against the grant query limit.',
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID to retrieve'),
      }),
    },
    async ({ vaultId, entryId }) => {
      try {
        const envelope = await deliverCredential(config, keypair, vaultId, entryId);
        const secret = await decryptCredential(envelope, keypair);
        return ok(JSON.stringify({ entryId: envelope.entryId, label: envelope.label, secret }, null, 2));
      } catch (err) {
        return fail(errorMessage(err));
      }
    }
  );
}
