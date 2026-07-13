import { afterEach, describe, expect, it, vi } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentConfig } from '../../src/config/config.js';
import type { Keypair } from '../../src/crypto/keypair.js';
import { INJECT_UNAVAILABLE } from '../../src/commands/inject.js';
import { registerTools } from '../../src/mcp/tools.js';

type ToolHandler = (input: Record<string, unknown>) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

describe('inject_credential browser boundary', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('never contacts fake CDP or the Palladin API', async () => {
    const handlers = new Map<string, ToolHandler>();
    const server = {
      registerTool(name: string, _definition: unknown, handler: ToolHandler) {
        handlers.set(name, handler);
      },
    } as unknown as McpServer;
    const fetch = vi.fn(() => {
      throw new Error('network must not be contacted');
    });
    vi.stubGlobal('fetch', fetch);

    registerTools(server, {} as AgentConfig, {} as Keypair);
    const inject = handlers.get('inject_credential');
    expect(inject).toBeDefined();

    const result = await inject!({
      vaultId: 'vault-fixture',
      entryId: 'entry-fixture',
      cdp: 'http://127.0.0.1:9222',
    });

    expect(fetch).not.toHaveBeenCalled();
    expect(result).toEqual({
      content: [{ type: 'text', text: INJECT_UNAVAILABLE }],
      isError: true,
    });
  });
});
