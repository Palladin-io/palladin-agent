import { describe, expect, it } from 'vitest';

import { injectWithPalladin } from '../../packages/agent-browser-mcp/src/server.js';

describe('AgentBrowser MCP Inject provider boundary', () => {
  it('fails closed without echoing or sending a credential', () => {
    const fixtureSecret = 'fixture-value-not-production';
    const result = injectWithPalladin();

    expect(result).toEqual({
      content: [{ type: 'text', text: JSON.stringify({
        status: 'provider-unavailable',
        provider: 'agent-browser',
        reason: 'unsupported-secret-delivery',
      }) }],
      isError: true,
    });
    expect(JSON.stringify(result)).not.toContain(fixtureSecret);
  });
});
