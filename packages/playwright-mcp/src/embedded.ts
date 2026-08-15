import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { Page } from 'playwright';

import { spawnAgentRuntime, type AgentRuntimeLocation } from './agent-runtime.js';
import { injectWithPalladin, type InjectArguments } from './server.js';

/** Inject into an agent-owned Page; never launches a browser or accepts CDP. */
export async function injectExistingPlaywrightPage(
  page: Page,
  args: InjectArguments,
  runtime: AgentRuntimeLocation = {},
): Promise<CallToolResult> {
  return injectWithPalladin(page, args, (runtimeArgs) => spawnAgentRuntime(runtimeArgs, runtime));
}
