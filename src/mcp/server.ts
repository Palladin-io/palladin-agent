import { Command } from 'commander';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig } from '../config/config.js';
import { loadKeypair } from '../crypto/keypair.js';
import { registerTools } from './tools.js';
import { ProfilePaths } from '../config/paths.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export function mcpServeCommand(getProfile: GetProfile): Command {
  return new Command('mcp')
    .description('MCP server commands')
    .addCommand(
      new Command('serve')
        .description('Start MCP server for AI agent use')
        .action(async () => {
          const { name, paths } = getProfile();
          const config  = loadConfig(paths);
          const keypair = await loadKeypair(name, paths);

          const server = new McpServer({
            name: 'Claw Vault Agents',
            version: '0.1.0',
          });

          registerTools(server, config, keypair);

          const transport = new StdioServerTransport();
          await server.connect(transport);
        }),
    );
}
