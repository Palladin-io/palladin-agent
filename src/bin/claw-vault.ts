#!/usr/bin/env node
import { Command } from 'commander';
import { loadRegistry } from '../config/registry.js';
import { profilePaths, ProfilePaths } from '../config/paths.js';
import { initCommand } from '../commands/init.js';
import { connectCommand } from '../commands/connect.js';
import { statusCommand } from '../commands/status.js';
import { listCommand } from '../commands/list.js';
import { getCommand } from '../commands/get.js';
import { agentsCommand } from '../commands/agents.js';
import { mcpServeCommand } from '../mcp/server.js';

const program = new Command();

program
  .name('claw-vault')
  .description('Claw Vault agent CLI + MCP server')
  .version('0.1.0')
  .option('--id <name>', 'agent profile name (default: registry default)');

const getProfile = (): { name: string; paths: ProfilePaths } => {
  const id = program.opts<{ id?: string }>().id;
  const registry = loadRegistry();
  const name = id ?? registry.default;
  return { name, paths: profilePaths(name) };
};

program.addCommand(initCommand(getProfile));
program.addCommand(connectCommand(getProfile));
program.addCommand(statusCommand(getProfile));
program.addCommand(listCommand(getProfile));
program.addCommand(getCommand(getProfile));
program.addCommand(agentsCommand());
program.addCommand(mcpServeCommand(getProfile));

program.parse();
