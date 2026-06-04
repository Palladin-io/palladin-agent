#!/usr/bin/env node
import { Command } from 'commander';
import { loadRegistry } from '../config/registry.js';
import { profilePaths, validateProfileName, ProfilePaths } from '../config/paths.js';
import { initCommand } from '../commands/init.js';
import { connectCommand } from '../commands/connect.js';
import { statusCommand } from '../commands/status.js';
import { listCommand } from '../commands/list.js';
import { getCommand } from '../commands/get.js';
import { agentsCommand } from '../commands/agents.js';
import { securityCommand } from '../commands/security.js';
import {
  searchCommand,
  requestAccessCommand,
  grantStatusCommand,
  retrieveCommand,
} from '../commands/credentials.js';
import { mcpServeCommand } from '../mcp/server.js';

const program = new Command();

program
  .name('claw-vault')
  .description('Claw Vault Agents — CLI + MCP server')
  .version('0.1.0')
  .option('--id <name>', 'agent profile name (default: registry default)');

const getProfile = (): { name: string; paths: ProfilePaths } => {
  const id = program.opts<{ id?: string }>().id;
  if (id !== undefined) validateProfileName(id);
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
program.addCommand(securityCommand(getProfile));
program.addCommand(searchCommand(getProfile));
program.addCommand(requestAccessCommand(getProfile));
program.addCommand(grantStatusCommand(getProfile));
program.addCommand(retrieveCommand(getProfile));
program.addCommand(mcpServeCommand(getProfile));

program.parse();
