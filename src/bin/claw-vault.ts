#!/usr/bin/env node
import { Command } from 'commander';
import { loadRegistry } from '../config/registry.js';
import { profilePaths, validateProfileName, ProfilePaths } from '../config/paths.js';
import { initCommand } from '../commands/init.js';
import { connectCommand } from '../commands/connect.js';
import { statusCommand } from '../commands/status.js';
import { agentsCommand } from '../commands/agents.js';
import { securityCommand } from '../commands/security.js';
import { searchCommand, getCredentialCommand, execCommand } from '../commands/credentials.js';
import { injectCommand } from '../commands/inject.js';
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
program.addCommand(agentsCommand());
program.addCommand(securityCommand(getProfile));
program.addCommand(searchCommand(getProfile));
program.addCommand(getCredentialCommand(getProfile));
program.addCommand(execCommand(getProfile));
program.addCommand(injectCommand(getProfile));
program.addCommand(mcpServeCommand(getProfile));

program.parse();
