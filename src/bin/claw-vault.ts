#!/usr/bin/env node
import { Command } from 'commander';
import { initCommand } from '../commands/init.js';
import { connectCommand } from '../commands/connect.js';
import { statusCommand } from '../commands/status.js';
import { listCommand } from '../commands/list.js';
import { getCommand } from '../commands/get.js';
import { mcpServeCommand } from '../mcp/server.js';

const program = new Command();

program
  .name('claw-vault')
  .description('Claw Vault agent CLI + MCP server')
  .version('0.1.0');

program.addCommand(initCommand());
program.addCommand(connectCommand());
program.addCommand(statusCommand());
program.addCommand(listCommand());
program.addCommand(getCommand());
program.addCommand(mcpServeCommand());

program.parse();
