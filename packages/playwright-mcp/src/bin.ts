#!/usr/bin/env node

import { main } from './server.js';

void main().catch(() => {
  process.stderr.write('Error: Palladin Playwright MCP could not start\n');
  process.exitCode = 1;
});
