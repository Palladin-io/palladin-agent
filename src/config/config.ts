import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { ProfilePaths } from './paths.js';

export interface AgentConfig {
  apiKey: string;
  host: string;
}

export function loadConfig(paths: ProfilePaths): AgentConfig {
  if (!existsSync(paths.config)) {
    throw new Error('Not connected. Run: claw-vault connect <api-key> --host <host>');
  }
  return JSON.parse(readFileSync(paths.config, 'utf8')) as AgentConfig;
}

export function saveConfig(config: AgentConfig, paths: ProfilePaths): void {
  mkdirSync(paths.root, { recursive: true });
  writeFileSync(paths.config, JSON.stringify(config, null, 2), { encoding: 'utf8', mode: 0o600 });
}
