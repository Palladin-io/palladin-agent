import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { ProfilePaths } from './paths.js';

export interface AgentConfig {
  apiKey: string;
  host: string;
  /**
   * The backend-assigned agent ID. Sent as X-Agent-Id and used in the signature canonical so the
   * server can look up Agent.SigningPublicKey to verify each request (CVT-157). Populated by
   * connect/status once the backend returns it; absent before the first successful enrollment.
   */
  agentId?: string;
  /** Base64 Ed25519 signing public key registered with the backend (for reference/status only). */
  signingPublicKey?: string;
}

export function loadConfig(paths: ProfilePaths): AgentConfig {
  if (!existsSync(paths.config)) {
    throw new Error('Not connected. Run: palladin connect <api-key> --host <host>');
  }
  return JSON.parse(readFileSync(paths.config, 'utf8')) as AgentConfig;
}

export function saveConfig(config: AgentConfig, paths: ProfilePaths): void {
  mkdirSync(paths.root, { recursive: true, mode: 0o700 });
  writeFileSync(paths.config, JSON.stringify(config, null, 2), { encoding: 'utf8', mode: 0o600 });
}
