import { homedir } from 'os';
import { join } from 'path';

export const clawVaultRoot = process.env['CLAW_VAULT_HOME'] ?? join(homedir(), '.claw-vault');
export const agentsDir = join(clawVaultRoot, 'agents');
export const registryPath = join(clawVaultRoot, 'registry.json');

export const legacyPaths = {
  config:     join(clawVaultRoot, 'config.json'),
  privateKey: join(clawVaultRoot, 'agent.key'),
  publicKey:  join(clawVaultRoot, 'agent.pub'),
};

export interface ProfilePaths {
  root:       string;
  privateKey: string;
  publicKey:  string;
  config:     string;
}

export function profilePaths(name: string): ProfilePaths {
  const root = join(agentsDir, name);
  return {
    root,
    privateKey: join(root, 'agent.key'),
    publicKey:  join(root, 'agent.pub'),
    config:     join(root, 'config.json'),
  };
}
