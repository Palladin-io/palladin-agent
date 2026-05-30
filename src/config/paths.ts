import { homedir } from 'os';
import { join } from 'path';

export const clawVaultRoot = process.env['CLAW_VAULT_HOME'] ?? join(homedir(), '.claw-vault');
export const agentsDir = join(clawVaultRoot, 'agents');
export const registryPath = join(clawVaultRoot, 'registry.json');

const NAME_RE = /^[a-z0-9_-]+$/i;

/**
 * Validates the profile name against the allowed character set.
 * Exits the process with an error message if the name is invalid.
 * Must be called before any filesystem operation that uses the name
 * to prevent path-traversal attacks (e.g. --id '../../etc').
 */
export function validateProfileName(name: string): void {
  if (!NAME_RE.test(name)) {
    console.error('Error: name must contain only letters, digits, hyphens, or underscores');
    process.exit(1);
  }
}

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
