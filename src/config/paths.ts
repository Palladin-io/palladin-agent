import { homedir } from 'os';
import { join } from 'path';

const root = process.env['CLAW_VAULT_HOME'] ?? join(homedir(), '.claw-vault');

export const paths = {
  root,
  privateKey: join(root, 'agent.key'),
  publicKey:  join(root, 'agent.pub'),
  config:     join(root, 'config.json'),
} as const;
