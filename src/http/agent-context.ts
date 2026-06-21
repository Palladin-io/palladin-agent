import { AgentConfig, loadConfig } from '../config/config.js';
import { Keypair, loadKeypair } from '../crypto/keypair.js';
import { loadSigningKeypair } from '../crypto/signing.js';
import { hasKey } from '../crypto/secure-storage.js';
import { ProfilePaths } from '../config/paths.js';
import { SigningContext } from './client.js';

export interface AgentContext {
  config: AgentConfig;
  keypair: Keypair;
  // Undefined for agents enrolled before signing existed or with no known agentId yet.
  signing?: SigningContext;
}

export async function resolveAgentContext(profile: string, paths: ProfilePaths): Promise<AgentContext> {
  const config = loadConfig(paths);
  const keypair = await loadKeypair(profile, paths);

  let signing: SigningContext | undefined;
  if (config.agentId && (await hasKey(profile, paths, 'signing'))) {
    const signingKeypair = await loadSigningKeypair(profile, paths);
    signing = { agentId: config.agentId, keypair: signingKeypair };
  }

  return { config, keypair, signing };
}
