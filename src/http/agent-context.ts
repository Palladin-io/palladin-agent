import { AgentConfig, loadConfig } from '../config/config.js';
import { Keypair, loadKeypair } from '../crypto/keypair.js';
import { loadSigningKeypair } from '../crypto/signing.js';
import { hasKey } from '../crypto/secure-storage.js';
import { ProfilePaths } from '../config/paths.js';
import { SigningContext } from './client.js';

/**
 * Everything an agent request needs: the saved config, the X25519 box keypair (for X-Agent-Key /
 * DEK unwrap), and — when available — the Ed25519 signing context used to sign every request
 * (CVT-157). `signing` is undefined only for an agent enrolled before signing was introduced or one
 * whose backend agentId is not yet known; in that case requests go unsigned (the backend rejects
 * them once signing is mandatory — re-run `claw-vault connect` to enroll the signing key).
 */
export interface AgentContext {
  config: AgentConfig;
  keypair: Keypair;
  signing?: SigningContext;
}

/**
 * Build the agent context for a profile. The signing context is included when both a signing key is
 * present in secure storage AND the backend agentId is known (persisted in config at connect/status).
 */
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
