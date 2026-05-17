import { AgentConfig } from '../config/config.js';
import { Keypair, publicKeyBase64 } from '../crypto/keypair.js';

export type AgentRegistrationResult =
  | { status: 'pending';     agentId: string }
  | { status: 'active';      agentId: string; name: string | null }
  | { status: 'deactivated'; agentId: string }
  | { status: 'invalid_key' }
  | { status: 'unreachable'; error: string };

export async function registerAgent(
  config: AgentConfig,
  keypair: Keypair,
): Promise<AgentRegistrationResult> {
  const headers = new Headers({
    'X-Api-Key':    config.apiKey,
    'X-Agent-Key':  publicKeyBase64(keypair),
    'Content-Type': 'application/json',
  });

  let res: Response;
  try {
    res = await fetch(`${config.host}/api/agent/me`, { headers });
  } catch (err) {
    return { status: 'unreachable', error: String(err) };
  }

  if (res.status === 401) {
    const agentId = res.headers.get('X-Agent-Id');
    if (agentId) {
      return { status: 'pending', agentId };
    }
    return { status: 'invalid_key' };
  }

  if (res.ok) {
    const body = await res.json() as { id: string; name: string | null; status: string };
    if (body.status === 'Deactivated') {
      return { status: 'deactivated', agentId: body.id };
    }
    return { status: 'active', agentId: body.id, name: body.name };
  }

  return { status: 'unreachable', error: `HTTP ${res.status}` };
}
