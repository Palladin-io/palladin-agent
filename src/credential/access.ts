import { CredentialAccess, CredentialMethod } from '../http/agent-api.js';

/**
 * Human-readable explanation for a non-granted access state, shared by the get/exec/inject commands
 * and the MCP tools so the messaging stays consistent. `method` tailors the method-not-allowed hint.
 */
export function accessMessage(access: Exclude<CredentialAccess['access'], 'granted'>, method: CredentialMethod, grantId?: string): string {
  switch (access) {
    case 'pending':
      return grantId
        ? `Access requested (grant ${grantId}) — awaiting user approval. Try again shortly.`
        : 'Access is pending user approval. Try again shortly.';
    case 'denied':
      return 'Access was denied by the vault owner.';
    case 'revoked':
      return 'Access to this credential was revoked.';
    case 'expired':
      return 'The grant for this credential has expired.';
    case 'consumed':
      return 'The grant has no remaining uses (consumed).';
    case 'unavailable':
      return 'A grant covers this entry but no credential material is available yet — request access.';
    case 'blocked':
      return 'This agent is deactivated.';
    case 'method-not-allowed':
      return methodNotAllowedMessage(method);
    default:
      return `No access: ${access satisfies never}`;
  }
}

function methodNotAllowedMessage(method: CredentialMethod): string {
  const alternatives = (['exec', 'inject', 'get'] as CredentialMethod[])
    .filter((m) => m !== method)
    .map((m) => `palladin ${m}`)
    .join(' or ');
  return `This grant does not permit "${method}". The owner restricted how this credential may be used — try ${alternatives}, or ask them to allow "${method}".`;
}

/**
 * Warning shown after a successful `get`: the plaintext is now in the agent's context and, for a
 * hosted LLM, leaves the machine. exec/inject keep the secret out of the model's context.
 */
export const GET_EXPOSURE_WARNING =
  'Note: this secret is now in the agent\'s context. On a hosted LLM it may leave your machine. ' +
  'Prefer `palladin exec` (injects into a subprocess) or `palladin inject` (fills a login form) to avoid exposing it.';
