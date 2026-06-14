import { CredentialAccess } from '../http/agent-api.js';

/**
 * Process exit codes, following the BSD sysexits convention so a calling agent / script can branch
 * on *retryable* vs *terminal* without parsing text:
 *   0  — success (granted)
 *   75 — TEMPFAIL: still pending after the wait budget, or `--no-wait` while pending, or `unavailable`.
 *        The request stays open server-side — re-running resumes. Retryable.
 *   77 — NOPERM: denied / revoked / expired / consumed / blocked / method-not-allowed. NOT retryable
 *        automatically — needs the owner to act (or a different method).
 *   1  — generic transport / validation failure.
 */
export const EX_OK = 0;
export const EX_GENERIC = 1;
export const EX_TEMPFAIL = 75;
export const EX_NOPERM = 77;

/** Map a non-granted access state to its exit code. */
export function exitCodeForAccess(
  access: Exclude<CredentialAccess['access'], 'granted'>,
): number {
  switch (access) {
    case 'pending':
    case 'unavailable':
      return EX_TEMPFAIL;
    default:
      return EX_NOPERM;
  }
}
