/**
 * Provider-neutral contract for an agent-owned browser session.
 *
 * The agent remains the owner of the browser. Palladin receives only a narrow
 * capability for the current page; it never launches a browser or accepts a
 * debugger/CDP endpoint. Provider adapters (Playwright, Agent Browser, Claude
 * Browser and Codex Browser) implement this contract in the agent process.
 */
import type { InjectFormDefinition, InjectFieldValue } from '../inject-contract.js';

export type BrowserProvider =
  | 'playwright'
  | 'agent-browser'
  | 'claude-browser'
  | 'codex-browser'
  | 'extension';

export interface BrowserPageCapability {
  readonly provider: BrowserProvider;
  /** Stable, agent-owned page/session identifier. Never a CDP URL. */
  readonly sessionId: string;
  readonly pageId: string;
  currentUrl(): Promise<string>;
  /** Fill the already-open page and perform the declared submit actions. */
  inject(values: readonly InjectFieldValue[], form: InjectFormDefinition): Promise<void>;
}

export interface BrowserInjectRequest {
  readonly page: BrowserPageCapability;
  readonly form: InjectFormDefinition;
  readonly vaultId: string;
  readonly entryId: string;
  readonly reason?: string;
  readonly wait?: string;
  readonly pollInterval?: string;
}

/** Runtime-neutral metadata sent in the authenticated provider handshake. */
export interface BrowserProviderOpenFrame {
  readonly protocol: 'palladin.inject-provider.v1';
  readonly type: 'open';
  readonly provider: BrowserProvider;
  readonly nonce: string;
  readonly sessionId: string;
  readonly pageId: string;
  readonly currentUrl: string;
  readonly form: InjectFormDefinition;
}

export function isBrowserProvider(value: unknown): value is BrowserProvider {
  return value === 'playwright' || value === 'agent-browser'
    || value === 'claude-browser' || value === 'codex-browser' || value === 'extension';
}

/** Reject accidental debugger URLs and require an agent-owned page identity. */
export function validateBrowserPageCapability(page: BrowserPageCapability): void {
  if (!isBrowserProvider(page.provider)) throw new Error('unsupported browser provider');
  if (!nonEmpty(page.sessionId) || !nonEmpty(page.pageId)) throw new Error('browser session identity is missing');
}

function nonEmpty(value: string): boolean {
  return value.length >= 1 && value.length <= 256 && !/[\u0000\r\n]/u.test(value);
}
