import { describe, expect, it } from 'vitest';

import {
  isBrowserProvider,
  validateBrowserPageCapability,
  type BrowserPageCapability,
} from '../../src/browser-host/provider-contract.js';

describe('agent-owned browser provider contract', () => {
  it('accepts the open provider namespace without treating endpoints as providers', () => {
    expect(isBrowserProvider('playwright')).toBe(true);
    expect(isBrowserProvider('agent-browser')).toBe(true);
    expect(isBrowserProvider('claude-browser')).toBe(true);
    expect(isBrowserProvider('codex-browser')).toBe(true);
    expect(isBrowserProvider('future-browser-adapter')).toBe(true);
    expect(isBrowserProvider('ws://127.0.0.1:9222')).toBe(false);
    expect(isBrowserProvider('Unknown Provider')).toBe(false);
    expect(isBrowserProvider('unfinished-')).toBe(false);
  });

  it('requires a stable page and session capability', () => {
    const page: BrowserPageCapability = {
      provider: 'playwright', sessionId: 'session-1', pageId: 'page-1',
      currentUrl: async () => 'https://example.com/login',
      inject: async () => undefined,
    };
    expect(() => validateBrowserPageCapability(page)).not.toThrow();
    expect(() => validateBrowserPageCapability({ ...page, pageId: '' })).toThrow('identity');
    expect(() => validateBrowserPageCapability({ ...page, sessionId: 'bad\nvalue' })).toThrow('identity');
  });
});
