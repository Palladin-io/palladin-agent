import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { uploadInjectFailure } from '../../src/http/agent-api.js';
import type { AgentConfig } from '../../src/config/config.js';
import type { Keypair } from '../../src/crypto/keypair.js';

const config: AgentConfig = { apiKey: 'k', host: 'http://localhost:5000' };
const keypair: Keypair = { publicKey: new Uint8Array(32).fill(1), privateKey: new Uint8Array(32).fill(2) };

const body = {
  entryId: 'e1',
  domain: 'tricky-site.com',
  reason: 'no login form detected on the current page',
  pageOrigin: 'https://tricky-site.com',
  controls: [{ tag: 'input', type: 'password', name: 'pw' }],
};

describe('uploadInjectFailure', () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env['CLAW_VAULT_NO_DIAGNOSTICS'];
  });

  it('POSTs the redacted report to the agent endpoint', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
    vi.stubGlobal('fetch', fetchSpy);

    const ok = await uploadInjectFailure(config, keypair, body);

    expect(ok).toBe(true);
    const url = fetchSpy.mock.calls[0]![0] as string;
    expect(url).toBe('http://localhost:5000/api/agent/inject-failures');
    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual(body);
  });

  it('returns false (best-effort) on a network error — never throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    await expect(uploadInjectFailure(config, keypair, body)).resolves.toBe(false);
  });

  it('returns false on a non-2xx response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 } as Response));
    expect(await uploadInjectFailure(config, keypair, body)).toBe(false);
  });

  it('does not call the network when diagnostics are opted out', async () => {
    process.env['CLAW_VAULT_NO_DIAGNOSTICS'] = '1';
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    expect(await uploadInjectFailure(config, keypair, body)).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
