import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { reportCredentialStale, tryReportCredentialStale, AgentApiError } from '../../src/http/agent-api.js';
import type { AgentConfig } from '../../src/config/config.js';
import type { Keypair } from '../../src/crypto/keypair.js';

const config: AgentConfig = { apiKey: 'test-api-key', host: 'http://localhost:5000' };
const keypair: Keypair = { publicKey: new Uint8Array(32).fill(1), privateKey: new Uint8Array(32).fill(2) };

describe('reportCredentialStale', () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env['PALLADIN_NO_DIAGNOSTICS'];
  });

  it('POSTs to the per-entry credential-failure endpoint with the agent auth headers', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 202 } as Response);
    vi.stubGlobal('fetch', fetchSpy);

    await reportCredentialStale(config, keypair, { vaultId: 'v1', entryId: 'e1', code: 'login_rejected', note: 'sign-in refused' });

    const url = fetchSpy.mock.calls[0]![0] as string;
    expect(url).toBe('http://localhost:5000/api/agent/vaults/v1/entries/e1/credential-failure');

    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ code: 'login_rejected', note: 'sign-in refused' });

    const headers = init.headers as Headers;
    expect(headers.get('X-Api-Key')).toBe('test-api-key');
    expect(headers.get('X-Agent-Key')).toBeTruthy();
    expect(headers.get('Content-Type')).toBe('application/json');
  });

  it('defaults the code to "manual" and omits the note when not given', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
    vi.stubGlobal('fetch', fetchSpy);

    await reportCredentialStale(config, keypair, { vaultId: 'v1', entryId: 'e1' });

    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({ code: 'manual' });
  });

  it('url-encodes the vault and entry ids', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
    vi.stubGlobal('fetch', fetchSpy);

    await reportCredentialStale(config, keypair, { vaultId: 'v/1', entryId: 'e 1' });

    const url = fetchSpy.mock.calls[0]![0] as string;
    expect(url).toBe('http://localhost:5000/api/agent/vaults/v%2F1/entries/e%201/credential-failure');
  });

  it('throws AgentApiError on a non-2xx response so a manual report can surface it', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404 } as Response));

    await expect(reportCredentialStale(config, keypair, { vaultId: 'v1', entryId: 'e1' }))
      .rejects.toBeInstanceOf(AgentApiError);
  });
});

describe('tryReportCredentialStale (best-effort auto-report)', () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env['PALLADIN_NO_DIAGNOSTICS'];
  });

  it('returns true when the backend accepts the report', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 202 } as Response));
    expect(await tryReportCredentialStale(config, keypair, { vaultId: 'v1', entryId: 'e1', code: 'login_rejected' })).toBe(true);
  });

  it('returns false (never throws) on a network error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    await expect(tryReportCredentialStale(config, keypair, { vaultId: 'v1', entryId: 'e1' })).resolves.toBe(false);
  });

  it('returns false on a non-2xx response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 } as Response));
    expect(await tryReportCredentialStale(config, keypair, { vaultId: 'v1', entryId: 'e1' })).toBe(false);
  });

  it('does not touch the network when diagnostics are opted out', async () => {
    process.env['PALLADIN_NO_DIAGNOSTICS'] = '1';
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    expect(await tryReportCredentialStale(config, keypair, { vaultId: 'v1', entryId: 'e1' })).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
