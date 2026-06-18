import { describe, it, expect, vi, afterEach } from 'vitest';
import { registerAgent } from '../../src/http/agent-api.js';
import type { AgentConfig } from '../../src/config/config.js';
import type { Keypair } from '../../src/crypto/keypair.js';

const config: AgentConfig = { apiKey: 'cv_test', host: 'http://localhost:5000' };
const boxKeypair: Keypair = { publicKey: new Uint8Array(32).fill(1), privateKey: new Uint8Array(32).fill(2) };

function activeResponse(): Response {
  return {
    ok: true,
    status: 200,
    headers: new Headers(),
    json: async () => ({ id: 'agent-1', name: 'CI', status: 'Active' }),
  } as unknown as Response;
}

function callOf(spy: ReturnType<typeof vi.fn>): { url: string; init: RequestInit; headers: Headers } {
  const [url, init] = spy.mock.calls[0]! as [string, RequestInit];
  return { url, init, headers: init.headers as Headers };
}

describe('registerAgent enrollment contract', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('uses GET with no body', async () => {
    const spy = vi.fn().mockResolvedValue(activeResponse());
    vi.stubGlobal('fetch', spy);

    await registerAgent(config, boxKeypair, 'CI', 'signpub==', 'ci');

    const { url, init } = callOf(spy);
    expect(url).toBe('http://localhost:5000/api/agent/me');
    expect(init.method ?? 'GET').toBe('GET');
    expect(init.body).toBeUndefined();
  });

  it('sends the signing public key in the X-Agent-Signing-Key header', async () => {
    const spy = vi.fn().mockResolvedValue(activeResponse());
    vi.stubGlobal('fetch', spy);

    await registerAgent(config, boxKeypair, 'CI', 'signpub==', 'ci');

    expect(callOf(spy).headers.get('X-Agent-Signing-Key')).toBe('signpub==');
  });

  it('sends X-Agent-Type when a type is given (trimmed)', async () => {
    const spy = vi.fn().mockResolvedValue(activeResponse());
    vi.stubGlobal('fetch', spy);

    await registerAgent(config, boxKeypair, 'CI', 'signpub==', '  ci  ');

    expect(callOf(spy).headers.get('X-Agent-Type')).toBe('ci');
  });
});
