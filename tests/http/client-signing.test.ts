import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import _sodium from 'libsodium-wrappers';
import { apiFetch, SigningContext } from '../../src/http/client.js';
import { canonicalString, generateSigningKeypair } from '../../src/crypto/signing.js';
import type { AgentConfig } from '../../src/config/config.js';
import type { Keypair } from '../../src/crypto/keypair.js';

const config: AgentConfig = { apiKey: 'k', host: 'http://localhost:5000' };
const boxKeypair: Keypair = { publicKey: new Uint8Array(32).fill(1), privateKey: new Uint8Array(32).fill(2) };

function headersFromCall(spy: ReturnType<typeof vi.fn>): Headers {
  return (spy.mock.calls[0]![1] as RequestInit).headers as Headers;
}

describe('apiFetch request signing', () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => vi.unstubAllGlobals());

  it('adds no signature headers when no signing context is given', async () => {
    const spy = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
    vi.stubGlobal('fetch', spy);

    await apiFetch('/api/agent/entries?query=x', config, boxKeypair);

    const headers = headersFromCall(spy);
    expect(headers.get('X-Api-Key')).toBe('k');
    expect(headers.get('X-Agent-Signature')).toBeNull();
    expect(headers.get('X-Agent-Id')).toBeNull();
  });

  it('adds all four signature headers when a signing context is given', async () => {
    const spy = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
    vi.stubGlobal('fetch', spy);
    const signing: SigningContext = { agentId: 'agent-123', keypair: await generateSigningKeypair() };

    await apiFetch('/api/agent/entries?query=x', config, boxKeypair, undefined, signing);

    const headers = headersFromCall(spy);
    expect(headers.get('X-Agent-Id')).toBe('agent-123');
    expect(headers.get('X-Agent-Timestamp')).toMatch(/^\d+$/);
    expect(Buffer.from(headers.get('X-Agent-Nonce')!, 'base64')).toHaveLength(16);
    expect(headers.get('X-Agent-Signature')).toBeTruthy();
  });

  it('signs the canonical for a POST so the backend can verify it (body included)', async () => {
    await _sodium.ready;
    const spy = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
    vi.stubGlobal('fetch', spy);
    const keypair = await generateSigningKeypair();
    const signing: SigningContext = { agentId: 'agent-123', keypair };

    const body = JSON.stringify({ reason: 'login' });
    await apiFetch(
      '/api/agent/vaults/v1/entries/e1/credential',
      config,
      boxKeypair,
      { method: 'POST', body },
      signing,
    );

    const headers = headersFromCall(spy);
    const canonical = canonicalString({
      method: 'POST',
      pathWithQuery: '/api/agent/vaults/v1/entries/e1/credential',
      timestamp: Number(headers.get('X-Agent-Timestamp')),
      nonce: headers.get('X-Agent-Nonce')!,
      body,
    });
    const sig = new Uint8Array(Buffer.from(headers.get('X-Agent-Signature')!, 'base64'));
    expect(_sodium.crypto_sign_verify_detached(sig, Buffer.from(canonical, 'utf8'), keypair.publicKey)).toBe(true);
  });

  it('signs an empty-body GET using the path with query string', async () => {
    await _sodium.ready;
    const spy = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
    vi.stubGlobal('fetch', spy);
    const keypair = await generateSigningKeypair();

    const path = '/api/agent/entries?query=facebook&pageSize=10';
    await apiFetch(path, config, boxKeypair, undefined, { agentId: 'a', keypair });

    const headers = headersFromCall(spy);
    const canonical = canonicalString({
      method: 'GET',
      pathWithQuery: path,
      timestamp: Number(headers.get('X-Agent-Timestamp')),
      nonce: headers.get('X-Agent-Nonce')!,
      body: '',
    });
    const sig = new Uint8Array(Buffer.from(headers.get('X-Agent-Signature')!, 'base64'));
    expect(_sodium.crypto_sign_verify_detached(sig, Buffer.from(canonical, 'utf8'), keypair.publicKey)).toBe(true);
  });
});
