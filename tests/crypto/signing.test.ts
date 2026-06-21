import { describe, it, expect } from 'vitest';
import _sodium from 'libsodium-wrappers';
import { createHash } from 'crypto';
import {
  generateSigningKeypair,
  signingPublicKeyBase64,
  canonicalString,
  sha256Base64,
  generateNonce,
  buildSignatureHeaders,
} from '../../src/crypto/signing.js';

async function sodium() {
  await _sodium.ready;
  return _sodium;
}

describe('generateSigningKeypair', () => {
  it('produces a 32-byte public key and 64-byte secret key (Ed25519)', async () => {
    const kp = await generateSigningKeypair();
    expect(kp.publicKey).toHaveLength(32);
    expect(kp.privateKey).toHaveLength(64);
  });

  it('embeds the public key in the trailing 32 bytes of the secret key', async () => {
    const kp = await generateSigningKeypair();
    expect(Buffer.from(kp.privateKey.slice(32))).toEqual(Buffer.from(kp.publicKey));
  });

  it('is unique per call', async () => {
    const a = await generateSigningKeypair();
    const b = await generateSigningKeypair();
    expect(Buffer.from(a.privateKey).toString('hex')).not.toBe(Buffer.from(b.privateKey).toString('hex'));
  });
});

describe('signingPublicKeyBase64', () => {
  it('round-trips to 32 raw bytes', async () => {
    const kp = await generateSigningKeypair();
    const b64 = signingPublicKeyBase64(kp);
    expect(Buffer.from(b64, 'base64')).toHaveLength(32);
  });
});

describe('sha256Base64', () => {
  it('hashes the empty body to base64(sha256(""))', () => {
    const expected = createHash('sha256').update(Buffer.alloc(0)).digest('base64');
    expect(sha256Base64('')).toBe(expected);
  });

  it('matches node crypto for a JSON body', () => {
    const body = JSON.stringify({ reason: 'login' });
    const expected = createHash('sha256').update(Buffer.from(body, 'utf8')).digest('base64');
    expect(sha256Base64(body)).toBe(expected);
  });
});

describe('canonicalString', () => {
  it('joins method, path, timestamp, nonce, and body hash with \\n in order', () => {
    const s = canonicalString({
      method: 'post',
      pathWithQuery: '/api/agent/vaults/v1/entries/e1/credential',
      timestamp: 1718000000,
      nonce: 'bm9uY2U=',
      body: '{"reason":"x"}',
    });
    const lines = s.split('\n');
    expect(lines).toHaveLength(5);
    expect(lines[0]).toBe('POST'); // upper-cased
    expect(lines[1]).toBe('/api/agent/vaults/v1/entries/e1/credential');
    expect(lines[2]).toBe('1718000000');
    expect(lines[3]).toBe('bm9uY2U=');
    expect(lines[4]).toBe(sha256Base64('{"reason":"x"}'));
  });

  it('hashes an empty/omitted body as sha256 of zero bytes', () => {
    const withEmpty = canonicalString({ method: 'GET', pathWithQuery: '/api/agent/entries?query=x', timestamp: 1, nonce: 'n' });
    expect(withEmpty.split('\n')[4]).toBe(sha256Base64(''));
  });
});

describe('generateNonce', () => {
  it('returns a 16-byte value as base64', () => {
    expect(Buffer.from(generateNonce(), 'base64')).toHaveLength(16);
  });

  it('is unique across calls', () => {
    expect(generateNonce()).not.toBe(generateNonce());
  });
});

describe('buildSignatureHeaders', () => {
  it('returns the four proof-of-possession headers', async () => {
    const keypair = await generateSigningKeypair();
    const headers = await buildSignatureHeaders({
      agentId: 'agent-123',
      keypair,
      method: 'POST',
      pathWithQuery: '/api/agent/vaults/v1/entries/e1/credential',
      body: '{"reason":"x"}',
      timestamp: 1718000000,
      nonce: 'bm9uY2U=',
    });

    expect(headers['X-Agent-Id']).toBe('agent-123');
    expect(headers['X-Agent-Timestamp']).toBe('1718000000');
    expect(headers['X-Agent-Nonce']).toBe('bm9uY2U=');
    expect(typeof headers['X-Agent-Signature']).toBe('string');
  });

  it('produces a signature the backend can verify against the canonical string (round-trip)', async () => {
    const s = await sodium();
    const keypair = await generateSigningKeypair();
    const ts = 1718000000;
    const nonce = generateNonce();
    const path = '/api/agent/vaults/v1/entries/e1/credential';
    const body = '{"reason":"login to post"}';

    const headers = await buildSignatureHeaders({
      agentId: 'agent-123',
      keypair,
      method: 'POST',
      pathWithQuery: path,
      body,
      timestamp: ts,
      nonce,
    });

    // Reconstruct the canonical the SAME way the backend would, then verify with the public key.
    const canonical = canonicalString({ method: 'POST', pathWithQuery: path, timestamp: ts, nonce, body });
    const sig = new Uint8Array(Buffer.from(headers['X-Agent-Signature'], 'base64'));
    const verified = s.crypto_sign_verify_detached(sig, Buffer.from(canonical, 'utf8'), keypair.publicKey);
    expect(verified).toBe(true);
  });

  it('a tampered body breaks verification', async () => {
    const s = await sodium();
    const keypair = await generateSigningKeypair();
    const ts = 1718000000;
    const nonce = 'bm9uY2U=';
    const path = '/api/agent/entries?query=x';

    const headers = await buildSignatureHeaders({
      agentId: 'a', keypair, method: 'GET', pathWithQuery: path, body: '', timestamp: ts, nonce,
    });

    // Verify against a DIFFERENT body hash → must fail.
    const tampered = canonicalString({ method: 'GET', pathWithQuery: path, timestamp: ts, nonce, body: 'malicious' });
    const sig = new Uint8Array(Buffer.from(headers['X-Agent-Signature'], 'base64'));
    expect(s.crypto_sign_verify_detached(sig, Buffer.from(tampered, 'utf8'), keypair.publicKey)).toBe(false);
  });
});
