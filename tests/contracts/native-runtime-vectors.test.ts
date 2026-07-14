import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import _sodium from 'libsodium-wrappers';
import { describe, expect, it } from 'vitest';

import { decryptCredential, EncryptedCredential } from '../../src/crypto/decrypt.js';
import { generateKeypair, Keypair } from '../../src/crypto/keypair.js';
import {
  buildSignatureHeaders,
  canonicalString,
  sha256Base64,
  SigningKeypair,
} from '../../src/crypto/signing.js';
import { expectSensitiveEqual } from '../helpers/sensitive-assert.js';

interface SigningFixture {
  contract: string;
  syntheticOnly: boolean;
  algorithm: string;
  canonicalLines: string[];
  input: {
    agentId: string;
    method: string;
    pathWithQuery: string;
    timestamp: number;
    nonceBase64: string;
    bodyUtf8: string;
  };
  key: {
    source: string;
    privateSeedHex: string;
    publicKeyBase64: string;
  };
  expected: {
    bodySha256Base64: string;
    canonicalUtf8: string;
    signatureBase64: string;
  };
}

interface EnvelopeFixture {
  contract: string;
  syntheticOnly: boolean;
  algorithms: {
    dekWrap: string;
    payload: string;
    encoding: string;
  };
  keyFixture: {
    seedHex: string;
    publicKeyBase64: string;
    privateKeyBase64: string;
  };
  plaintextUtf8: string;
  dekBase64: string;
  envelope: EncryptedCredential;
  checks: string[];
}

interface McpFixture {
  contract: string;
  syntheticOnly: boolean;
  version: string;
  status: string;
  server: {
    name: string;
    title: string;
  };
  supportedProtocolVersions: string[];
  compatibility: Record<string, string>;
  tools: Array<{
    name: string;
    description: string;
    requiredMethod: string | null;
    inputSchema: Record<string, unknown>;
  }>;
}

const signing = fixture<SigningFixture>('request-signing.json');
const encrypted = fixture<EnvelopeFixture>('encrypted-envelope.json');
const mcp = fixture<McpFixture>('mcp-tools.json');

describe('frozen native runtime vectors in TypeScript', () => {
  it('matches request canonical bytes, body hash, and Ed25519 signature byte-for-byte', async () => {
    expect(fixtureSha256('request-signing.json')).toBe(
      '364a87c2dce913cb470057c548f1ded55fd26ee63209bffddc9d16b2371f563a',
    );
    expect(signing.contract).toBe('agent-request-signing-v1');
    expect(signing.syntheticOnly).toBe(true);
    expect(signing.algorithm).toBe('Ed25519');
    expect(signing.canonicalLines).toEqual([
      'uppercase-method',
      'path-with-query',
      'unix-timestamp-seconds',
      'base64-nonce',
      'base64-sha256-body',
    ]);

    const sodium = await sodiumRuntime();
    const seed = new Uint8Array(Buffer.from(signing.key.privateSeedHex, 'hex'));
    const derived = sodium.crypto_sign_seed_keypair(seed);
    const keypair: SigningKeypair = {
      publicKey: derived.publicKey,
      privateKey: derived.privateKey,
    };

    try {
      expectSensitiveEqual(
        Buffer.from(keypair.publicKey).toString('base64'),
        signing.key.publicKeyBase64,
        'frozen signing public key',
      );
      expectSensitiveEqual(
        sha256Base64(signing.input.bodyUtf8),
        signing.expected.bodySha256Base64,
        'frozen request body digest',
      );

      const canonical = canonicalString({
        method: signing.input.method,
        pathWithQuery: signing.input.pathWithQuery,
        timestamp: signing.input.timestamp,
        nonce: signing.input.nonceBase64,
        body: signing.input.bodyUtf8,
      });
      expectSensitiveEqual(
        Buffer.from(canonical, 'utf8'),
        Buffer.from(signing.expected.canonicalUtf8, 'utf8'),
        'frozen canonical request bytes',
      );

      const headers = await buildSignatureHeaders({
        agentId: signing.input.agentId,
        keypair,
        method: signing.input.method,
        pathWithQuery: signing.input.pathWithQuery,
        timestamp: signing.input.timestamp,
        nonce: signing.input.nonceBase64,
        body: signing.input.bodyUtf8,
      });
      expect(headers['X-Agent-Id']).toBe(signing.input.agentId);
      expect(headers['X-Agent-Timestamp']).toBe(String(signing.input.timestamp));
      expect(headers['X-Agent-Nonce']).toBe(signing.input.nonceBase64);
      expectSensitiveEqual(
        headers['X-Agent-Signature'],
        signing.expected.signatureBase64,
        'frozen request signature',
      );

      const signatureBytes = new Uint8Array(Buffer.from(signing.expected.signatureBase64, 'base64'));
      const canonicalBytes = Buffer.from(canonical, 'utf8');
      expect(sodium.crypto_sign_verify_detached(signatureBytes, canonicalBytes, keypair.publicKey)).toBe(true);

      const tamperedCanonical = canonicalString({
        method: signing.input.method,
        pathWithQuery: signing.input.pathWithQuery,
        timestamp: signing.input.timestamp,
        nonce: signing.input.nonceBase64,
        body: `${signing.input.bodyUtf8} `,
      });
      expect(
        sodium.crypto_sign_verify_detached(
          signatureBytes,
          Buffer.from(tamperedCanonical, 'utf8'),
          keypair.publicKey,
        ),
      ).toBe(false);
    } finally {
      sodium.memzero(seed);
      sodium.memzero(keypair.privateKey);
    }
  });

  it('decrypts the frozen envelope byte-for-byte and fails closed on tampering', async () => {
    expect(fixtureSha256('encrypted-envelope.json')).toBe(
      '98f288511c590e1bc983a0c299748f2ae2f183d056f3b7b182fe6338d97481ee',
    );
    expect(encrypted.contract).toBe('encrypted-credential-envelope-v1');
    expect(encrypted.syntheticOnly).toBe(true);
    expect(encrypted.algorithms).toEqual({
      dekWrap: 'crypto_box_seal',
      payload: 'crypto_secretbox_easy',
      encoding: 'base64-original',
    });
    expect(encrypted.checks).toEqual([
      'unwrap-DEK',
      'decrypt-byte-for-byte',
      'tamper-fails-closed',
    ]);

    const keypair: Keypair = {
      publicKey: new Uint8Array(Buffer.from(encrypted.keyFixture.publicKeyBase64, 'base64')),
      privateKey: new Uint8Array(Buffer.from(encrypted.keyFixture.privateKeyBase64, 'base64')),
    };

    try {
      const plaintext = await decryptCredential(encrypted.envelope, keypair);
      expectSensitiveEqual(
        Buffer.from(plaintext, 'utf8'),
        Buffer.from(encrypted.plaintextUtf8, 'utf8'),
        'frozen decrypted credential bytes',
      );

      await expect(decryptCredential(tamperEnvelope(encrypted.envelope, 'reEncryptedBlob'), keypair))
        .rejects.toThrow();
      await expect(decryptCredential(tamperEnvelope(encrypted.envelope, 'agentWrappedDek'), keypair))
        .rejects.toThrow();
      await expect(decryptCredential(tamperEnvelope(encrypted.envelope, 'nonce'), keypair))
        .rejects.toThrow();

      const wrongKeypair = await generateKeypair();
      try {
        await expect(decryptCredential(encrypted.envelope, wrongKeypair)).rejects.toThrow();
      } finally {
        wrongKeypair.privateKey.fill(0);
      }
    } finally {
      keypair.privateKey.fill(0);
    }
  });

  it('pins the exact public MCP definitions without snapshotting secret vectors', () => {
    expect(fixtureSha256('mcp-tools.json')).toBe(
      'c673d367cbd15d9692fc277000fa77d3efb69824851f1c12efedb241788da2c0',
    );
    expect(mcp.contract).toBe('palladin-agent-mcp-tools');
    expect(mcp.syntheticOnly).toBe(true);
    expect(mcp.version).toBe('1.0.0');
    expect(mcp.status).toBe('frozen');
    expect(mcp.tools.map(({ name }) => name)).toEqual([
      'search_entries',
      'get_credential',
      'exec_with_credential',
      'inject_credential',
      'report_credential_stale',
    ]);
    expect(
      /"(?:privateSeedHex|privateKeyBase64|dekBase64|plaintextUtf8|signatureBase64|agentWrappedDek|reEncryptedBlob)"/
        .test(JSON.stringify(mcp)),
      'public MCP snapshot input must not contain secret-vector fields',
    ).toBe(false);

    // This snapshot contains only public protocol metadata and JSON Schemas. The signing
    // seed, private X25519 key, DEK, envelope, and plaintext fixtures are never included.
    expect(mcp).toMatchSnapshot();
  });
});

function fixture<T>(name: string): T {
  return JSON.parse(fixtureBytes(name).toString('utf8')) as T;
}

function fixtureBytes(name: string): Buffer {
  return readFileSync(new URL(`../../runtime/contracts/v1/${name}`, import.meta.url));
}

function fixtureSha256(name: string): string {
  return createHash('sha256').update(fixtureBytes(name)).digest('hex');
}

async function sodiumRuntime(): Promise<typeof _sodium> {
  await _sodium.ready;
  return _sodium;
}

function tamperEnvelope(
  envelope: EncryptedCredential,
  field: keyof EncryptedCredential,
): EncryptedCredential {
  const bytes = Buffer.from(envelope[field], 'base64');
  const last = bytes.length - 1;
  bytes[last] = (bytes[last] ?? 0) ^ 0x01;
  return { ...envelope, [field]: bytes.toString('base64') };
}
