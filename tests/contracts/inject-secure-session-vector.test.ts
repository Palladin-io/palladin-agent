import { createHash, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

import _sodium from 'libsodium-wrappers';
import { describe, expect, it } from 'vitest';

interface SecureFrame {
  protocol: string;
  type: string;
  sessionId: string;
  sequence: string;
  ciphertext: string;
}

interface SecureSessionVector {
  version: number;
  protocol: string;
  extensionOrigin: string;
  syntheticInputs: {
    extensionEphemeralSecretKey: string;
  };
  open: {
    protocol: string;
    type: string;
    extensionNonce: string;
    extensionEphemeralPublicKey: string;
  };
  ready: {
    protocol: string;
    type: string;
    extensionNonce: string;
    hostNonce: string;
    hostEphemeralPublicKey: string;
    hostSigningPublicKey: string;
    signature: string;
    sessionId: string;
  };
  firstHostPlaintext: Record<string, unknown>;
  firstHostFrame: SecureFrame;
  firstExtensionPlaintext: Record<string, unknown>;
  firstExtensionFrame: SecureFrame;
}

const HANDSHAKE_DOMAIN = Buffer.from(
  'palladin.inject-provider.v1\0extension-session-v1\0',
  'utf8',
);
const SESSION_ID_DOMAIN = Buffer.from(
  'palladin.inject-provider.v1\0extension-session-id-v1\0',
  'utf8',
);
const KEY_DERIVATION_INFO = Buffer.from(
  'palladin.inject-provider.v1\0extension-session-keys-v1\0',
  'utf8',
);
const FRAME_AAD_DOMAIN = Buffer.from(
  'palladin.inject-provider.v1\0extension-secure-frame-v1\0',
  'utf8',
);

const vector = JSON.parse(
  readFileSync(
    new URL('../../runtime/contracts/inject-provider/v1/secure-session.json', import.meta.url),
    'utf8',
  ),
) as SecureSessionVector;

function decodeBase64Url(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

function appendBytes(parts: Buffer[], value: Uint8Array): void {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length);
  parts.push(length, Buffer.from(value));
}

function handshakeTranscript(fixture: SecureSessionVector): Buffer {
  const parts = [HANDSHAKE_DOMAIN];
  appendBytes(parts, Buffer.from(fixture.extensionOrigin, 'utf8'));
  appendBytes(parts, decodeBase64Url(fixture.open.extensionNonce));
  appendBytes(parts, decodeBase64Url(fixture.open.extensionEphemeralPublicKey));
  appendBytes(parts, decodeBase64Url(fixture.ready.hostNonce));
  appendBytes(parts, decodeBase64Url(fixture.ready.hostEphemeralPublicKey));
  appendBytes(parts, decodeBase64Url(fixture.ready.hostSigningPublicKey));
  return Buffer.concat(parts);
}

function frameNonce(base: Uint8Array, sequence: bigint): Uint8Array {
  const nonce = new Uint8Array(base);
  const sequenceBytes = Buffer.alloc(8);
  sequenceBytes.writeBigUInt64BE(sequence);
  for (let index = 0; index < sequenceBytes.length; index += 1) {
    const nonceIndex = 16 + index;
    nonce[nonceIndex] = (nonce[nonceIndex] ?? 0) ^ (sequenceBytes[index] ?? 0);
  }
  return nonce;
}

function frameAad(sessionId: string, direction: string, sequence: bigint): Buffer {
  const sequenceBytes = Buffer.alloc(8);
  sequenceBytes.writeBigUInt64BE(sequence);
  return Buffer.concat([
    FRAME_AAD_DOMAIN,
    Buffer.from(sessionId, 'utf8'),
    Buffer.from([0]),
    Buffer.from(direction, 'utf8'),
    Buffer.from([0]),
    sequenceBytes,
  ]);
}

function rustJsonBytes(value: Record<string, unknown>): Buffer {
  const sorted = Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  );
  return Buffer.from(JSON.stringify(sorted), 'utf8');
}

describe('Rust browser-host secure-session vector in TypeScript', () => {
  it('verifies and opens both directions byte-for-byte and rejects tampering', async () => {
    await _sodium.ready;
    const sodium = _sodium;
    const transcript = handshakeTranscript(vector);
    const signature = decodeBase64Url(vector.ready.signature);
    const hostSigningPublicKey = decodeBase64Url(vector.ready.hostSigningPublicKey);
    const extensionSecret = decodeBase64Url(vector.syntheticInputs.extensionEphemeralSecretKey);
    let shared = new Uint8Array();
    let material = new Uint8Array();

    try {
      expect(vector.version).toBe(1);
      expect(vector.protocol).toBe('palladin.inject-provider.v1');
      expect(
        sodium.crypto_sign_verify_detached(signature, transcript, hostSigningPublicKey),
      ).toBe(true);

      const sessionId = createHash('sha256')
        .update(SESSION_ID_DOMAIN)
        .update(transcript)
        .update(signature)
        .digest('base64url');
      expect(sessionId).toBe(vector.ready.sessionId);

      shared = sodium.crypto_scalarmult(
        extensionSecret,
        decodeBase64Url(vector.ready.hostEphemeralPublicKey),
      );
      const salt = createHash('sha256').update(transcript).digest();
      material = new Uint8Array(
        hkdfSync('sha256', shared, salt, KEY_DERIVATION_INFO, 112),
      );

      const hostSequence = BigInt(vector.firstHostFrame.sequence);
      const hostPlaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        decodeBase64Url(vector.firstHostFrame.ciphertext),
        frameAad(vector.ready.sessionId, 'host-to-extension', hostSequence),
        frameNonce(material.slice(64, 88), hostSequence),
        material.slice(0, 32),
      );
      expect(JSON.parse(Buffer.from(hostPlaintext).toString('utf8'))).toEqual(
        vector.firstHostPlaintext,
      );

      const extensionSequence = BigInt(vector.firstExtensionFrame.sequence);
      const extensionCiphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        rustJsonBytes(vector.firstExtensionPlaintext),
        frameAad(vector.ready.sessionId, 'extension-to-host', extensionSequence),
        null,
        frameNonce(material.slice(88, 112), extensionSequence),
        material.slice(32, 64),
      );
      expect(encodeBase64Url(extensionCiphertext)).toBe(
        vector.firstExtensionFrame.ciphertext,
      );

      const tamperedSignature = new Uint8Array(signature);
      tamperedSignature[0] = (tamperedSignature[0] ?? 0) ^ 1;
      expect(
        sodium.crypto_sign_verify_detached(
          tamperedSignature,
          transcript,
          hostSigningPublicKey,
        ),
      ).toBe(false);

      const tamperedCiphertext = decodeBase64Url(vector.firstHostFrame.ciphertext);
      tamperedCiphertext[0] = (tamperedCiphertext[0] ?? 0) ^ 1;
      expect(() =>
        sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          null,
          tamperedCiphertext,
          frameAad(vector.ready.sessionId, 'host-to-extension', hostSequence),
          frameNonce(material.slice(64, 88), hostSequence),
          material.slice(0, 32),
        ),
      ).toThrow();
    } finally {
      sodium.memzero(extensionSecret);
      sodium.memzero(shared);
      sodium.memzero(material);
    }
  });
});
