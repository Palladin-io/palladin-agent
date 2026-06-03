import { describe, it, expect, beforeAll } from 'vitest'
import _sodium from 'libsodium-wrappers'
import { decryptCredential, EncryptedCredential } from '../../src/crypto/decrypt.js'
import { generateKeypair, Keypair } from '../../src/crypto/keypair.js'

let sodium: typeof _sodium

beforeAll(async () => {
  await _sodium.ready
  sodium = _sodium
})

/**
 * Build an envelope exactly like the approving user's client / backend does:
 *   DEK             = random 32 bytes
 *   reEncryptedBlob = crypto_secretbox(DEK, plaintext, nonce)
 *   agentWrappedDek = crypto_box_seal(agentPublicKey, DEK)
 */
function buildEnvelope(plaintext: string, agentPublicKey: Uint8Array): EncryptedCredential {
  const dek = sodium.crypto_secretbox_keygen()
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  const blob = sodium.crypto_secretbox_easy(sodium.from_string(plaintext), nonce, dek)
  const wrappedDek = sodium.crypto_box_seal(dek, agentPublicKey)
  const b64 = (b: Uint8Array) => sodium.to_base64(b, sodium.base64_variants.ORIGINAL)
  return {
    reEncryptedBlob: b64(blob),
    nonce: b64(nonce),
    agentWrappedDek: b64(wrappedDek),
  }
}

describe('decryptCredential', () => {
  it('recovers the plaintext secret from a valid envelope', async () => {
    const kp = await generateKeypair()
    const envelope = buildEnvelope('s3cr3t-db-password!', kp.publicKey)

    const result = await decryptCredential(envelope, kp)

    expect(result).toBe('s3cr3t-db-password!')
  })

  it('handles unicode plaintext', async () => {
    const kp = await generateKeypair()
    const envelope = buildEnvelope('hasło-żółć-🔐', kp.publicKey)

    expect(await decryptCredential(envelope, kp)).toBe('hasło-żółć-🔐')
  })

  it('throws when the sealed DEK was wrapped for a different agent', async () => {
    const owner: Keypair = await generateKeypair()
    const attacker: Keypair = await generateKeypair()
    const envelope = buildEnvelope('top-secret', owner.publicKey)

    await expect(decryptCredential(envelope, attacker)).rejects.toThrow()
  })

  it('throws when the ciphertext blob is tampered with', async () => {
    const kp = await generateKeypair()
    const envelope = buildEnvelope('top-secret', kp.publicKey)
    const tampered = sodium.from_base64(envelope.reEncryptedBlob, sodium.base64_variants.ORIGINAL)
    tampered[0] ^= 0xff
    envelope.reEncryptedBlob = sodium.to_base64(tampered, sodium.base64_variants.ORIGINAL)

    await expect(decryptCredential(envelope, kp)).rejects.toThrow()
  })
})
