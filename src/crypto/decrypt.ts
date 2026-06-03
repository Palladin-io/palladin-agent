import _sodium from 'libsodium-wrappers';
import { Keypair } from './keypair.js';

/**
 * The encrypted envelope as delivered by the backend credential endpoint
 * (`GET /api/agent/vaults/{vaultId}/credentials/{entryId}`). All fields are
 * base64. This is the ONLY ciphertext the server ever returns; it never holds
 * the DEK or any plaintext.
 *
 * Crypto contract (libsodium — identical to web/mobile clients):
 *   agentWrappedDek = crypto_box_seal(agentPublicKey, DEK)   // anonymous sealed box
 *   reEncryptedBlob = crypto_secretbox(DEK, plaintext, nonce) // XSalsa20-Poly1305
 *
 * Agent-side reversal:
 *   DEK       = crypto_box_seal_open(agentPublicKey, agentPrivateKey, agentWrappedDek)
 *   plaintext = crypto_secretbox_open_easy(reEncryptedBlob, nonce, DEK)
 */
export interface EncryptedCredential {
  reEncryptedBlob: string;
  nonce: string;
  agentWrappedDek: string;
}

let sodiumReady: Promise<typeof _sodium> | null = null;

async function getSodium(): Promise<typeof _sodium> {
  if (!sodiumReady) {
    sodiumReady = _sodium.ready.then(() => _sodium);
  }
  return sodiumReady;
}

/**
 * Decrypt a delivered credential locally using the agent's X25519 keypair.
 *
 * Security:
 *  - The agent private key never leaves this process; decryption is entirely local.
 *  - The DEK is unwrapped in-memory only and immediately zeroed after use.
 *  - Never log the return value or any intermediate (DEK, blob, nonce).
 *
 * @returns the plaintext secret as a UTF-8 string.
 * @throws if the sealed box or secretbox fails to open (tampered / wrong key).
 */
export async function decryptCredential(
  envelope: EncryptedCredential,
  keypair: Keypair,
): Promise<string> {
  const sodium = await getSodium();

  const wrappedDek = sodium.from_base64(envelope.agentWrappedDek, sodium.base64_variants.ORIGINAL);
  const blob = sodium.from_base64(envelope.reEncryptedBlob, sodium.base64_variants.ORIGINAL);
  const nonce = sodium.from_base64(envelope.nonce, sodium.base64_variants.ORIGINAL);

  const dek = sodium.crypto_box_seal_open(wrappedDek, keypair.publicKey, keypair.privateKey);
  try {
    const plaintext = sodium.crypto_secretbox_open_easy(blob, nonce, dek);
    return sodium.to_string(plaintext);
  } finally {
    sodium.memzero(dek);
  }
}
