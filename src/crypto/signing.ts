import _sodium from 'libsodium-wrappers';
import { createHash, randomBytes } from 'crypto';
import { ProfilePaths } from '../config/paths.js';
import { loadKey, storeKey, hasKey } from './secure-storage.js';

/**
 * Ed25519 signing keypair (CVT-157). Separate from the X25519 'box' key used to unwrap delivered
 * DEKs — X25519 cannot sign, so request signing (proof-of-possession) needs its own Ed25519 key.
 *
 * The private key never leaves this process. It lives in secure storage next to the box key
 * ('signing' slot). At enrollment the PUBLIC key is sent to the backend, which stores it as
 * Agent.SigningPublicKey and uses it to verify every request's X-Agent-Signature.
 */
export interface SigningKeypair {
  publicKey: Uint8Array;  // 32 bytes
  privateKey: Uint8Array; // 64 bytes (libsodium secret key = seed ++ public key)
}

let sodiumReady: Promise<typeof _sodium> | null = null;

async function getSodium(): Promise<typeof _sodium> {
  if (!sodiumReady) {
    sodiumReady = _sodium.ready.then(() => _sodium);
  }
  return sodiumReady;
}

/** Generate a fresh Ed25519 signing keypair. */
export async function generateSigningKeypair(): Promise<SigningKeypair> {
  const sodium = await getSodium();
  const { publicKey, privateKey } = sodium.crypto_sign_keypair();
  return { publicKey, privateKey };
}

/** Store the signing private key in the 'signing' secure-storage slot. Returns the tier used. */
export async function saveSigningKeypair(keypair: SigningKeypair, profile: string, paths: ProfilePaths) {
  const base64 = Buffer.from(keypair.privateKey).toString('base64');
  return storeKey(profile, paths, 'signing', base64);
}

/**
 * Load the signing keypair from secure storage. A libsodium Ed25519 secret key is `seed(32) ++
 * publicKey(32)`, so the public key is the trailing 32 bytes of the 64-byte secret key — no extra
 * derivation call needed.
 */
export async function loadSigningKeypair(profile: string, paths: ProfilePaths): Promise<SigningKeypair> {
  const { value } = await loadKey(profile, paths, 'signing');
  const privateKey = new Uint8Array(Buffer.from(value, 'base64'));
  if (privateKey.length !== 64) {
    throw new Error(`invalid Ed25519 signing key length (${privateKey.length}, expected 64)`);
  }
  const publicKey = privateKey.slice(32);
  return { publicKey, privateKey };
}

/** Generate + persist a signing keypair if one does not exist; otherwise load the existing one. */
export async function ensureSigningKeypair(profile: string, paths: ProfilePaths): Promise<SigningKeypair> {
  if (await hasKey(profile, paths, 'signing')) {
    return loadSigningKeypair(profile, paths);
  }
  const keypair = await generateSigningKeypair();
  await saveSigningKeypair(keypair, profile, paths);
  return keypair;
}

/** Base64 (standard, with padding) of the signing public key — what enrollment sends to the backend. */
export function signingPublicKeyBase64(keypair: SigningKeypair): string {
  return Buffer.from(keypair.publicKey).toString('base64');
}

/**
 * Build the canonical string the backend signs/verifies byte-for-byte:
 *
 *   METHOD + "\n" + pathWithQuery + "\n" + timestamp + "\n" + nonce + "\n" + base64(sha256(rawBody))
 *
 * - METHOD: upper-case HTTP method.
 * - pathWithQuery: the request path including the query string (no scheme/host), exactly as sent.
 * - timestamp: unix seconds as a decimal string.
 * - nonce: the per-request random base64 nonce.
 * - body hash: standard base64 of SHA-256 over the raw request body bytes; an empty body hashes the
 *   empty byte string (sha256("") → base64).
 */
export function canonicalString(input: {
  method: string;
  pathWithQuery: string;
  timestamp: number;
  nonce: string;
  body?: string | Uint8Array | null;
}): string {
  const bodyHash = sha256Base64(input.body ?? '');
  return [
    input.method.toUpperCase(),
    input.pathWithQuery,
    String(input.timestamp),
    input.nonce,
    bodyHash,
  ].join('\n');
}

/** Standard base64 of SHA-256 over the raw body bytes. Empty body → sha256 of zero bytes. */
export function sha256Base64(body: string | Uint8Array): string {
  const bytes = typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
  return createHash('sha256').update(bytes).digest('base64');
}

/** A fresh 16-byte random nonce, standard base64. */
export function generateNonce(): string {
  return randomBytes(16).toString('base64');
}

export interface SignatureHeaders {
  'X-Agent-Id': string;
  'X-Agent-Timestamp': string;
  'X-Agent-Nonce': string;
  'X-Agent-Signature': string;
}

/**
 * Sign a request and return the four proof-of-possession headers. Detached Ed25519 signature over
 * the canonical string, standard-base64 encoded.
 */
export async function buildSignatureHeaders(input: {
  agentId: string;
  keypair: SigningKeypair;
  method: string;
  pathWithQuery: string;
  body?: string | Uint8Array | null;
  /** Override for tests; defaults to now. */
  timestamp?: number;
  /** Override for tests; defaults to a fresh random nonce. */
  nonce?: string;
}): Promise<SignatureHeaders> {
  const sodium = await getSodium();
  const timestamp = input.timestamp ?? Math.floor(Date.now() / 1000);
  const nonce = input.nonce ?? generateNonce();

  const canonical = canonicalString({
    method: input.method,
    pathWithQuery: input.pathWithQuery,
    timestamp,
    nonce,
    body: input.body ?? '',
  });

  const signature = sodium.crypto_sign_detached(
    Buffer.from(canonical, 'utf8'),
    input.keypair.privateKey,
  );

  return {
    'X-Agent-Id': input.agentId,
    'X-Agent-Timestamp': String(timestamp),
    'X-Agent-Nonce': nonce,
    'X-Agent-Signature': Buffer.from(signature).toString('base64'),
  };
}
