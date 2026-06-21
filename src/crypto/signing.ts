import _sodium from 'libsodium-wrappers';
import { createHash, randomBytes } from 'crypto';
import { ProfilePaths } from '../config/paths.js';
import { loadKey, storeKey, hasKey } from './secure-storage.js';

// Ed25519 request-signing keypair — separate from the X25519 'box' key (X25519 cannot sign).
export interface SigningKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array; // libsodium secret key = seed(32) ++ publicKey(32)
}

let sodiumReady: Promise<typeof _sodium> | null = null;

async function getSodium(): Promise<typeof _sodium> {
  if (!sodiumReady) {
    sodiumReady = _sodium.ready.then(() => _sodium);
  }
  return sodiumReady;
}

export async function generateSigningKeypair(): Promise<SigningKeypair> {
  const sodium = await getSodium();
  const { publicKey, privateKey } = sodium.crypto_sign_keypair();
  return { publicKey, privateKey };
}

export async function saveSigningKeypair(keypair: SigningKeypair, profile: string, paths: ProfilePaths) {
  const base64 = Buffer.from(keypair.privateKey).toString('base64');
  return storeKey(profile, paths, 'signing', base64);
}

export async function loadSigningKeypair(profile: string, paths: ProfilePaths): Promise<SigningKeypair> {
  const { value } = await loadKey(profile, paths, 'signing');
  const privateKey = new Uint8Array(Buffer.from(value, 'base64'));
  if (privateKey.length !== 64) {
    throw new Error(`invalid Ed25519 signing key length (${privateKey.length}, expected 64)`);
  }
  // publicKey is the trailing 32 bytes of the secret key — no derivation needed.
  const publicKey = privateKey.slice(32);
  return { publicKey, privateKey };
}

export async function ensureSigningKeypair(profile: string, paths: ProfilePaths): Promise<SigningKeypair> {
  if (await hasKey(profile, paths, 'signing')) {
    return loadSigningKeypair(profile, paths);
  }
  const keypair = await generateSigningKeypair();
  await saveSigningKeypair(keypair, profile, paths);
  return keypair;
}

export function signingPublicKeyBase64(keypair: SigningKeypair): string {
  return Buffer.from(keypair.publicKey).toString('base64');
}

// 5 LF-joined lines; must match the backend byte-for-byte.
export function canonicalString(input: {
  method: string;
  pathWithQuery: string;
  timestamp: number;
  nonce: string;
  body?: string | Uint8Array | null;
}): string {
  return [
    input.method.toUpperCase(),
    input.pathWithQuery,
    String(input.timestamp),
    input.nonce,
    sha256Base64(input.body ?? ''),
  ].join('\n');
}

// Empty body → sha256 of zero bytes.
export function sha256Base64(body: string | Uint8Array): string {
  const bytes = typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
  return createHash('sha256').update(bytes).digest('base64');
}

export function generateNonce(): string {
  return randomBytes(16).toString('base64');
}

export interface SignatureHeaders {
  'X-Agent-Id': string;
  'X-Agent-Timestamp': string;
  'X-Agent-Nonce': string;
  'X-Agent-Signature': string;
}

export async function buildSignatureHeaders(input: {
  agentId: string;
  keypair: SigningKeypair;
  method: string;
  pathWithQuery: string;
  body?: string | Uint8Array | null;
  timestamp?: number;
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
