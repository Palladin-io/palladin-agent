import { x25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from 'crypto';
import { ProfilePaths } from '../config/paths.js';
import { loadPrivateKey, storePrivateKey, hasPrivateKey } from './secure-storage.js';

export interface Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export async function generateKeypair(): Promise<Keypair> {
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

export async function saveKeypair(keypair: Keypair, profile: string, paths: ProfilePaths) {
  const base64 = Buffer.from(keypair.privateKey).toString('base64');
  return storePrivateKey(profile, paths, base64);
}

export async function loadKeypair(profile: string, paths: ProfilePaths): Promise<Keypair> {
  const { value } = await loadPrivateKey(profile, paths);
  const privateKey = new Uint8Array(Buffer.from(value, 'base64'));
  const publicKey  = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

export async function ensureKeypair(profile: string, paths: ProfilePaths): Promise<Keypair> {
  if (await hasPrivateKey(profile, paths)) {
    return loadKeypair(profile, paths);
  }
  const keypair = await generateKeypair();
  const tier = await saveKeypair(keypair, profile, paths);
  console.log(`✓ Keypair generated (${tier === 'keychain' ? 'stored in OS keychain' : paths.root})`);
  return keypair;
}

export function publicKeyBase64(keypair: Keypair): string {
  return Buffer.from(keypair.publicKey).toString('base64');
}
