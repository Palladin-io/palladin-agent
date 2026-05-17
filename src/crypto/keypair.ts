import sodium from 'libsodium-wrappers';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { paths } from '../config/paths.js';

export interface Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export async function generateKeypair(): Promise<Keypair> {
  await sodium.ready;
  const keypair = sodium.crypto_box_keypair();
  return { publicKey: keypair.publicKey, privateKey: keypair.privateKey };
}

export function saveKeypair(keypair: Keypair): void {
  mkdirSync(paths.root, { recursive: true });
  writeFileSync(paths.privateKey, Buffer.from(keypair.privateKey).toString('base64'), {
    encoding: 'utf8',
    mode: 0o600,
  });
  writeFileSync(paths.publicKey, Buffer.from(keypair.publicKey).toString('base64'), {
    encoding: 'utf8',
    mode: 0o644,
  });
}

export function loadKeypair(): Keypair {
  if (!existsSync(paths.privateKey)) {
    throw new Error(`No keypair found. Run: claw-vault init`);
  }
  const privateKey = new Uint8Array(Buffer.from(readFileSync(paths.privateKey, 'utf8'), 'base64'));
  const publicKey = new Uint8Array(Buffer.from(readFileSync(paths.publicKey, 'utf8'), 'base64'));
  return { publicKey, privateKey };
}

export function publicKeyBase64(keypair: Keypair): string {
  return Buffer.from(keypair.publicKey).toString('base64');
}
