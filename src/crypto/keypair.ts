import { x25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from 'crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { execSync } from 'child_process';
import { platform } from 'os';
import { paths } from '../config/paths.js';

export interface Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export async function generateKeypair(): Promise<Keypair> {
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
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
  restrictPrivateKeyPermissions();
}

function restrictPrivateKeyPermissions(): void {
  if (platform() !== 'win32') return;

  try {
    // Remove inherited permissions, grant only current user full control
    execSync(
      `icacls "${paths.privateKey}" /inheritance:r /grant:r "%USERNAME%:F"`,
      { stdio: 'ignore' },
    );
  } catch {
    console.warn(`  Warning: could not restrict permissions on ${paths.privateKey}`);
    console.warn('  Protect this file manually — it contains your private key.');
  }
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
