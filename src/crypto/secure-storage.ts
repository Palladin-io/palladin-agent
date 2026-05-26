import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'fs';
import { ProfilePaths } from '../config/paths.js';

export type StorageTier = 'keychain' | 'env' | 'file';

const SERVICE = 'claw-vault';

function account(profile: string): string {
  return `${profile}:private-key`;
}

function envVarName(profile: string): string {
  const suffix = profile === 'default' ? '' : `_${profile.replace(/-/g, '_').toUpperCase()}`;
  return `CLAW_VAULT_PRIVATE_KEY${suffix}`;
}

async function keychainGet(profile: string): Promise<string | null> {
  try {
    const { Entry } = await import('@napi-rs/keyring');
    const entry = new Entry(SERVICE, account(profile));
    return entry.getPassword();
  } catch {
    return null;
  }
}

async function keychainSet(profile: string, value: string): Promise<boolean> {
  try {
    const { Entry } = await import('@napi-rs/keyring');
    const entry = new Entry(SERVICE, account(profile));
    entry.setPassword(value);
    return true;
  } catch {
    return false;
  }
}

async function keychainDelete(profile: string): Promise<void> {
  try {
    const { Entry } = await import('@napi-rs/keyring');
    const entry = new Entry(SERVICE, account(profile));
    entry.deletePassword();
  } catch {
    // ignore — key may not exist in keychain
  }
}

/**
 * Store private key. Tries keychain first; falls back to file.
 * Returns the tier that was actually used.
 */
export async function storePrivateKey(
  profile: string,
  paths: ProfilePaths,
  base64Key: string,
): Promise<StorageTier> {
  const stored = await keychainSet(profile, base64Key);
  if (stored) {
    // Remove plaintext file if it exists — key is now in keychain
    if (existsSync(paths.privateKey)) unlinkSync(paths.privateKey);
    if (existsSync(paths.publicKey))  unlinkSync(paths.publicKey);
    return 'keychain';
  }

  mkdirSync(paths.root, { recursive: true });
  writeFileSync(paths.privateKey, base64Key, { encoding: 'utf8', mode: 0o600 });
  return 'file';
}

/**
 * Load private key. Priority: keychain → env var → file.
 */
export async function loadPrivateKey(
  profile: string,
  paths: ProfilePaths,
): Promise<{ value: string; tier: StorageTier }> {
  const fromKeychain = await keychainGet(profile);
  if (fromKeychain) return { value: fromKeychain, tier: 'keychain' };

  const envName = envVarName(profile);
  const fromEnv = process.env[envName];
  if (fromEnv) return { value: fromEnv, tier: 'env' };

  if (existsSync(paths.privateKey)) {
    return { value: readFileSync(paths.privateKey, 'utf8').trim(), tier: 'file' };
  }

  throw new Error('No keypair found. Run: claw-vault init');
}

/**
 * Detect tier without loading the actual value (for status display).
 */
export async function detectKeyTier(profile: string, paths: ProfilePaths): Promise<StorageTier> {
  if (await keychainGet(profile)) return 'keychain';
  if (process.env[envVarName(profile)]) return 'env';
  return 'file';
}

/** Delete the private key from all tiers (keychain + file). Called on agent delete. */
export async function deletePrivateKey(profile: string, paths: ProfilePaths): Promise<void> {
  await keychainDelete(profile);
  if (existsSync(paths.privateKey)) unlinkSync(paths.privateKey);
  if (existsSync(paths.publicKey))  unlinkSync(paths.publicKey);
}

/**
 * Migrate keychain entry from oldProfile to newProfile.
 * Called on agent rename. No-op if key is not in keychain.
 */
export async function migrateKeychainEntry(oldProfile: string, newProfile: string): Promise<void> {
  const value = await keychainGet(oldProfile);
  if (value) {
    await keychainSet(newProfile, value);
    await keychainDelete(oldProfile);
  }
}

/** Returns true if a private key is available via any tier. */
export async function hasPrivateKey(profile: string, paths: ProfilePaths): Promise<boolean> {
  if (await keychainGet(profile)) return true;
  if (process.env[envVarName(profile)]) return true;
  return existsSync(paths.privateKey);
}

/**
 * Move key from file → keychain. Returns false if keychain unavailable.
 */
export async function upgradeToKeychain(profile: string, paths: ProfilePaths): Promise<boolean> {
  if (!existsSync(paths.privateKey)) return false;
  const base64Key = readFileSync(paths.privateKey, 'utf8').trim();
  const stored = await keychainSet(profile, base64Key);
  if (stored) {
    if (existsSync(paths.privateKey)) unlinkSync(paths.privateKey);
    if (existsSync(paths.publicKey))  unlinkSync(paths.publicKey);
    return true;
  }
  return false;
}

export function tierLabel(tier: StorageTier): string {
  switch (tier) {
    case 'keychain': return '🔒 Keychain  (encrypted at rest by OS)';
    case 'env':      return '⚠️  Env var   (no disk, process-scoped)';
    case 'file':     return '⚠️  File      (plaintext, chmod 600)';
  }
}

export function tierUpgradeHint(tier: StorageTier, profile: string): string | null {
  if (tier === 'keychain') return null;
  const idFlag = profile !== 'default' ? ` --id ${profile}` : '';
  return `  Tip: claw-vault${idFlag} security upgrade  →  move keys to OS keychain`;
}
