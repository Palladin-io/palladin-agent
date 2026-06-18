import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'fs';
import { join } from 'path';
import { ProfilePaths } from '../config/paths.js';

export type StorageTier = 'keychain' | 'env' | 'file';

const SERVICE = 'claw-vault';

/**
 * Two distinct private keys live per profile:
 *   - 'box'     — the X25519 key used to UNWRAP delivered DEKs (crypto_box_seal). Original key.
 *   - 'signing' — the Ed25519 key used to SIGN every agent request (proof-of-possession, CVT-157).
 *
 * They are kept in SEPARATE slots (keychain account / env var / file) so one can be rotated or
 * inspected without touching the other, and so a signing key is never usable as a box key.
 */
export type KeyKind = 'box' | 'signing';

// The 'box' slot keeps its historical names (account ':private-key', file 'agent.key', env
// CLAW_VAULT_PRIVATE_KEY) so existing installs keep working untouched. 'signing' gets its own slot.
function account(profile: string, kind: KeyKind): string {
  return kind === 'box' ? `${profile}:private-key` : `${profile}:signing-key`;
}

function envVarName(profile: string, kind: KeyKind): string {
  const base = kind === 'box' ? 'CLAW_VAULT_PRIVATE_KEY' : 'CLAW_VAULT_SIGNING_KEY';
  const suffix = profile === 'default' ? '' : `_${profile.replace(/-/g, '_').toUpperCase()}`;
  return `${base}${suffix}`;
}

/** Filesystem path for the kind's private/public key inside the profile root. */
function keyFiles(paths: ProfilePaths, kind: KeyKind): { privateKey: string; publicKey: string } {
  if (kind === 'box') {
    return { privateKey: paths.privateKey, publicKey: paths.publicKey };
  }
  return { privateKey: join(paths.root, 'signing.key'), publicKey: join(paths.root, 'signing.pub') };
}

async function keychainGet(profile: string, kind: KeyKind): Promise<string | null> {
  try {
    const { Entry } = await import('@napi-rs/keyring');
    const entry = new Entry(SERVICE, account(profile, kind));
    return entry.getPassword();
  } catch {
    return null;
  }
}

async function keychainSet(profile: string, kind: KeyKind, value: string): Promise<boolean> {
  try {
    const { Entry } = await import('@napi-rs/keyring');
    const entry = new Entry(SERVICE, account(profile, kind));
    entry.setPassword(value);
    return true;
  } catch {
    return false;
  }
}

async function keychainDelete(profile: string, kind: KeyKind): Promise<void> {
  try {
    const { Entry } = await import('@napi-rs/keyring');
    const entry = new Entry(SERVICE, account(profile, kind));
    entry.deletePassword();
  } catch {
    // ignore — key may not exist in keychain
  }
}

/**
 * Store a private key for the given kind. Tries keychain first; falls back to file.
 * Returns the tier that was actually used.
 */
export async function storeKey(
  profile: string,
  paths: ProfilePaths,
  kind: KeyKind,
  base64Key: string,
): Promise<StorageTier> {
  const files = keyFiles(paths, kind);
  const stored = await keychainSet(profile, kind, base64Key);
  if (stored) {
    // Remove plaintext file if it exists — key is now in keychain
    if (existsSync(files.privateKey)) unlinkSync(files.privateKey);
    if (existsSync(files.publicKey))  unlinkSync(files.publicKey);
    return 'keychain';
  }

  mkdirSync(paths.root, { recursive: true });
  writeFileSync(files.privateKey, base64Key, { encoding: 'utf8', mode: 0o600 });
  return 'file';
}

/**
 * Load a private key for the given kind. Priority: keychain → env var → file.
 */
export async function loadKey(
  profile: string,
  paths: ProfilePaths,
  kind: KeyKind,
): Promise<{ value: string; tier: StorageTier }> {
  const fromKeychain = await keychainGet(profile, kind);
  if (fromKeychain) return { value: fromKeychain, tier: 'keychain' };

  const fromEnv = process.env[envVarName(profile, kind)];
  if (fromEnv) return { value: fromEnv, tier: 'env' };

  const files = keyFiles(paths, kind);
  if (existsSync(files.privateKey)) {
    return { value: readFileSync(files.privateKey, 'utf8').trim(), tier: 'file' };
  }

  throw new Error(
    kind === 'box'
      ? 'No keypair found. Run: claw-vault init'
      : 'No signing key found. Run: claw-vault connect to (re)enroll the agent.',
  );
}

/** Detect tier without loading the value (for status display). */
export async function detectKeyTier(profile: string, paths: ProfilePaths, kind: KeyKind = 'box'): Promise<StorageTier> {
  if (await keychainGet(profile, kind)) return 'keychain';
  if (process.env[envVarName(profile, kind)]) return 'env';
  return 'file';
}

/** Returns true if a private key of the kind is available via any tier. */
export async function hasKey(profile: string, paths: ProfilePaths, kind: KeyKind = 'box'): Promise<boolean> {
  if (await keychainGet(profile, kind)) return true;
  if (process.env[envVarName(profile, kind)]) return true;
  return existsSync(keyFiles(paths, kind).privateKey);
}

/** Delete a private key of the kind from all tiers (keychain + file). */
export async function deleteKey(profile: string, paths: ProfilePaths, kind: KeyKind): Promise<void> {
  await keychainDelete(profile, kind);
  const files = keyFiles(paths, kind);
  if (existsSync(files.privateKey)) unlinkSync(files.privateKey);
  if (existsSync(files.publicKey))  unlinkSync(files.publicKey);
}

/** Move a kind's key from file → keychain. Returns false if keychain unavailable or no file. */
export async function upgradeKeyToKeychain(profile: string, paths: ProfilePaths, kind: KeyKind): Promise<boolean> {
  const files = keyFiles(paths, kind);
  if (!existsSync(files.privateKey)) return false;
  const base64Key = readFileSync(files.privateKey, 'utf8').trim();
  const stored = await keychainSet(profile, kind, base64Key);
  if (stored) {
    if (existsSync(files.privateKey)) unlinkSync(files.privateKey);
    if (existsSync(files.publicKey))  unlinkSync(files.publicKey);
    return true;
  }
  return false;
}

// ── Backward-compatible 'box' wrappers ───────────────────────────────────────
// The original API operated only on the box (X25519) key. These thin wrappers keep every existing
// caller and test working while the parameterized functions above serve both kinds.

export const storePrivateKey = (profile: string, paths: ProfilePaths, base64Key: string) =>
  storeKey(profile, paths, 'box', base64Key);

export const loadPrivateKey = (profile: string, paths: ProfilePaths) =>
  loadKey(profile, paths, 'box');

export const hasPrivateKey = (profile: string, paths: ProfilePaths) =>
  hasKey(profile, paths, 'box');

export const upgradeToKeychain = (profile: string, paths: ProfilePaths) =>
  upgradeKeyToKeychain(profile, paths, 'box');

/** Delete BOTH the box and signing keys from all tiers (called on agent delete). */
export async function deletePrivateKey(profile: string, paths: ProfilePaths): Promise<void> {
  await deleteKey(profile, paths, 'box');
  await deleteKey(profile, paths, 'signing');
}

/**
 * Migrate both keychain entries (box + signing) from oldProfile to newProfile (agent rename).
 * No-op for a kind whose key is not in the keychain.
 */
export async function migrateKeychainEntry(oldProfile: string, newProfile: string): Promise<void> {
  for (const kind of ['box', 'signing'] as KeyKind[]) {
    const value = await keychainGet(oldProfile, kind);
    if (value) {
      const migrated = await keychainSet(newProfile, kind, value);
      if (migrated) await keychainDelete(oldProfile, kind);
    }
  }
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
