import { mkdtempSync, rmSync, writeFileSync, existsSync, mkdirSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// vi.mock is hoisted before module-level code, so use vi.hoisted() so the
// factory can reference these variables when the mock module is first imported.
const { mockGetPassword, mockSetPassword, mockDeletePassword, MockEntry } = vi.hoisted(() => {
  const mockGetPassword    = vi.fn<() => string | null>()
  const mockSetPassword    = vi.fn<() => void>()
  const mockDeletePassword = vi.fn<() => void>()
  const MockEntry = vi.fn().mockImplementation(function () {
    return { getPassword: mockGetPassword, setPassword: mockSetPassword, deletePassword: mockDeletePassword }
  })
  return { mockGetPassword, mockSetPassword, mockDeletePassword, MockEntry }
})

vi.mock('@napi-rs/keyring', () => ({ Entry: MockEntry }))

function resetMocks() {
  vi.resetAllMocks()
  MockEntry.mockImplementation(function () {
    return { getPassword: mockGetPassword, setPassword: mockSetPassword, deletePassword: mockDeletePassword }
  })
}

import {
  storePrivateKey,
  loadPrivateKey,
  detectKeyTier,
  hasPrivateKey,
  upgradeToKeychain,
} from '../../src/crypto/secure-storage.js'
import { profilePaths } from '../../src/config/paths.js'

const FAKE_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

describe('storePrivateKey', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cv-sec-'))
    resetMocks()
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('returns "keychain" and does NOT write a file when keychain succeeds', async () => {
    mockSetPassword.mockImplementation(() => { /* ok */ })
    const paths = profilePaths('default')
    // Override root to our temp dir
    const testPaths = { ...paths, root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub') }

    const tier = await storePrivateKey('default', testPaths, FAKE_KEY)

    expect(tier).toBe('keychain')
    expect(existsSync(testPaths.privateKey)).toBe(false)
  })

  it('returns "file" and writes agent.key when keychain throws', async () => {
    mockSetPassword.mockImplementation(() => { throw new Error('keychain unavailable') })
    const testPaths = {
      root: tmpDir,
      privateKey: join(tmpDir, 'agent.key'),
      publicKey:  join(tmpDir, 'agent.pub'),
      config:     join(tmpDir, 'config.json'),
    }

    const tier = await storePrivateKey('default', testPaths, FAKE_KEY)

    expect(tier).toBe('file')
    expect(existsSync(testPaths.privateKey)).toBe(true)
  })

  it('returns "file" when keychain Entry constructor throws', async () => {
    MockEntry.mockImplementation(function () { throw new Error('module not found') })
    const testPaths = {
      root: tmpDir,
      privateKey: join(tmpDir, 'agent.key'),
      publicKey:  join(tmpDir, 'agent.pub'),
      config:     join(tmpDir, 'config.json'),
    }

    const tier = await storePrivateKey('default', testPaths, FAKE_KEY)
    expect(tier).toBe('file')
  })
})

describe('loadPrivateKey', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cv-sec-'))
    resetMocks()
    vi.unstubAllEnvs()
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
    vi.unstubAllEnvs()
  })

  it('returns keychain value with tier "keychain" when keychain has the key', async () => {
    mockGetPassword.mockReturnValue(FAKE_KEY)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }

    const { value, tier } = await loadPrivateKey('default', testPaths)

    expect(value).toBe(FAKE_KEY)
    expect(tier).toBe('keychain')
  })

  it('falls back to env var with tier "env" when keychain returns null', async () => {
    mockGetPassword.mockReturnValue(null)
    vi.stubEnv('CLAW_VAULT_PRIVATE_KEY', FAKE_KEY)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }

    const { value, tier } = await loadPrivateKey('default', testPaths)

    expect(value).toBe(FAKE_KEY)
    expect(tier).toBe('env')
  })

  it('uses profile-specific env var for non-default profiles', async () => {
    mockGetPassword.mockReturnValue(null)
    vi.stubEnv('CLAW_VAULT_PRIVATE_KEY_CURSOR', FAKE_KEY)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }

    const { value, tier } = await loadPrivateKey('cursor', testPaths)

    expect(value).toBe(FAKE_KEY)
    expect(tier).toBe('env')
  })

  it('falls back to file with tier "file" when keychain null and no env var', async () => {
    mockGetPassword.mockReturnValue(null)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    writeFileSync(testPaths.privateKey, FAKE_KEY, { mode: 0o600 })

    const { value, tier } = await loadPrivateKey('default', testPaths)

    expect(value).toBe(FAKE_KEY)
    expect(tier).toBe('file')
  })

  it('throws when no key available in any tier', async () => {
    mockGetPassword.mockReturnValue(null)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }

    await expect(loadPrivateKey('default', testPaths)).rejects.toThrow('No keypair found')
  })
})

describe('detectKeyTier', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cv-sec-'))
    resetMocks()
    vi.unstubAllEnvs()
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
    vi.unstubAllEnvs()
  })

  it('returns "keychain" when keychain has the value', async () => {
    mockGetPassword.mockReturnValue(FAKE_KEY)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    expect(await detectKeyTier('default', testPaths)).toBe('keychain')
  })

  it('returns "env" when keychain null but env var set', async () => {
    mockGetPassword.mockReturnValue(null)
    vi.stubEnv('CLAW_VAULT_PRIVATE_KEY', FAKE_KEY)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    expect(await detectKeyTier('default', testPaths)).toBe('env')
  })

  it('returns "file" when neither keychain nor env var present', async () => {
    mockGetPassword.mockReturnValue(null)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    expect(await detectKeyTier('default', testPaths)).toBe('file')
  })
})

describe('hasPrivateKey', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cv-sec-'))
    resetMocks()
    vi.unstubAllEnvs()
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
    vi.unstubAllEnvs()
  })

  it('returns true when key is in keychain', async () => {
    mockGetPassword.mockReturnValue(FAKE_KEY)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    expect(await hasPrivateKey('default', testPaths)).toBe(true)
  })

  it('returns true when key is in env var', async () => {
    mockGetPassword.mockReturnValue(null)
    vi.stubEnv('CLAW_VAULT_PRIVATE_KEY', FAKE_KEY)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    expect(await hasPrivateKey('default', testPaths)).toBe(true)
  })

  it('returns true when key is in file', async () => {
    mockGetPassword.mockReturnValue(null)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    writeFileSync(testPaths.privateKey, FAKE_KEY)
    expect(await hasPrivateKey('default', testPaths)).toBe(true)
  })

  it('returns false when no key anywhere', async () => {
    mockGetPassword.mockReturnValue(null)
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    expect(await hasPrivateKey('default', testPaths)).toBe(false)
  })
})

describe('upgradeToKeychain', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cv-sec-'))
    resetMocks()
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('moves key from file to keychain and removes the file', async () => {
    mockSetPassword.mockImplementation(() => { /* ok */ })
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    writeFileSync(testPaths.privateKey, FAKE_KEY)

    const success = await upgradeToKeychain('default', testPaths)

    expect(success).toBe(true)
    expect(mockSetPassword).toHaveBeenCalledWith(FAKE_KEY)
    expect(existsSync(testPaths.privateKey)).toBe(false)
  })

  it('returns false when no file exists', async () => {
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    const success = await upgradeToKeychain('default', testPaths)
    expect(success).toBe(false)
  })

  it('returns false and keeps the file when keychain write fails', async () => {
    mockSetPassword.mockImplementation(() => { throw new Error('keychain unavailable') })
    const testPaths = { root: tmpDir, privateKey: join(tmpDir, 'agent.key'), publicKey: join(tmpDir, 'agent.pub'), config: join(tmpDir, 'config.json') }
    writeFileSync(testPaths.privateKey, FAKE_KEY)

    const success = await upgradeToKeychain('default', testPaths)

    expect(success).toBe(false)
    expect(existsSync(testPaths.privateKey)).toBe(true)
  })
})
