import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/crypto/secure-storage.js', () => ({
  storePrivateKey: vi.fn().mockResolvedValue('keychain'),
  loadPrivateKey:  vi.fn(),
}))

import { generateKeypair, loadKeypair, ensureKeypair, publicKeyBase64 } from '../../src/crypto/keypair.js'
import { storePrivateKey, loadPrivateKey } from '../../src/crypto/secure-storage.js'
import { profilePaths } from '../../src/config/paths.js'

const TEST_PATHS = profilePaths('default')

describe('generateKeypair', () => {
  it('returns a 32-byte private key and 32-byte public key', async () => {
    const kp = await generateKeypair()
    expect(kp.privateKey).toHaveLength(32)
    expect(kp.publicKey).toHaveLength(32)
  })

  it('generates unique keypairs on each call', async () => {
    const a = await generateKeypair()
    const b = await generateKeypair()
    expect(Buffer.from(a.privateKey).toString('hex')).not.toBe(Buffer.from(b.privateKey).toString('hex'))
  })
})

describe('publicKeyBase64', () => {
  it('returns a base64-encoded string', async () => {
    const kp = await generateKeypair()
    const b64 = publicKeyBase64(kp)
    expect(b64).toMatch(/^[A-Za-z0-9+/]+=*$/)
    expect(Buffer.from(b64, 'base64')).toHaveLength(32)
  })
})

describe('loadKeypair', () => {
  beforeEach(() => vi.resetAllMocks())

  it('reconstructs keypair from stored base64 private key', async () => {
    const original = await generateKeypair()
    const base64 = Buffer.from(original.privateKey).toString('base64')

    vi.mocked(loadPrivateKey).mockResolvedValue({ value: base64, tier: 'keychain' })

    const loaded = await loadKeypair('default', TEST_PATHS)

    expect(Buffer.from(loaded.privateKey).toString('base64')).toBe(base64)
    expect(publicKeyBase64(loaded)).toBe(publicKeyBase64(original))
  })

  it('throws when loadPrivateKey throws', async () => {
    vi.mocked(loadPrivateKey).mockRejectedValue(new Error('No keypair found'))
    await expect(loadKeypair('default', TEST_PATHS)).rejects.toThrow('No keypair found')
  })
})

describe('ensureKeypair', () => {
  beforeEach(() => vi.resetAllMocks())

  it('returns existing keypair without generating a new one', async () => {
    const existing = await generateKeypair()
    const base64 = Buffer.from(existing.privateKey).toString('base64')
    vi.mocked(loadPrivateKey).mockResolvedValue({ value: base64, tier: 'file' })

    const result = await ensureKeypair('default', TEST_PATHS)

    expect(vi.mocked(storePrivateKey)).not.toHaveBeenCalled()
    expect(publicKeyBase64(result)).toBe(publicKeyBase64(existing))
  })

  it('generates and stores a new keypair when none exists', async () => {
    vi.mocked(loadPrivateKey).mockRejectedValue(new Error('No keypair found'))

    const result = await ensureKeypair('default', TEST_PATHS)

    expect(result.privateKey).toHaveLength(32)
    expect(vi.mocked(storePrivateKey)).toHaveBeenCalledOnce()
  })
})
