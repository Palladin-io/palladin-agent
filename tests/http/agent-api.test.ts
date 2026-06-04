import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { searchEntries, AgentApiError } from '../../src/http/agent-api.js'
import type { AgentConfig } from '../../src/config/config.js'
import type { Keypair } from '../../src/crypto/keypair.js'

const config: AgentConfig = { apiKey: 'test-api-key', host: 'http://localhost:5000' }
const keypair: Keypair = {
  publicKey: new Uint8Array(32).fill(1),
  privateKey: new Uint8Array(32).fill(2),
}

function mockFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response)
}

describe('searchEntries', () => {
  beforeEach(() => vi.restoreAllMocks())
  afterEach(() => vi.unstubAllGlobals())

  it('calls the org-wide agent entries endpoint with the query', async () => {
    const fetchSpy = mockFetch(200, { items: [], nextCursor: null })
    vi.stubGlobal('fetch', fetchSpy)

    await searchEntries(config, keypair, 'facebook')

    const url = fetchSpy.mock.calls[0]![0] as string
    expect(url).toBe('http://localhost:5000/api/agent/entries?query=facebook')

    const init = fetchSpy.mock.calls[0]![1] as RequestInit
    const headers = init.headers as Headers
    expect(headers.get('X-Api-Key')).toBe('test-api-key')
    expect(headers.get('X-Agent-Key')).toBeTruthy()
  })

  it('passes cursor and pageSize when provided', async () => {
    const fetchSpy = mockFetch(200, { items: [], nextCursor: null })
    vi.stubGlobal('fetch', fetchSpy)

    await searchEntries(config, keypair, 'gmail', { cursor: 'abc', pageSize: 10 })

    const url = fetchSpy.mock.calls[0]![0] as string
    expect(url).toContain('query=gmail')
    expect(url).toContain('cursor=abc')
    expect(url).toContain('pageSize=10')
  })

  it('returns the parsed items and nextCursor', async () => {
    const payload = {
      items: [
        { entryId: 'e1', vaultId: 'v1', label: 'Facebook', urlDomain: 'facebook.com', description: null },
      ],
      nextCursor: 'next',
    }
    vi.stubGlobal('fetch', mockFetch(200, payload))

    const result = await searchEntries(config, keypair, 'face')

    expect(result.items).toHaveLength(1)
    expect(result.items[0]!.entryId).toBe('e1')
    expect(result.nextCursor).toBe('next')
  })

  it('throws AgentApiError on a non-2xx response', async () => {
    vi.stubGlobal('fetch', mockFetch(400, {}))

    await expect(searchEntries(config, keypair, 'x')).rejects.toBeInstanceOf(AgentApiError)
  })
})
