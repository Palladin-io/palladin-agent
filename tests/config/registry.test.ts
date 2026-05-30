import { mkdirSync, writeFileSync, mkdtempSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  registryAddAgent,
  registryDeleteAgent,
  registrySetDefault,
  registryRenameAgent,
  loadRegistry,
  saveRegistry,
  type Registry,
} from '../../src/config/registry.js'

// ── Pure function tests (no I/O) ──────────────────────────────────────────────

describe('registryAddAgent', () => {
  const base: Registry = { default: 'default', agents: [{ name: 'default', createdAt: '2026-01-01T00:00:00.000Z' }] }

  it('adds a new agent', () => {
    const result = registryAddAgent(base, 'cursor')
    expect(result.agents).toHaveLength(2)
    expect(result.agents[1]?.name).toBe('cursor')
  })

  it('does not mutate the original registry', () => {
    registryAddAgent(base, 'cursor')
    expect(base.agents).toHaveLength(1)
  })

  it('throws when agent name already exists', () => {
    expect(() => registryAddAgent(base, 'default')).toThrow('already exists')
  })

  it('stores an ISO createdAt timestamp', () => {
    const result = registryAddAgent(base, 'cursor')
    expect(() => new Date(result.agents[1]!.createdAt)).not.toThrow()
  })
})

describe('registryDeleteAgent', () => {
  const base: Registry = {
    default: 'default',
    agents: [
      { name: 'default', createdAt: '2026-01-01T00:00:00.000Z' },
      { name: 'cursor',  createdAt: '2026-01-01T00:00:00.000Z' },
    ],
  }

  it('removes the named agent', () => {
    const result = registryDeleteAgent(base, 'cursor')
    expect(result.agents.map(a => a.name)).toEqual(['default'])
  })

  it('throws when deleting the default agent', () => {
    expect(() => registryDeleteAgent(base, 'default')).toThrow('default')
  })

  it('throws when agent does not exist', () => {
    expect(() => registryDeleteAgent(base, 'ghost')).toThrow('not found')
  })

  it('does not mutate the original registry', () => {
    registryDeleteAgent(base, 'cursor')
    expect(base.agents).toHaveLength(2)
  })
})

describe('registrySetDefault', () => {
  const base: Registry = {
    default: 'default',
    agents: [
      { name: 'default', createdAt: '2026-01-01T00:00:00.000Z' },
      { name: 'cursor',  createdAt: '2026-01-01T00:00:00.000Z' },
    ],
  }

  it('updates the default pointer', () => {
    const result = registrySetDefault(base, 'cursor')
    expect(result.default).toBe('cursor')
  })

  it('throws when agent does not exist', () => {
    expect(() => registrySetDefault(base, 'ghost')).toThrow('not found')
  })

  it('does not mutate the original registry', () => {
    registrySetDefault(base, 'cursor')
    expect(base.default).toBe('default')
  })
})

describe('registryRenameAgent', () => {
  const base: Registry = {
    default: 'cursor',
    agents: [
      { name: 'default', createdAt: '2026-01-01T00:00:00.000Z' },
      { name: 'cursor',  createdAt: '2026-01-01T00:00:00.000Z' },
    ],
  }

  it('renames the agent', () => {
    const result = registryRenameAgent(base, 'default', 'claude-code')
    expect(result.agents.map(a => a.name)).toContain('claude-code')
    expect(result.agents.map(a => a.name)).not.toContain('default')
  })

  it('updates the default pointer when renaming the default', () => {
    const result = registryRenameAgent(base, 'cursor', 'cursor-v2')
    expect(result.default).toBe('cursor-v2')
  })

  it('preserves the default pointer when renaming a non-default', () => {
    const result = registryRenameAgent(base, 'default', 'claude-code')
    expect(result.default).toBe('cursor')
  })

  it('throws when old name does not exist', () => {
    expect(() => registryRenameAgent(base, 'ghost', 'new')).toThrow('not found')
  })

  it('throws when new name already exists', () => {
    expect(() => registryRenameAgent(base, 'default', 'cursor')).toThrow('already exists')
  })

  it('does not mutate the original registry', () => {
    registryRenameAgent(base, 'default', 'claude-code')
    expect(base.agents[0]?.name).toBe('default')
  })
})

// ── File I/O tests ────────────────────────────────────────────────────────────

describe('loadRegistry / saveRegistry round-trip', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cv-test-'))
    vi.resetModules()
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
    vi.unstubAllEnvs()
  })

  it('saves and loads a registry', async () => {
    vi.stubEnv('CLAW_VAULT_HOME', tmpDir)
    const { saveRegistry, loadRegistry } = await import('../../src/config/registry.js')

    const reg: Registry = {
      default: 'cursor',
      agents: [{ name: 'cursor', createdAt: '2026-05-24T00:00:00.000Z' }],
    }
    saveRegistry(reg)
    const loaded = loadRegistry()
    expect(loaded).toEqual(reg)
  })

  it('returns empty registry when no file exists', async () => {
    vi.stubEnv('CLAW_VAULT_HOME', tmpDir)
    const { loadRegistry } = await import('../../src/config/registry.js')

    const reg = loadRegistry()
    expect(reg.default).toBe('default')
    expect(reg.agents).toHaveLength(0)
  })

  it('auto-migrates legacy layout to agents/default/', async () => {
    vi.stubEnv('CLAW_VAULT_HOME', tmpDir)
    const { loadRegistry } = await import('../../src/config/registry.js')

    // Create legacy files
    writeFileSync(join(tmpDir, 'config.json'), JSON.stringify({ host: 'http://localhost', apiKey: 'cv_test' }))
    writeFileSync(join(tmpDir, 'agent.key'), 'base64key==')
    writeFileSync(join(tmpDir, 'agent.pub'), 'base64pub==')

    const reg = loadRegistry()

    expect(reg.default).toBe('default')
    expect(reg.agents[0]?.name).toBe('default')

    // Legacy files moved to agents/default/
    const { existsSync } = await import('fs')
    expect(existsSync(join(tmpDir, 'agents', 'default', 'config.json'))).toBe(true)
    expect(existsSync(join(tmpDir, 'agents', 'default', 'agent.key'))).toBe(true)
    expect(existsSync(join(tmpDir, 'config.json'))).toBe(false)
  })
})
