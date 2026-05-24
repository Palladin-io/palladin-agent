import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync } from 'fs';
import { clawVaultRoot, registryPath, legacyPaths, profilePaths } from './paths.js';

export interface AgentEntry {
  name: string;
  createdAt: string;
}

export interface Registry {
  default: string;
  agents: AgentEntry[];
}

export function loadRegistry(): Registry {
  if (!existsSync(registryPath) && existsSync(legacyPaths.config)) {
    return migrateLegacy();
  }
  if (!existsSync(registryPath)) {
    return { default: 'default', agents: [] };
  }
  return JSON.parse(readFileSync(registryPath, 'utf8')) as Registry;
}

export function saveRegistry(registry: Registry): void {
  mkdirSync(clawVaultRoot, { recursive: true });
  writeFileSync(registryPath, JSON.stringify(registry, null, 2), { encoding: 'utf8', mode: 0o600 });
}

export function registryAddAgent(registry: Registry, name: string): Registry {
  if (registry.agents.some(a => a.name === name)) {
    throw new Error(`Agent "${name}" already exists.`);
  }
  return { ...registry, agents: [...registry.agents, { name, createdAt: new Date().toISOString() }] };
}

export function registryDeleteAgent(registry: Registry, name: string): Registry {
  if (!registry.agents.some(a => a.name === name)) {
    throw new Error(`Agent "${name}" not found.`);
  }
  if (registry.default === name) {
    throw new Error(`Cannot delete the default agent. Run: claw-vault agents set-default <other>`);
  }
  return { ...registry, agents: registry.agents.filter(a => a.name !== name) };
}

export function registrySetDefault(registry: Registry, name: string): Registry {
  if (!registry.agents.some(a => a.name === name)) {
    throw new Error(`Agent "${name}" not found.`);
  }
  return { ...registry, default: name };
}

export function registryRenameAgent(registry: Registry, oldName: string, newName: string): Registry {
  if (!registry.agents.some(a => a.name === oldName)) {
    throw new Error(`Agent "${oldName}" not found.`);
  }
  if (registry.agents.some(a => a.name === newName)) {
    throw new Error(`Agent "${newName}" already exists.`);
  }
  return {
    default: registry.default === oldName ? newName : registry.default,
    agents: registry.agents.map(a => a.name === oldName ? { ...a, name: newName } : a),
  };
}

function migrateLegacy(): Registry {
  const paths = profilePaths('default');
  mkdirSync(paths.root, { recursive: true });
  if (existsSync(legacyPaths.config))     renameSync(legacyPaths.config,     paths.config);
  if (existsSync(legacyPaths.privateKey)) renameSync(legacyPaths.privateKey, paths.privateKey);
  if (existsSync(legacyPaths.publicKey))  renameSync(legacyPaths.publicKey,  paths.publicKey);
  const registry: Registry = {
    default: 'default',
    agents: [{ name: 'default', createdAt: new Date().toISOString() }],
  };
  saveRegistry(registry);
  return registry;
}
