import { Command } from 'commander';
import { mkdirSync, rmSync, renameSync, existsSync } from 'fs';
import {
  loadRegistry,
  saveRegistry,
  registryAddAgent,
  registryDeleteAgent,
  registrySetDefault,
  registryRenameAgent,
} from '../config/registry.js';
import { profilePaths, validateProfileName } from '../config/paths.js';
import { generateKeypair, saveKeypair, publicKeyBase64 } from '../crypto/keypair.js';
import { tierLabel, tierUpgradeHint, deletePrivateKey, migrateKeychainEntry } from '../crypto/secure-storage.js';

export function agentsCommand(): Command {
  const cmd = new Command('agents').description('Manage agent profiles');

  cmd.addCommand(
    new Command('list')
      .description('List all agent profiles')
      .action(() => {
        const registry = loadRegistry();
        if (registry.agents.length === 0) {
          console.log('No agents. Run: claw-vault agents create <name>');
          return;
        }
        for (const agent of registry.agents) {
          const marker = agent.name === registry.default ? '* ' : '  ';
          const tag    = agent.name === registry.default ? ' (default)' : '';
          console.log(`${marker}${agent.name}${tag}`);
        }
      }),
  );

  cmd.addCommand(
    new Command('create')
      .description('Create a new agent profile with a fresh keypair')
      .argument('<name>', 'profile name')
      .option('--type <type>', 'agent type/category, free-form e.g. ci, browser, backend')
      .action(async (name: string, opts: { type?: string }) => {
        validateProfileName(name);
        const registry = loadRegistry();
        const isFirst = registry.agents.length === 0;
        let updated;
        try {
          updated = registryAddAgent(registry, name, opts.type);
        } catch (err) {
          console.error(`Error: ${(err as Error).message}`);
          process.exit(1);
        }
        if (isFirst) updated = { ...updated, default: name };

        const paths = profilePaths(name);
        mkdirSync(paths.root, { recursive: true });
        const keypair = await generateKeypair();
        const tier = await saveKeypair(keypair, name, paths);
        saveRegistry(updated);

        console.log(`✓ Agent "${name}" created`);
        console.log(`  Public key:  ${publicKeyBase64(keypair)}`);
        console.log(`  Security:    ${tierLabel(tier)}`);
        const hint = tierUpgradeHint(tier, name);
        if (hint) console.log(hint);
        console.log('');
        console.log(`Next: claw-vault --id ${name} connect <api-key> --host <host>`);
      }),
  );

  cmd.addCommand(
    new Command('delete')
      .description('Delete an agent profile and its keypair')
      .argument('<name>', 'profile name')
      .action(async (name: string) => {
        const registry = loadRegistry();
        let updated;
        try {
          updated = registryDeleteAgent(registry, name);
        } catch (err) {
          console.error(`Error: ${(err as Error).message}`);
          process.exit(1);
        }

        const paths = profilePaths(name);
        await deletePrivateKey(name, paths);
        if (existsSync(paths.root)) {
          rmSync(paths.root, { recursive: true });
        }
        saveRegistry(updated);
        console.log(`✓ Agent "${name}" deleted`);
      }),
  );

  cmd.addCommand(
    new Command('set-default')
      .description('Set an agent profile as the default (used when --id is omitted)')
      .argument('<name>', 'profile name')
      .action((name: string) => {
        const registry = loadRegistry();
        let updated;
        try {
          updated = registrySetDefault(registry, name);
        } catch (err) {
          console.error(`Error: ${(err as Error).message}`);
          process.exit(1);
        }
        saveRegistry(updated);
        console.log(`✓ Default agent set to "${name}"`);
      }),
  );

  cmd.addCommand(
    new Command('rename')
      .description('Rename an agent profile')
      .argument('<old-name>', 'current profile name')
      .argument('<new-name>', 'new profile name')
      .action(async (oldName: string, newName: string) => {
        validateProfileName(newName);
        const registry = loadRegistry();
        let updated;
        try {
          updated = registryRenameAgent(registry, oldName, newName);
        } catch (err) {
          console.error(`Error: ${(err as Error).message}`);
          process.exit(1);
        }

        await migrateKeychainEntry(oldName, newName);
        const oldPaths = profilePaths(oldName);
        const newPaths = profilePaths(newName);
        if (existsSync(oldPaths.root)) {
          renameSync(oldPaths.root, newPaths.root);
        }
        saveRegistry(updated);
        console.log(`✓ Agent "${oldName}" renamed to "${newName}"`);
      }),
  );

  return cmd;
}
