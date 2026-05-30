import { Command } from 'commander';
import { mkdirSync } from 'fs';
import { generateKeypair, saveKeypair, publicKeyBase64 } from '../crypto/keypair.js';
import { loadRegistry, saveRegistry, registryAddAgent } from '../config/registry.js';
import { tierLabel, tierUpgradeHint, hasPrivateKey } from '../crypto/secure-storage.js';
import { ProfilePaths } from '../config/paths.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export function initCommand(getProfile: GetProfile): Command {
  return new Command('init')
    .description('Generate agent keypair for the current profile')
    .option('--force', 'Overwrite existing keypair')
    .action(async (opts: { force?: boolean }) => {
      const { name, paths } = getProfile();

      if (await hasPrivateKey(name, paths) && !opts.force) {
        console.log('Keypair already exists. Use --force to overwrite.');
        return;
      }

      const registry = loadRegistry();
      let effectiveDefault = registry.default;
      if (!registry.agents.some(a => a.name === name)) {
        const isFirst = registry.agents.length === 0;
        let updated = registryAddAgent(registry, name);
        if (isFirst) updated = { ...updated, default: name };
        saveRegistry(updated);
        effectiveDefault = updated.default;
      }

      mkdirSync(paths.root, { recursive: true });
      const keypair = await generateKeypair();
      const tier = await saveKeypair(keypair, name, paths);

      const idFlag = name !== effectiveDefault ? ` --id ${name}` : '';
      console.log('✓ Keypair generated');
      console.log(`  Profile:     ${name}`);
      console.log(`  Public key:  ${publicKeyBase64(keypair)}`);
      console.log(`  Security:    ${tierLabel(tier)}`);
      const hint = tierUpgradeHint(tier, name);
      if (hint) console.log(hint);
      console.log('');
      console.log(`Next: claw-vault${idFlag} connect <api-key> --host <host>`);
    });
}
