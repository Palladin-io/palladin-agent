import { Command } from 'commander';
import { existsSync } from 'fs';
import { generateKeypair, saveKeypair, publicKeyBase64 } from '../crypto/keypair.js';
import { paths } from '../config/paths.js';

export function initCommand(): Command {
  return new Command('init')
    .description('Generate agent keypair (~/.claw-vault/agent.key)')
    .option('--force', 'Overwrite existing keypair')
    .action(async (opts: { force?: boolean }) => {
      if (existsSync(paths.privateKey) && !opts.force) {
        console.log('Keypair already exists. Use --force to overwrite.');
        return;
      }

      const keypair = await generateKeypair();
      saveKeypair(keypair);

      console.log('✓ Keypair generated');
      console.log(`  Private key: ${paths.privateKey}`);
      console.log(`  Public key:  ${publicKeyBase64(keypair)}`);
      console.log('');
      console.log('Next: claw-vault connect <api-key> --host <host>');
    });
}
