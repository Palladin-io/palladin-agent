import { Command } from 'commander';
import { saveConfig } from '../config/config.js';
import { loadKeypair, publicKeyBase64 } from '../crypto/keypair.js';

export function connectCommand(): Command {
  return new Command('connect')
    .description('Connect agent to a Claw Vault server')
    .argument('<api-key>', 'API key (must start with cv_)')
    .requiredOption('--host <host>', 'Claw Vault server URL')
    .action((apiKey: string, opts: { host: string }) => {
      if (!apiKey.startsWith('cv_')) {
        console.error('Invalid API key — must start with cv_');
        process.exit(1);
      }

      const keypair = loadKeypair();
      saveConfig({ apiKey, host: opts.host.replace(/\/$/, '') });

      console.log('✓ Connected');
      console.log(`  Host:       ${opts.host}`);
      console.log(`  Public key: ${publicKeyBase64(keypair)}`);
      console.log('');
      console.log('Approve this agent in the Claw Vault panel to activate it.');
    });
}
