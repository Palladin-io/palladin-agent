import { Command } from 'commander';
import { saveConfig } from '../config/config.js';
import { ensureKeypair, publicKeyBase64 } from '../crypto/keypair.js';
import { registerAgent } from '../http/agent-api.js';
import { ProfilePaths } from '../config/paths.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export function connectCommand(getProfile: GetProfile): Command {
  return new Command('connect')
    .description('Connect agent to a Claw Vault server and register it')
    .argument('<api-key>', 'API key (must start with cv_)')
    .requiredOption('--host <host>', 'Claw Vault server URL')
    .action(async (apiKey: string, opts: { host: string }) => {
      if (!apiKey.startsWith('cv_')) {
        console.error('Error: invalid API key — must start with cv_');
        process.exit(1);
      }

      const { name, paths } = getProfile();
      const keypair = await ensureKeypair(paths);
      const config = { apiKey, host: opts.host.replace(/\/$/, '') };
      saveConfig(config, paths);

      console.log(`  Profile:    ${name}`);
      console.log(`  Host:       ${config.host}`);
      console.log(`  Public key: ${publicKeyBase64(keypair)}`);
      console.log('');

      const result = await registerAgent(config, keypair);

      switch (result.status) {
        case 'pending':
          console.log('✓ Agent registered — awaiting approval');
          console.log(`  Agent ID: ${result.agentId}`);
          console.log('');
          console.log('Approve this agent in the Claw Vault panel to activate it.');
          break;

        case 'active':
          console.log('✓ Agent active');
          console.log(`  Agent ID: ${result.agentId}`);
          if (result.name) console.log(`  Name:     ${result.name}`);
          break;

        case 'deactivated':
          console.warn('⚠ Agent is deactivated');
          console.warn(`  Agent ID: ${result.agentId}`);
          console.warn('  Re-activate this agent in the Claw Vault panel.');
          process.exit(1);
          break;

        case 'invalid_key':
          console.error('Error: API key is invalid or revoked');
          process.exit(1);
          break;

        case 'unreachable':
          console.warn(`⚠ Config saved but could not reach server: ${result.error}`);
          console.warn('  Run `claw-vault status` once the server is reachable.');
          break;
      }
    });
}
