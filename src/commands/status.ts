import { Command } from 'commander';
import { existsSync } from 'fs';
import { loadConfig } from '../config/config.js';
import { loadKeypair, publicKeyBase64 } from '../crypto/keypair.js';
import { registerAgent } from '../http/agent-api.js';
import { ProfilePaths } from '../config/paths.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export function statusCommand(getProfile: GetProfile): Command {
  return new Command('status')
    .description('Show connection and agent registration status')
    .action(async () => {
      const { name, paths } = getProfile();

      const hasKeypair = existsSync(paths.privateKey);
      const hasConfig  = existsSync(paths.config);

      console.log(`Profile:  ${name}`);
      console.log('Keypair:  ' + (hasKeypair ? `✓ ${paths.privateKey}` : '✗ not found (run: claw-vault init)'));
      console.log('Config:   ' + (hasConfig  ? `✓ ${paths.config}`     : '✗ not found (run: claw-vault connect)'));

      if (!hasKeypair || !hasConfig) {
        process.exit(1);
      }

      const config  = loadConfig(paths);
      const keypair = loadKeypair(paths);

      console.log(`Host:     ${config.host}`);
      console.log(`Key:      ${publicKeyBase64(keypair)}`);
      console.log('');

      const result = await registerAgent(config, keypair);

      switch (result.status) {
        case 'pending':
          console.log('Agent:    ⏳ pending approval');
          console.log(`          ID: ${result.agentId}`);
          console.log('          Approve in the Claw Vault panel to activate.');
          break;

        case 'active':
          console.log('Agent:    ✓ active');
          console.log(`          ID:           ${result.agentId}`);
          if (result.name) console.log(`          Backend name: ${result.name}`);
          console.log(`          Local alias:  ${name}`);
          break;

        case 'deactivated':
          console.log('Agent:    ✗ deactivated');
          console.log(`          ID: ${result.agentId}`);
          break;

        case 'invalid_key':
          console.log('Agent:    ✗ API key invalid or revoked');
          process.exit(1);
          break;

        case 'unreachable':
          console.log(`Agent:    ✗ server unreachable (${result.error})`);
          process.exit(1);
          break;
      }
    });
}
