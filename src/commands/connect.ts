import { Command } from 'commander';
import { saveConfig, AgentConfig } from '../config/config.js';
import { ensureKeypair, publicKeyBase64 } from '../crypto/keypair.js';
import { ensureSigningKeypair, signingPublicKeyBase64 } from '../crypto/signing.js';
import { detectKeyTier, tierLabel, tierUpgradeHint } from '../crypto/secure-storage.js';
import { registerAgent } from '../http/agent-api.js';
import { ProfilePaths } from '../config/paths.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export function connectCommand(getProfile: GetProfile): Command {
  return new Command('connect')
    .description('Connect agent to a Claw Vault server and register it')
    .argument('<api-key>', 'API key (must start with cv_)')
    .option('--host <host>', 'Claw Vault server URL', 'https://api.clawvault.io')
    .option('--id <name>', 'Agent display name to register with')
    .action(async (apiKey: string, opts: { host: string; id?: string }) => {
      if (!apiKey.startsWith('cv_')) {
        console.error('Error: invalid API key — must start with cv_');
        process.exit(1);
      }

      const { name, paths } = getProfile();
      const keypair = await ensureKeypair(name, paths);
      // Ed25519 signing key for per-request proof-of-possession (CVT-157). Generated alongside the
      // box key; its PUBLIC key is sent at enrollment so the backend can verify every request.
      const signingKeypair = await ensureSigningKeypair(name, paths);
      const signingPubKey = signingPublicKeyBase64(signingKeypair);

      const config: AgentConfig = { apiKey, host: opts.host.replace(/\/$/, ''), signingPublicKey: signingPubKey };
      saveConfig(config, paths);

      const tier = await detectKeyTier(name, paths);
      console.log(`  Profile:     ${name}`);
      console.log(`  Host:        ${config.host}`);
      console.log(`  Public key:  ${publicKeyBase64(keypair)}`);
      console.log(`  Signing key: ${signingPubKey}`);
      console.log(`  Security:    ${tierLabel(tier)}`);
      const hint = tierUpgradeHint(tier, name);
      if (hint) console.log(hint);
      console.log('');

      const displayName = opts.id ?? (name !== 'default' ? name : undefined);
      const result = await registerAgent(config, keypair, displayName, signingPubKey);

      // Persist the backend agentId so subsequent commands can sign requests (X-Agent-Id +
      // signature canonical). Saved for both pending and active — signing applies once the key is
      // registered, regardless of approval state.
      if (result.status === 'pending' || result.status === 'active' || result.status === 'deactivated') {
        saveConfig({ ...config, agentId: result.agentId }, paths);
      }

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
