import { Command } from 'commander';
import { existsSync } from 'fs';
import { loadConfig, saveConfig } from '../config/config.js';
import { loadKeypair, publicKeyBase64 } from '../crypto/keypair.js';
import { ensureSigningKeypair, signingPublicKeyBase64 } from '../crypto/signing.js';
import { detectKeyTier, hasPrivateKey, tierLabel, tierUpgradeHint } from '../crypto/secure-storage.js';
import { registerAgent } from '../http/agent-api.js';
import { ProfilePaths } from '../config/paths.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export function statusCommand(getProfile: GetProfile): Command {
  return new Command('status')
    .description('Show connection and agent registration status')
    .action(async () => {
      const { name, paths } = getProfile();

      const hasKeypair = await hasPrivateKey(name, paths);
      const hasConfig  = existsSync(paths.config);
      const tier       = await detectKeyTier(name, paths);

      console.log(`Profile:  ${name}`);
      console.log('Keypair:  ' + (hasKeypair ? `✓ ${tierLabel(tier)}` : '✗ not found (run: claw-vault init)'));
      console.log('Config:   ' + (hasConfig  ? `✓ ${paths.config}` : '✗ not found (run: claw-vault connect)'));

      if (!hasKeypair || !hasConfig) {
        process.exit(1);
      }

      const config  = loadConfig(paths);
      const keypair = await loadKeypair(name, paths);
      // Backfill / register the signing key for agents enrolled before signing existed (CVT-157).
      const signingKeypair = await ensureSigningKeypair(name, paths);
      const signingPubKey = signingPublicKeyBase64(signingKeypair);
      const signingTier = await detectKeyTier(name, paths, 'signing');

      console.log(`Host:         ${config.host}`);
      console.log(`Key:          ${publicKeyBase64(keypair)}`);
      console.log(`Signing key:  ${signingPubKey}`);
      console.log(`Signing tier: ${tierLabel(signingTier)}`);
      // Hint to upgrade when either key still lives outside the OS keychain.
      const hint = tierUpgradeHint(tier, name) ?? tierUpgradeHint(signingTier, name);
      if (hint) console.log(hint);
      console.log('');

      const result = await registerAgent(config, keypair, undefined, signingPubKey);

      // Persist agentId + signing pubkey so later commands can sign their requests.
      if (result.status === 'pending' || result.status === 'active' || result.status === 'deactivated') {
        if (config.agentId !== result.agentId || config.signingPublicKey !== signingPubKey) {
          saveConfig({ ...config, agentId: result.agentId, signingPublicKey: signingPubKey }, paths);
        }
      }

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
