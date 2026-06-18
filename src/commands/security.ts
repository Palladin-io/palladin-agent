import { Command } from 'commander';
import { existsSync } from 'fs';
import { upgradeToKeychain, upgradeKeyToKeychain, detectKeyTier, hasKey } from '../crypto/secure-storage.js';
import { ProfilePaths } from '../config/paths.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export function securityCommand(getProfile: GetProfile): Command {
  const cmd = new Command('security').description('Manage key security settings');

  cmd.addCommand(
    new Command('upgrade')
      .description('Move private key from file to OS keychain')
      .action(async () => {
        const { name, paths } = getProfile();

        const currentTier = await detectKeyTier(name, paths);
        if (currentTier === 'keychain') {
          console.log('Key is already stored in the OS keychain — nothing to do.');
          return;
        }

        if (!existsSync(paths.privateKey)) {
          console.log('No file-based key found. Run: claw-vault init');
          return;
        }

        const success = await upgradeToKeychain(name, paths);
        if (success) {
          console.log('✓ Key moved to OS keychain');
          // Move the Ed25519 signing key too, if it is currently file-based (CVT-157).
          if (await hasKey(name, paths, 'signing')) {
            const signingMoved = await upgradeKeyToKeychain(name, paths, 'signing');
            if (signingMoved) console.log('✓ Signing key moved to OS keychain');
          }
        } else {
          console.log('Keychain unavailable on this system. Install @napi-rs/keyring to enable keychain support.');
        }
      }),
  );

  return cmd;
}
