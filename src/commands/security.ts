import { Command } from 'commander';
import { upgradeToKeychain } from '../crypto/secure-storage.js';
import { ProfilePaths } from '../config/paths.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export function securityCommand(getProfile: GetProfile): Command {
  const cmd = new Command('security').description('Manage key security settings');

  cmd.addCommand(
    new Command('upgrade')
      .description('Move private key from file to OS keychain')
      .action(async () => {
        const { name, paths } = getProfile();
        const success = await upgradeToKeychain(name, paths);
        if (success) {
          console.log('✓ Key moved to OS keychain');
        } else {
          console.log('Key is already in keychain, or no file-based key found, or keychain unavailable.');
        }
      }),
  );

  return cmd;
}
