import { Command } from 'commander';
import { loadConfig } from '../config/config.js';
import { loadKeypair } from '../crypto/keypair.js';
import { apiFetch } from '../http/client.js';
import { ProfilePaths } from '../config/paths.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export function listCommand(getProfile: GetProfile): Command {
  return new Command('list')
    .description('List accessible vaults')
    .action(async () => {
      const { name, paths } = getProfile();
      const config  = loadConfig(paths);
      const keypair = await loadKeypair(name, paths);
      const res = await apiFetch('/api/vaults', config, keypair);
      if (!res.ok) {
        console.error(`Error: ${res.status} ${res.statusText}`);
        process.exit(1);
      }
      const data = await res.json() as unknown;
      console.log(JSON.stringify(data, null, 2));
    });
}
