import { Command } from 'commander';
import { apiFetch } from '../http/client.js';

export function listCommand(): Command {
  return new Command('list')
    .description('List accessible vaults')
    .action(async () => {
      const res = await apiFetch('/api/vaults');
      if (!res.ok) {
        console.error(`Error: ${res.status} ${res.statusText}`);
        process.exit(1);
      }
      const data = await res.json() as unknown;
      console.log(JSON.stringify(data, null, 2));
    });
}
