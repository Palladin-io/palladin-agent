import { Command } from 'commander';
import { apiFetch } from '../http/client.js';

export function getCommand(): Command {
  return new Command('get')
    .description('Fetch a credential by vault/entry path')
    .argument('<path>', 'vault/entry (e.g. my-vault/db-password)')
    .action(async (path: string) => {
      const [vault, ...rest] = path.split('/');
      if (!vault || rest.length === 0) {
        console.error('Invalid path — expected: <vault>/<entry>');
        process.exit(1);
      }
      const entry = rest.join('/');
      const res = await apiFetch(`/api/vaults/${encodeURIComponent(vault)}/entries/${encodeURIComponent(entry)}`);
      if (!res.ok) {
        console.error(`Error: ${res.status} ${res.statusText}`);
        process.exit(1);
      }
      const data = await res.json() as unknown;
      console.log(JSON.stringify(data, null, 2));
    });
}
