import { Command } from 'commander';
import { loadConfig } from '../config/config.js';
import { loadKeypair } from '../crypto/keypair.js';
import { ProfilePaths } from '../config/paths.js';
import {
  AgentApiError,
  searchEntries,
  getCredential,
} from '../http/agent-api.js';
import { decryptCredential } from '../crypto/decrypt.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

function fail(message: string): never {
  console.error(`Error: ${message}`);
  process.exit(1);
}

function describe(err: unknown): string {
  if (err instanceof AgentApiError) return err.message;
  return (err as Error).message ?? String(err);
}

async function profileContext(getProfile: GetProfile) {
  const { name, paths } = getProfile();
  const config = loadConfig(paths);
  const keypair = await loadKeypair(name, paths);
  return { config, keypair };
}

/** claw-vault search <query> — discovery (entry metadata, no secrets). */
export function searchCommand(getProfile: GetProfile): Command {
  return new Command('search')
    .description("Search entries by name/url/description across the agent's organization")
    .argument('<query>', 'search term (min 2 chars)')
    .option('--json', 'output raw JSON')
    .action(async (query: string, opts: { json?: boolean }) => {
      const { config, keypair } = await profileContext(getProfile);
      let result;
      try {
        result = await searchEntries(config, keypair, query.trim());
      } catch (err) {
        fail(describe(err));
      }

      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      if (result.items.length === 0) {
        console.log('No entries found.');
        return;
      }

      for (const item of result.items) {
        console.log(`${item.label}`);
        console.log(`  entryId:     ${item.entryId}`);
        console.log(`  vaultId:     ${item.vaultId}`);
        if (item.urlDomain)   console.log(`  url:         ${item.urlDomain}`);
        if (item.description) console.log(`  description: ${item.description}`);
        console.log('');
      }
      if (result.nextCursor) {
        console.log('(more results available — refine your query)');
      }
    });
}

/**
 * claw-vault get <vaultId> <entryId> [--reason <reason>]   (alias: retrieve)
 *
 * One call for the whole flow. On first use (no grant yet) the server creates a
 * pending grant and returns access:"pending"; call again once the user approves
 * to get access:"granted" with the secret decrypted locally.
 */
export function getCredentialCommand(getProfile: GetProfile): Command {
  return new Command('get')
    .alias('retrieve')
    .description('Get a credential — requests a grant on first use, returns the decrypted secret once approved')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .option('--reason <reason>', 'justification shown to the approving user (required on first request)')
    .action(async (vaultId: string, entryId: string, opts: { reason?: string }) => {
      const { config, keypair } = await profileContext(getProfile);

      let result;
      try {
        result = await getCredential(config, keypair, vaultId, entryId, opts.reason?.trim());
      } catch (err) {
        fail(describe(err));
      }

      switch (result.access) {
        case 'granted': {
          const secret = await decryptCredential(result, keypair);
          // Intentional plaintext output: this is the requested result for the user.
          console.log(JSON.stringify({ entryId: result.entryId, label: result.label, secret }, null, 2));
          return;
        }
        case 'pending':
          if (result.created) {
            console.log(`No access yet — access requested (grant ${result.grantId}), awaiting approval. Try again shortly.`);
          } else {
            console.log(`Access request is pending approval (grant ${result.grantId}). Try again shortly.`);
          }
          return;
        default:
          fail(`No access: ${result.access}`);
      }
    });
}
