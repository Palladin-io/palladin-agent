import { Command } from 'commander';
import { loadConfig } from '../config/config.js';
import { loadKeypair } from '../crypto/keypair.js';
import { ProfilePaths } from '../config/paths.js';
import {
  AgentApiError,
  searchEntries,
  requestAccess,
  getGrantStatus,
  deliverCredential,
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

/** claw-vault request-access <vaultId> <entryId> --reason <reason> */
export function requestAccessCommand(getProfile: GetProfile): Command {
  return new Command('request-access')
    .description('Request user approval to access an entry (creates a pending grant)')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .requiredOption('--reason <reason>', 'justification shown to the approving user')
    .action(async (vaultId: string, entryId: string, opts: { reason: string }) => {
      const { config, keypair } = await profileContext(getProfile);
      try {
        const result = await requestAccess(config, keypair, vaultId, entryId, opts.reason.trim());
        console.log(JSON.stringify(result, null, 2));
        if (result.status === 'Pending') {
          console.log('\nWaiting for user approval. Poll with: claw-vault grant-status ' + result.grantId + ' ' + vaultId);
        }
      } catch (err) {
        fail(describe(err));
      }
    });
}

/** claw-vault grant-status <grantId> <vaultId> */
export function grantStatusCommand(getProfile: GetProfile): Command {
  // The status endpoint is scoped per vault (GET .../vaults/{vaultId}/grants/{grantId}/status),
  // so vaultId is required alongside the grantId.
  return new Command('grant-status')
    .description('Check the status of a previously requested grant')
    .argument('<grantId>', 'grant ID returned by request-access')
    .argument('<vaultId>', 'vault ID the grant belongs to')
    .action(async (grantId: string, vaultId: string) => {
      const { config, keypair } = await profileContext(getProfile);
      try {
        const result = await getGrantStatus(config, keypair, vaultId, grantId);
        console.log(JSON.stringify(result, null, 2));
      } catch (err) {
        fail(describe(err));
      }
    });
}

/** claw-vault retrieve <vaultId> <entryId> — delivery + local X25519 decrypt. */
export function retrieveCommand(getProfile: GetProfile): Command {
  return new Command('retrieve')
    .description('Retrieve and locally decrypt a credential (requires an active grant)')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .action(async (vaultId: string, entryId: string) => {
      const { config, keypair } = await profileContext(getProfile);
      try {
        const envelope = await deliverCredential(config, keypair, vaultId, entryId);
        const secret = await decryptCredential(envelope, keypair);
        // Intentional plaintext output: this is the requested result for the user.
        console.log(JSON.stringify({ entryId: envelope.entryId, label: envelope.label, secret }, null, 2));
      } catch (err) {
        fail(describe(err));
      }
    });
}
