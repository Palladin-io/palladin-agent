import { Command } from 'commander';
import type { ProfilePaths } from '../config/paths.js';
import { addWaitOptions } from '../credential/wait-options.js';

type GetProfile = () => { name: string; paths: ProfilePaths };

export const INJECT_UNAVAILABLE =
  'Browser injection is disabled because an unauthenticated CDP endpoint can spoof the page origin and receive plaintext. ' +
  'Palladin will enable inject only through a reviewed authenticated browser boundary. ' +
  'No browser endpoint was contacted and no credential was requested or decrypted.';

export const INJECT_UNAVAILABLE_EXIT_CODE = 78;

/**
 * Preserve the public CLI surface while failing before profile resolution, grant delivery, or
 * decryption. CDP has no browser attestation: a fake endpoint controls every URL that the client
 * would inspect, so an origin check over the same channel cannot authorize secret release.
 */
export function injectCommand(_getProfile: GetProfile): Command {
  const cmd = new Command('inject')
    .description('Browser injection is unavailable until an authenticated browser boundary is installed')
    .argument('<vaultId>', 'vault ID')
    .argument('<entryId>', 'entry ID')
    .requiredOption('--cdp <endpoint>', 'deprecated and rejected unauthenticated CDP endpoint')
    .option('--reason <reason>', 'justification shown to the approving user')
    .option('--username-selector <css>', 'reserved for a future reviewed implementation')
    .option('--password-selector <css>', 'reserved for a future reviewed implementation')
    .option('--submit-selector <css>', 'reserved for a future reviewed implementation')
    .option('--no-submit', 'reserved for a future reviewed implementation')
    .option('--page-url <url>', 'reserved for a future reviewed implementation')
    .option('--fill-only', 'reserved for a future reviewed implementation')
    .option('--field <label>', 'reserved for a future reviewed implementation')
    .option('--field-id <uuid>', 'reserved for a future reviewed implementation')
    .option('--verbose', 'reserved for a future reviewed implementation');
  addWaitOptions(cmd);
  return cmd.action(() => {
    console.error(`Error: ${INJECT_UNAVAILABLE} No Agent profile was opened.`);
    process.exitCode = INJECT_UNAVAILABLE_EXIT_CODE;
  });
}
