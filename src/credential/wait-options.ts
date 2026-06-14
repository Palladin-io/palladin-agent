import { Command } from 'commander';
import { parseDuration } from './duration.js';
import { ProgressMode, WaitCliOptions } from './await-grant.js';

/** Raw option bag as Commander parses the wait flags. */
export interface RawWaitOpts {
  wait?: string | false; // string from --wait <dur>; false from --no-wait
  pollInterval?: string;
  progress?: string;
}

/**
 * Attach the shared approval-wait flags to a `get` / `exec` / `inject` command so the surface stays
 * identical everywhere. See [awaitGrant] for the mechanics.
 */
export function addWaitOptions(cmd: Command): Command {
  return cmd
    .option(
      '--wait <duration>',
      'max time to wait for approval (e.g. 3m, 30s, 0) — default 3m or backend policy',
    )
    .option('--no-wait', 'do not wait — return immediately while approval is still pending')
    .option(
      '--poll-interval <duration>',
      'how often to re-check approval while waiting (e.g. 30s) — default 30s or backend policy',
    )
    .option('--progress <mode>', 'liveness output while waiting: plain | json | none', 'plain');
}

const PROGRESS_MODES: ProgressMode[] = ['plain', 'json', 'none'];

/** Turn Commander's raw flags into a [WaitCliOptions]. Throws on a malformed duration / progress mode. */
export function parseWaitCli(opts: RawWaitOpts): WaitCliOptions {
  const out: WaitCliOptions = {};
  if (opts.wait === false) {
    out.waitMs = 0; // --no-wait
  } else if (typeof opts.wait === 'string') {
    out.waitMs = parseDuration(opts.wait);
  }
  if (opts.pollInterval) {
    out.pollMs = parseDuration(opts.pollInterval);
  }
  if (opts.progress) {
    if (!PROGRESS_MODES.includes(opts.progress as ProgressMode)) {
      throw new Error(`invalid --progress "${opts.progress}" — use plain | json | none`);
    }
    out.progress = opts.progress as ProgressMode;
  }
  return out;
}
