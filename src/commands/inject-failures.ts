import { Command } from 'commander';
import { readdirSync, readFileSync, rmSync } from 'fs';
import { join } from 'path';
import { failureReportDir, type InjectFailureReport } from '../inject/failure-report.js';

/**
 * `claw-vault inject-failures` — review the redacted inject failure reports collected locally
 * (CVT-151 follow-up). This is the fast feedback loop for patching unsupported sites: it groups
 * misses by domain so you can see which forms the heuristic could not drive, inspect their (value-
 * free) structure, and turn them into fixtures or selector overrides.
 *
 * Reports are value-free by construction (see failure-report.ts) — no secrets, no field values,
 * origin only. Stored under ~/.claw-vault/inject-failures/*.jsonl.
 */
export function injectFailuresCommand(): Command {
  return new Command('inject-failures')
    .description('Review redacted inject failure diagnostics collected locally (for improving site support)')
    .option('--json', 'output raw aggregated JSON')
    .option('--domain <domain>', 'show only failures for this bound domain')
    .option('--details', 'include the redacted form-control structure for each group')
    .option('--clear', 'delete all collected reports after showing them')
    .action((opts: { json?: boolean; domain?: string; details?: boolean; clear?: boolean }) => {
      const dir = failureReportDir();
      const reports = readReports(dir).filter((r) => !opts.domain || r.entryDomain === opts.domain);

      if (reports.length === 0) {
        console.log('No inject failures recorded.');
        return;
      }

      const groups = groupByDomain(reports);

      if (opts.json) {
        console.log(JSON.stringify(groups, null, 2));
      } else {
        renderGroups(groups, opts.details ?? false);
      }

      if (opts.clear) {
        clearReports(dir);
        console.log('\nCleared all recorded failure reports.');
      }
    });
}

interface DomainGroup {
  domain: string;
  count: number;
  reasons: Record<string, number>;
  lastSeen: string;
  /** A representative redacted control structure from the most recent report. */
  sampleControls: InjectFailureReport['controls'];
  sampleOrigin: string | null;
}

function readReports(dir: string): InjectFailureReport[] {
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith('.jsonl'));
  } catch {
    return [];
  }
  const reports: InjectFailureReport[] = [];
  for (const file of files) {
    const content = readFileSync(join(dir, file), 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        reports.push(JSON.parse(trimmed) as InjectFailureReport);
      } catch {
        // Skip a malformed line rather than abort the whole review.
      }
    }
  }
  return reports;
}

function groupByDomain(reports: InjectFailureReport[]): DomainGroup[] {
  const byDomain = new Map<string, InjectFailureReport[]>();
  for (const r of reports) {
    const key = r.entryDomain ?? '(no domain)';
    const list = byDomain.get(key) ?? [];
    list.push(r);
    byDomain.set(key, list);
  }

  const groups: DomainGroup[] = [];
  for (const [domain, list] of byDomain) {
    const sorted = [...list].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    const reasons: Record<string, number> = {};
    for (const r of list) {
      reasons[r.reason] = (reasons[r.reason] ?? 0) + 1;
    }
    groups.push({
      domain,
      count: list.length,
      reasons,
      lastSeen: sorted[0]!.timestamp,
      sampleControls: sorted[0]!.controls,
      sampleOrigin: sorted[0]!.pageOrigin,
    });
  }
  // Most-failing domains first — that's where patching pays off most.
  return groups.sort((a, b) => b.count - a.count);
}

function renderGroups(groups: DomainGroup[], details: boolean): void {
  const total = groups.reduce((sum, g) => sum + g.count, 0);
  console.log(`${total} inject failure(s) across ${groups.length} domain(s):\n`);

  for (const g of groups) {
    console.log(`${g.domain}  —  ${g.count} failure(s), last ${g.lastSeen}`);
    if (g.sampleOrigin) {
      console.log(`  origin: ${g.sampleOrigin}`);
    }
    for (const [reason, count] of Object.entries(g.reasons)) {
      console.log(`  • ${reason} (${count})`);
    }
    if (details) {
      console.log('  form controls (redacted, no values):');
      for (const c of g.sampleControls) {
        const attrs = [
          c.type && `type=${c.type}`,
          c.name && `name=${c.name}`,
          c.id && `id=${c.id}`,
          c.autocomplete && `autocomplete=${c.autocomplete}`,
          c.placeholder && `placeholder=${JSON.stringify(c.placeholder)}`,
          c.ariaLabel && `aria-label=${JSON.stringify(c.ariaLabel)}`,
          c.dataTestid && `data-testid=${c.dataTestid}`,
          c.hidden && 'hidden',
          !c.inForm && 'no-form',
        ].filter(Boolean).join(' ');
        console.log(`    <${c.tag}> ${attrs}`);
      }
    }
    console.log('');
  }
}

function clearReports(dir: string): void {
  try {
    for (const f of readdirSync(dir).filter((f) => f.endsWith('.jsonl'))) {
      rmSync(join(dir, f), { force: true });
    }
  } catch {
    // nothing to clear
  }
}
