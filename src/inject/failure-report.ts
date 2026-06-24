import { appendFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { parseHTML } from 'linkedom';
import { palladinRoot } from '../config/paths.js';

/**
 * Privacy-safe diagnostics for `inject` failures (CVT-151 follow-up). When the heuristic cannot
 * drive a real login form we record a STRUCTURAL snapshot — never any field values, never the
 * secret — so the detection rules can be improved against real-world misses without ever
 * persisting sensitive data.
 *
 * What is captured per form control: tag, type, and the identification attributes the heuristic
 * keys off (name/id/autocomplete/placeholder/aria-label/data-testid), plus whether it is hidden and
 * whether it sits in a <form>. What is NEVER captured: the element's `value`, the page's path/query
 * (only the origin), cookies, or anything the user typed.
 */
export interface InputSummary {
  tag: string;
  type: string | null;
  name: string | null;
  id: string | null;
  autocomplete: string | null;
  placeholder: string | null;
  ariaLabel: string | null;
  dataTestid: string | null;
  hidden: boolean;
  inForm: boolean;
}

export interface InjectFailureReport {
  timestamp: string;
  reason: string;
  steps: string[];
  vaultId: string;
  entryId: string;
  /** The entry's bound domain (already non-secret metadata). */
  entryDomain: string | null;
  /** Origin only (scheme + host) — never the full URL, which could carry tokens in the path/query. */
  pageOrigin: string | null;
  /** Redacted structural snapshot of the page's form controls — no values. */
  controls: InputSummary[];
}

interface ElementLike {
  readonly tagName: string;
  getAttribute(name: string): string | null;
  closest(selector: string): ElementLike | null;
}
interface DocumentLike {
  querySelectorAll(selector: string): ArrayLike<ElementLike>;
}

/**
 * Extract a redacted, value-free summary of every input/button on the page. Pure — operates on a
 * parsed document so it is unit-testable and provably never reads `value`.
 */
export function summarizeControls(doc: DocumentLike): InputSummary[] {
  const list = doc.querySelectorAll('input, button, [role="button"]');
  const out: InputSummary[] = [];
  for (let i = 0; i < list.length; i++) {
    const el = list[i];
    if (!el) {
      continue;
    }
    const type = (el.getAttribute('type') ?? '').toLowerCase();
    out.push({
      tag: el.tagName.toLowerCase(),
      type: el.getAttribute('type'),
      name: el.getAttribute('name'),
      id: el.getAttribute('id'),
      autocomplete: el.getAttribute('autocomplete'),
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label'),
      dataTestid: el.getAttribute('data-testid'),
      hidden: type === 'hidden' || el.getAttribute('aria-hidden') === 'true',
      inForm: el.closest('form') !== null,
    });
  }
  return out;
}

function safeOrigin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** Build the report from the failure context and the page HTML at failure time. */
export function buildFailureReport(input: {
  reason: string;
  steps: string[];
  vaultId: string;
  entryId: string;
  entryDomain: string | null;
  pageUrl: string;
  html: string;
  now?: Date;
}): InjectFailureReport {
  const { document } = parseHTML(input.html);
  return {
    timestamp: (input.now ?? new Date()).toISOString(),
    reason: input.reason,
    steps: input.steps,
    vaultId: input.vaultId,
    entryId: input.entryId,
    entryDomain: input.entryDomain,
    pageOrigin: safeOrigin(input.pageUrl),
    controls: summarizeControls(document as unknown as DocumentLike),
  };
}

/** Directory where inject failure reports are appended (one JSONL file per day). */
export function failureReportDir(root: string = palladinRoot): string {
  return join(root, 'inject-failures');
}

/**
 * Append a failure report as one JSON line to `~/.palladin/inject-failures/YYYY-MM-DD.jsonl`.
 * Best-effort: a write error never propagates (diagnostics must not break the command). Returns the
 * file path on success, or null when writing failed or capture is disabled.
 *
 * Opt-out: set `PALLADIN_NO_DIAGNOSTICS=1` to disable failure capture entirely.
 */
export function writeFailureReport(report: InjectFailureReport, root?: string): string | null {
  if (process.env['PALLADIN_NO_DIAGNOSTICS'] === '1') {
    return null;
  }
  try {
    const dir = failureReportDir(root);
    mkdirSync(dir, { recursive: true });
    const day = report.timestamp.slice(0, 10);
    const file = join(dir, `${day}.jsonl`);
    appendFileSync(file, `${JSON.stringify(report)}\n`, { encoding: 'utf8', mode: 0o600 });
    return file;
  } catch {
    return null;
  }
}
