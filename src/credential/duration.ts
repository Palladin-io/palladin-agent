/**
 * Parse a human duration into milliseconds. Accepts `ms` / `s` / `m` / `h` suffixes; a bare number
 * is read as seconds (the friendly default for `--wait` / `--poll-interval`). `"0"` → 0 (no wait).
 * Throws on anything else so a typo never silently becomes a surprising timeout.
 */
export function parseDuration(input: string): number {
  const s = input.trim().toLowerCase();
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)?$/.exec(s);
  if (!m) {
    throw new Error(`invalid duration "${input}" — use e.g. 30s, 3m, 0`);
  }
  const n = parseFloat(m[1]!);
  switch (m[2]) {
    case 'ms':
      return Math.round(n);
    case 'm':
      return Math.round(n * 60_000);
    case 'h':
      return Math.round(n * 3_600_000);
    case 's':
    case undefined:
      return Math.round(n * 1_000);
    default:
      // Unreachable given the regex, but keeps the switch exhaustive.
      throw new Error(`invalid duration "${input}"`);
  }
}
