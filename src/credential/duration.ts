/**
 * Parse a human duration into milliseconds. Accepts `ms` / `s` / `m` / `h` suffixes; a bare number
 * is read as seconds (the friendly default for `--wait` / `--poll-interval`). `"0"` → 0 (no wait).
 * Throws on anything else so a typo never silently becomes a surprising timeout.
 */
export function parseDuration(input: string): number {
  const s = input.trim().toLowerCase();
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)?$/.exec(s);
  if (!m) {
    throw new Error(`invalid duration "${input}" - use e.g. 30s, 3m, 0`);
  }
  const n = parseFloat(m[1]!);
  let milliseconds: number;
  switch (m[2]) {
    case 'ms':
      milliseconds = Math.round(n);
      break;
    case 'm':
      milliseconds = Math.round(n * 60_000);
      break;
    case 'h':
      milliseconds = Math.round(n * 3_600_000);
      break;
    case 's':
    case undefined:
      milliseconds = Math.round(n * 1_000);
      break;
    default:
      // Unreachable given the regex, but keeps the switch exhaustive.
      throw new Error(`invalid duration "${input}"`);
  }
  if (!Number.isSafeInteger(milliseconds)) {
    throw new Error(`invalid duration "${input}"`);
  }
  return milliseconds;
}
