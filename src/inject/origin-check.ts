import { getDomain, parse } from 'tldts';

export type OriginCheckResult =
  | { ok: true; registrableDomain: string }
  | { ok: false; reason: string };

/**
 * Anti-phishing gate for `inject` (CVT-151). Before the CLI types a credential into a page it must
 * prove the page's origin belongs to the same site the entry is bound to. Without this, a
 * prompt-injected agent could navigate to a look-alike phishing page and have `inject` type the
 * real password into it.
 *
 * Rules:
 *  - The page must be served over HTTPS. A login form on http:// can be trivially MITM'd, so we
 *    refuse rather than leak the secret onto a cleartext page. (localhost is allowed for dev.)
 *  - The page's registrable domain (eTLD+1) must equal the entry's. Comparing eTLD+1 — not the full
 *    host — lets `accounts.google.com` match an entry bound to `google.com` while still rejecting
 *    `google.com.evil.tld` and `goggle.com`. The public-suffix list (tldts) makes `foo.co.uk`
 *    compare correctly against multi-label suffixes.
 *  - An entry with no bound domain cannot be matched, so `inject` is refused for it.
 */
export function checkOrigin(currentUrl: string, entryDomain: string | null): OriginCheckResult {
  if (!entryDomain || entryDomain.trim() === '') {
    return { ok: false, reason: 'entry has no bound URL/domain — inject is only allowed for entries with a known site' };
  }

  let parsed: URL;
  try {
    parsed = new URL(currentUrl);
  } catch {
    return { ok: false, reason: `cannot parse current page URL: ${currentUrl}` };
  }

  const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
  if (parsed.protocol !== 'https:' && !isLocalhost) {
    return { ok: false, reason: `refusing to inject on a non-HTTPS page (${parsed.protocol}//) — credentials must not be typed over cleartext` };
  }

  // localhost has no registrable domain (the public-suffix list returns null), so match it by exact
  // hostname against the entry instead — handled before the registrable-domain computation.
  if (isLocalhost) {
    const entryHost = safeHost(entryDomain);
    if (entryHost === 'localhost' || entryHost === '127.0.0.1') {
      return { ok: true, registrableDomain: parsed.hostname };
    }
    return { ok: false, reason: `page is ${parsed.hostname} but entry is bound to ${entryDomain}` };
  }

  // Normalize the entry's bound domain: accept a bare domain ("github.com") or a full URL.
  const entryRegistrable = getDomain(entryDomain) ?? getDomain(`https://${entryDomain}`);
  if (!entryRegistrable) {
    return { ok: false, reason: `entry domain is not a valid registrable domain: ${entryDomain}` };
  }

  const pageInfo = parse(parsed.hostname);
  const pageRegistrable = pageInfo.domain;
  if (!pageRegistrable) {
    return { ok: false, reason: `current page host has no registrable domain: ${parsed.hostname}` };
  }

  if (pageRegistrable.toLowerCase() !== entryRegistrable.toLowerCase()) {
    return {
      ok: false,
      reason: `origin mismatch — page is "${pageRegistrable}" but the credential is bound to "${entryRegistrable}". Refusing to inject (possible phishing).`,
    };
  }

  return { ok: true, registrableDomain: pageRegistrable };
}

function safeHost(value: string): string | null {
  try {
    return new URL(value.includes('://') ? value : `https://${value}`).hostname;
  } catch {
    return null;
  }
}
