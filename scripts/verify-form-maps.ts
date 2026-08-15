#!/usr/bin/env node
/** Public, no-secret verifier for Form Discovery Maps. It never fills or submits a form. */
import { readFile } from 'node:fs/promises';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { chromium, type Page } from 'playwright';
import { parseFormDiscoveryMap, type FormDiscoveryMap } from '../src/form-map.js';
import { formMapFingerprint } from '../src/form-map-fingerprint.js';
import { popularFormMaps } from '../src/popular-form-maps.js';

type Result = { domain: string; status: 'ok' | 'stale' | 'failed'; checks: string[] };
const navigationTimeoutMs = boundedEnvNumber('PALLADIN_MAP_TIMEOUT_MS', 12_000, 1_000, 60_000);
const settleMs = boundedEnvNumber('PALLADIN_MAP_SETTLE_MS', 2_000, 0, 10_000);

const file = process.argv[2];
export async function run(file: string | undefined): Promise<number> {
if (file === '--catalog') {
  const results: Result[] = [];
  const browser = await chromium.launch({ headless: process.env.PALLADIN_MAP_HEADLESS !== '0' });
  try {
    const selected = process.env.PALLADIN_MAP_DOMAIN === undefined ? popularFormMaps
      : popularFormMaps.filter((map) => map.domain === process.env.PALLADIN_MAP_DOMAIN);
    const concurrency = boundedEnvNumber('PALLADIN_MAP_CONCURRENCY', 2, 1, 5);
    for (let index = 0; index < selected.length; index += concurrency) {
      results.push(...await Promise.all(selected.slice(index, index + concurrency).map((map) => verifyWithRetry(browser, map))));
    }
  }
  finally { await browser.close(); }
  process.stdout.write(`${JSON.stringify({ results }, null, 2)}\n`);
  return results.some((result) => result.status !== 'ok') ? 1 : 0;
}
if (file === undefined) {
  console.error('Usage: npm run verify:form-maps -- path/to/maps.json');
  return 2;
} else {
  const raw = JSON.parse(await readFile(file, 'utf8')) as unknown;
  const maps = Array.isArray(raw) ? raw : [raw];
  const parsed = maps.map(parseFormDiscoveryMap);
  if (parsed.some((map) => map === null)) {
    console.error('Invalid map input: every map must pass the same contract parser as the providers.');
    return 2;
  } else {
    const browser = await chromium.launch({ headless: process.env.PALLADIN_MAP_HEADLESS !== '0' });
    try {
      const results: Result[] = [];
      for (const map of parsed as FormDiscoveryMap[]) results.push(await verify(browser, map));
      process.stdout.write(`${JSON.stringify({ results }, null, 2)}\n`);
      return results.some((result) => result.status !== 'ok') ? 1 : 0;
    } finally { await browser.close(); }
  }
}
}

if (process.env.PALLADIN_VERIFY_FORM_MAPS === '1'
  || (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href)) {
  process.exitCode = await run(file);
}

export async function verify(browser: Awaited<ReturnType<typeof chromium.launch>>, map: FormDiscoveryMap): Promise<Result> {
  const checks: string[] = [];
  const page = await browser.newPage();
  try {
    await page.goto(map.loginUrl, { waitUntil: 'domcontentloaded', timeout: navigationTimeoutMs });
    await page.waitForTimeout(settleMs);
    verifyOrigin(page.url(), map.domain);
    checks.push('origin');
    await dismissOverlays(page, map);
    checks.push('cookie-overlays');
    // A multi-step provider can only expose its first surface before credentials are entered.
    // Validate that public surface; the provider revalidates each subsequent step during Inject.
    for (const step of map.form.steps.slice(0, 1)) {
      for (const field of step.fields) {
        const controls = page.locator(field.selector);
        const count = await controls.count();
        if (count !== 1 || !(await controls.first().isVisible())) throw new Error(`field:${field.entryFieldId}:${count}:${field.selector}`);
        const type = await controls.first().getAttribute('type');
        if (field.control === 'password' && type !== 'password') throw new Error(`control:${field.entryFieldId}`);
      }
      // Some SPAs render the submit control only after a non-secret identifier is entered.
      // It is validated during the real Inject run; the public smoke test must not submit data.
      if (map.form.steps.length === 1 && await page.locator(step.submit.selector).count() < 1) throw new Error('submit-selector');
    }
    checks.push('form-controls');
    const actualFingerprint = formMapFingerprint(map);
    if (map.fingerprint !== actualFingerprint) return { domain: map.domain, status: 'stale', checks: [...checks, 'fingerprint-mismatch'] };
    checks.push('fingerprint');
    return { domain: map.domain, status: 'ok', checks };
  } catch (error) {
    return { domain: map.domain, status: 'failed', checks: [...checks, error instanceof Error ? error.message : 'unknown'] };
  } finally { await page.close(); }
}

async function verifyWithRetry(
  browser: Awaited<ReturnType<typeof chromium.launch>>,
  map: FormDiscoveryMap,
): Promise<Result> {
  let result = await verify(browser, map);
  for (let attempt = 1; attempt < 3 && result.status !== 'ok'; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    result = await verify(browser, map);
  }
  return result;
}

async function dismissOverlays(page: Page, map: FormDiscoveryMap): Promise<void> {
  for (const overlay of map.cookieOverlays ?? []) {
    const visible = (await Promise.all(overlay.selectors.map((selector) => page.locator(selector).isVisible().catch(() => false)))).some(Boolean);
    if (!visible) continue;
    const button = page.locator(overlay.dismiss.selector);
    if (await button.count() !== 1 || !(await button.isVisible()) || !(await button.isEnabled())) throw new Error('cookie-dismiss-control');
    await button.click();
    if (overlay.disappears !== undefined) await page.locator(overlay.disappears).waitFor({ state: 'hidden', timeout: 5_000 });
  }
}

function verifyOrigin(url: string, domain: string): void {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || (parsed.hostname !== domain && !parsed.hostname.endsWith(`.${domain}`))) throw new Error('origin-mismatch');
}

function boundedEnvNumber(name: string, fallback: number, min: number, max: number): number {
  const value = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : fallback;
}

export const fingerprint = formMapFingerprint;
