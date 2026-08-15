#!/usr/bin/env node

import { randomBytes } from 'node:crypto';
import type { ChildProcess } from 'node:child_process';

import { createConnection } from '@playwright/mcp';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { chromium, type BrowserContext, type Locator, type Page } from 'playwright';
import { getDomain } from 'tldts';
import {
  injectFormJsonSchema,
  parseInjectForm,
  parseInjectValues,
  type InjectControl,
  type InjectFieldValue,
  type InjectFormDefinition,
} from '@palladin/agent/inject-contract';
import { parseFormDiscoveryMap, type FormDiscoveryMap } from '@palladin/agent/form-map';

import { captureRuntimeStderr, spawnAgentRuntime } from './agent-runtime.js';

const INJECT_PROTOCOL = 'palladin.inject-provider.v1';
const MAX_PROVIDER_FRAME_BYTES = 256 * 1024;
const PROFILE_ARGUMENT = process.env.PALLADIN_AGENT_PROFILE?.trim();

export interface InjectArguments {
  /** Provider-owned Palladin profile. This is never a credential value. */
  profile?: string;
  vaultId: string;
  entryId: string;
  reason?: string;
  wait?: string;
  noWait?: boolean;
  pollInterval?: string;
  form: InjectFormDefinition;
  formMap?: unknown;
}

export interface ProviderCredential {
  protocol: typeof INJECT_PROTOCOL;
  type: 'credential';
  provider: 'playwright';
  nonce: string;
  transactionId: string;
  grantId: string;
  entryId: string;
  expectedDomain: string;
  form: InjectFormDefinition;
  values: InjectFieldValue[];
}

const injectTool: Tool = {
  name: 'inject_credential',
  title: 'Inject Palladin credential',
  description: 'Request an Inject grant and fill the current Playwright page without returning the credential to the model.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      vaultId: { type: 'string', minLength: 1, maxLength: 256 },
      entryId: { type: 'string', minLength: 1, maxLength: 256 },
      reason: { type: 'string', maxLength: 4096 },
      wait: { type: 'string', maxLength: 32 },
      noWait: { type: 'boolean' },
      pollInterval: { type: 'string', maxLength: 32 },
      form: injectFormJsonSchema,
      formMap: { type: 'object', additionalProperties: true },
    },
    required: ['vaultId', 'entryId', 'form'],
  },
};

export async function main(): Promise<void> {
  const browser = await chromium.launch({
    channel: process.env.PALLADIN_PLAYWRIGHT_CHANNEL ?? 'chrome',
    headless: process.env.PALLADIN_PLAYWRIGHT_HEADLESS === '1',
  });
  const context = await browser.newContext();
  const upstream = await createConnection({
    browser: { isolated: true },
    capabilities: ['core'],
    saveSession: false,
    imageResponses: 'omit',
  }, async (): Promise<BrowserContext> => context);
  const [upstreamServerTransport, upstreamClientTransport] = InMemoryTransport.createLinkedPair();
  await upstream.connect(upstreamServerTransport);
  const playwrightClient = new Client(
    { name: 'palladin-playwright-provider', version: '0.1.0' },
    { capabilities: {} },
  );
  await playwrightClient.connect(upstreamClientTransport);

  const server = new Server(
    { name: 'Palladin Playwright', version: '0.1.0' },
    {
      capabilities: { tools: {} },
      instructions: 'Prepare the public login surface before Inject: dismiss cookie/consent overlays, complete allowed public navigation and any human CAPTCHA, then inspect the visible controls and build the complete value-free multi-step form. Only after the page is ready call inject_credential; it never returns field values.',
    },
  );
  let injectionActive = false;
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const listed = await playwrightClient.listTools();
    return {
      ...listed,
      tools: [...listed.tools.filter((tool) => tool.name !== injectTool.name), injectTool],
    };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    if (injectionActive) return toolError('A trusted Inject operation is already active.');
    if (request.params.name !== injectTool.name) {
      return await playwrightClient.callTool(request.params) as CallToolResult;
    }
    const args = parseInjectArguments(request.params.arguments);
    if (args === null) return toolError('Inject arguments are invalid.');
    const pages = context.pages();
    const page = pages.at(-1);
    if (page === undefined) return toolError('No active Playwright page is available.');
    injectionActive = true;
    try {
      return await injectWithPalladin(page, args);
    } finally {
      injectionActive = false;
    }
  });

  const shutdown = async (): Promise<void> => {
    await server.close().catch(() => undefined);
    await playwrightClient.close().catch(() => undefined);
    await upstream.close().catch(() => undefined);
    await context.close().catch(() => undefined);
    await browser.close().catch(() => undefined);
  };
  process.once('SIGINT', () => void shutdown());
  process.once('SIGTERM', () => void shutdown());
  await server.connect(new StdioServerTransport());
}

export async function injectWithPalladin(
  page: Page,
  args: InjectArguments,
  spawnRuntime: typeof spawnAgentRuntime = spawnAgentRuntime,
): Promise<CallToolResult> {
  if (args.formMap !== undefined) {
    const map = parseFormDiscoveryMap(args.formMap);
    if (map === null || JSON.stringify(map.form) !== JSON.stringify(args.form)) return toolError('Form discovery map does not match the Inject form.');
    await applyCookieOverlays(page, map);
  }
  const nonce = randomBytes(32).toString('hex');
  const runtimeArgs: string[] = [];
  const profile = args.profile?.trim() || PROFILE_ARGUMENT;
  if (profile) runtimeArgs.push('--id', profile);
  runtimeArgs.push(
    'inject',
    args.vaultId,
    args.entryId,
    '--provider',
    'playwright',
    '--provider-transport-stdio',
  );
  if (args.reason !== undefined) runtimeArgs.push('--reason', args.reason);
  if (args.noWait === true) runtimeArgs.push('--no-wait');
  else if (args.wait !== undefined) runtimeArgs.push('--wait', args.wait);
  if (args.pollInterval !== undefined) runtimeArgs.push('--poll-interval', args.pollInterval);

  let child: ChildProcess | undefined;
  let credential: ProviderCredential | undefined;
  let stderrCapture: ReturnType<typeof captureRuntimeStderr> | undefined;
  let failureStage = 'runtime-start';
  try {
    child = spawnRuntime(runtimeArgs);
    if (child.stderr === null) throw new Error('runtime stderr unavailable');
    stderrCapture = captureRuntimeStderr(child.stderr);
    const stdin = child.stdin;
    const stdout = child.stdout;
    if (stdin === null || stdout === null) throw new Error('provider transport unavailable');
    failureStage = 'runtime-handshake';
    stdin.write(`${JSON.stringify({
      protocol: INJECT_PROTOCOL,
      type: 'open',
      provider: 'playwright',
      nonce,
      currentUrl: page.url(),
      form: args.form,
    })}\n`);
    const parsedCredential = parseProviderCredentialDiagnostic(
      await readOneLine(stdout), nonce, args.entryId, args.form,
    );
    if (parsedCredential.credential === null) {
      throw new Error(parsedCredential.code ?? 'provider-frame-unexpected-fields');
    }
    const received = parsedCredential.credential;
    credential = received;
    failureStage = 'origin-verification';
    verifyDomain(page.url(), credential.expectedDomain);
    failureStage = 'form-fill';
    const outcome = await fillAndSubmit(page, credential);
    failureStage = 'runtime-result';
    stdin.end(`${JSON.stringify({
      protocol: INJECT_PROTOCOL,
      type: 'result',
      nonce,
      transactionId: credential.transactionId,
      outcome,
    })}\n`);
    const exitCode = await waitForExit(child);
    if (outcome !== 'injected' || exitCode !== 0) {
      return toolError(
        `The Playwright provider did not complete Inject (outcome=${outcome}, exit=${exitCode ?? 'unknown'}).`,
      );
    }
    return {
      content: [{ type: 'text', text: JSON.stringify({ status: 'injected', provider: 'playwright' }) }],
      isError: false,
    };
  } catch (error) {
    const stderr = stderrCapture === undefined ? '' : await Promise.race([
      stderrCapture.done,
      new Promise<string>((resolve) => setTimeout(() => resolve(''), 250)),
    ]);
    const failureCode = safeFailureCode(error, stderr);
    process.stderr.write(`[palladin-playwright] failure stage=${failureStage} code=${failureCode}\n`);
    if (child?.stdin !== null && child?.stdin !== undefined && credential !== undefined) {
      child.stdin.end(`${JSON.stringify({
        protocol: INJECT_PROTOCOL,
        type: 'result',
        nonce,
        transactionId: credential.transactionId,
        outcome: providerOutcomeForError(error),
      })}\n`);
    }
    child?.kill();
    return toolError(
      `The trusted Playwright Inject provider failed at ${failureStage} (${failureCode}).`,
    );
  } finally {
    if (credential !== undefined) {
      for (const field of credential.values) field.value = '';
      credential.values.length = 0;
    }
    credential = undefined;
  }
}

/** Dismisses only public, same-origin cookie/CMP controls declared by a validated map. */
export async function applyCookieOverlays(page: Page, map: FormDiscoveryMap): Promise<void> {
  for (const overlay of map.cookieOverlays ?? []) {
    const visible = (await Promise.all(overlay.selectors.map((selector) => page.locator(selector).isVisible().catch(() => false)))
      ).some(Boolean);
    if (!visible) continue;
    const button = page.locator(overlay.dismiss.selector);
    const count = await button.count();
    if (count !== 1 || !(await button.isVisible()) || !(await button.isEnabled())) continue;
    await button.click();
    if (overlay.disappears !== undefined) await page.locator(overlay.disappears).waitFor({ state: 'hidden', timeout: 5_000 }).catch(() => undefined);
  }
}

function providerOutcomeForError(error: unknown):
  'rejected' | 'no-password-field' | 'no-submit-control' | 'origin-mismatch'
  | 'insecure-origin' | 'ambiguous-form' | 'provider-unavailable' {
  const message = error instanceof Error ? error.message : '';
  if (message.includes('origin mismatch')) return 'origin-mismatch';
  if (message.includes('insecure origin')) return 'insecure-origin';
  if (message.includes('ambiguous')) return 'ambiguous-form';
  if (message.includes('password field is missing')) return 'no-password-field';
  if (message.includes('submit control is missing')) return 'no-submit-control';
  if (message.includes('rejected')) return 'rejected';
  return 'provider-unavailable';
}

export function safeRuntimeStderrCode(stderr: string): string {
  const safeRuntimeMessages: ReadonlyArray<[string, string]> = [
    ['API key is invalid or revoked', 'api-key-invalid-or-revoked'],
    ['Access was denied by the vault owner.', 'grant-denied'],
    ['The grant for this credential has expired.', 'grant-expired'],
    ['The grant has no remaining uses (consumed).', 'grant-consumed'],
    ['This Agent is deactivated.', 'agent-deactivated'],
    ['trusted provider handshake is invalid', 'provider-handshake-invalid'],
    ['trusted provider transport closed before credential delivery', 'provider-transport-closed'],
    ['trusted provider result is invalid', 'provider-result-invalid'],
    ['the trusted browser provider did not complete Inject', 'browser-action-failed'],
  ];
  for (const [known, code] of safeRuntimeMessages) if (stderr.includes(known)) return code;
  return stderr.length > 0 ? 'runtime-rejected' : 'runtime-unavailable';
}

function safeFailureCode(error: unknown, stderr = ''): string {
  const message = error instanceof Error ? error.message : '';
  if (message === 'login form is missing') return 'login-surface-missing';
  if (message === 'username field is ambiguous') return 'username-ambiguous';
  if (message === 'username field is missing or ambiguous') return 'username-missing-or-ambiguous';
  if (message === 'password field is ambiguous') return 'password-ambiguous';
  if (message === 'password field is missing') return 'password-missing';
  if (message === 'combined login form is ambiguous') return 'combined-surface-ambiguous';
  if (message === 'combined login form is missing or ambiguous') return 'combined-surface-missing-or-ambiguous';
  if (message === 'origin mismatch' || message.startsWith('origin mismatch (')) return message;
  if (message === 'insecure origin') return 'insecure-origin';
  if (message === 'declared field is missing or ambiguous') return 'declared-field-missing-or-ambiguous';
  if (message === 'declared field control does not match') return 'declared-field-control-mismatch';
  if (message === 'provider-frame-invalid-json' || message === 'provider-frame-unexpected-fields'
    || message === 'provider-frame-binding-mismatch' || message === 'provider-frame-form-mismatch'
    || message === 'provider-frame-values-invalid') return message;
  if (stderr.length > 0) return safeRuntimeStderrCode(stderr);
  if (message === 'declared field value is missing') return 'declared-field-value-missing';
  if (message === 'submit control is missing or ambiguous') return 'submit-control-missing-or-ambiguous';
  if (message === 'site-rate-limited' || message === 'site-challenge-required'
    || message === 'site-rejected') return message;
  if (message === 'transition target is missing') return 'transition-target-missing';
  if (message === 'transition target is ambiguous') return 'transition-target-ambiguous';
  if (message.includes('Timeout')) return 'browser-action-timeout';
  return 'browser-action-failed';
}

export async function fillAndSubmit(
  page: Page,
  credential: ProviderCredential,
): Promise<'injected'> {
  const values = new Map(credential.values.map((field) => [field.entryFieldId, field.value]));
  const filled: Array<{
    target: Locator;
    entryFieldId: string;
    control: ProviderCredential['form']['steps'][number]['fields'][number]['control'];
  }> = [];
  try {
    for (const step of credential.form.steps) {
      verifyDomain(page.url(), credential.expectedDomain);
      for (const field of step.fields) {
        const value = values.get(field.entryFieldId);
        if (value === undefined) throw new Error('declared field value is missing');
        const target = await uniqueUsableControl(page, field.selector, field.control);
        await target.fill(value);
        filled.push({ target, entryFieldId: field.entryFieldId, control: field.control });
        verifyDomain(page.url(), credential.expectedDomain);
      }
      verifyDomain(page.url(), credential.expectedDomain);
      if (step.submit.action === 'click') {
        const submit = await waitForUniqueSubmit(page, step.submit.selector);
        await submit.click();
      } else {
        const submitField = await uniqueUsableControl(
          page,
          step.submit.selector,
          step.fields.find((field) => field.selector === step.submit.selector)?.control ?? 'text',
        );
        await submitField.press('Enter');
      }
      if (step.waitFor !== undefined) {
        await waitForUniqueTransition(
          page,
          step.waitFor.selector,
          step.waitFor.timeoutMs ?? 20_000,
        );
      }
      verifyDomain(page.url(), credential.expectedDomain);
    }
    return 'injected';
  } catch (error) {
    for (const field of filled.reverse()) {
      const isPublicDiscoveryUsername = field.entryFieldId === 'credential.username'
        && field.control === 'username';
      if (!isPublicDiscoveryUsername) await field.target.fill('').catch(() => undefined);
    }
    throw error;
  }
}

async function waitForUniqueSubmit(page: Page, selector: string, timeoutMs = 20_000): Promise<Locator> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const visibleSubmits: Locator[] = [];
    for (const candidate of await page.locator(selector).all()) {
      if (await candidate.isVisible() && await candidate.isEnabled()) visibleSubmits.push(candidate);
    }
    if (visibleSubmits.length === 1) {
      const submit = visibleSubmits[0];
      if (submit !== undefined) return submit;
    }
    if (visibleSubmits.length > 1) throw new Error('submit control is missing or ambiguous');
    await page.waitForTimeout(100);
  }
  throw new Error('submit control is missing or ambiguous');
}

async function waitForUniqueTransition(
  page: Page,
  selector: string,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const siteFailure = await publicSiteFailure(page);
    if (siteFailure !== null) throw new Error(siteFailure);
    const locator = page.locator(selector);
    const candidates = await locator.all();
    const inputCount = candidates.length === 0 ? 0 : await locator.evaluateAll((elements) => (
      elements.filter((element) => element instanceof HTMLInputElement
        || element instanceof HTMLTextAreaElement).length
    ));
    if (inputCount > 0) {
      if (inputCount !== candidates.length) throw new Error('transition target is ambiguous');
      const usable = await usableInputs(locator);
      if (usable.length === 1) return;
      if (usable.length > 1) throw new Error('transition target is ambiguous');
    } else {
      const visible = [];
      for (const candidate of candidates) if (await candidate.isVisible()) visible.push(candidate);
      if (visible.length === 1) return;
      if (visible.length > 1) throw new Error('transition target is ambiguous');
    }
    await page.waitForTimeout(100);
  }
  throw new Error('transition target is missing');
}

async function publicSiteFailure(
  page: Page,
): Promise<'site-rate-limited' | 'site-challenge-required' | 'site-rejected' | null> {
  for (const alert of await page.locator('[role="alert"]').all()) {
    if (!(await alert.isVisible().catch(() => false))) continue;
    const text = (await alert.innerText().catch(() => '')).toLowerCase();
    if (text.includes('temporarily limited') || text.includes('try again later')
      || text.includes('too many') || text.includes('rate limit')) return 'site-rate-limited';
    if (text.includes('captcha') || text.includes('verify you are human')
      || text.includes('verify you are a human')) return 'site-challenge-required';
    return 'site-rejected';
  }
  return null;
}

async function uniqueUsableControl(
  page: Page,
  selector: string,
  control: InjectControl,
  timeoutMs = 20_000,
): Promise<Locator> {
  const deadline = Date.now() + timeoutMs;
  let target: Locator | undefined;
  while (Date.now() < deadline) {
    const candidates = await usableInputs(page.locator(selector));
    if (candidates.length === 1) {
      target = candidates[0];
      break;
    }
    if (candidates.length > 1) throw new Error('declared field is missing or ambiguous');
    await page.waitForTimeout(100);
  }
  if (target === undefined) throw new Error('declared field is missing or ambiguous');
  const matches = await target.evaluate((element, expected) => {
    if (element instanceof HTMLTextAreaElement) return expected === 'text';
    if (!(element instanceof HTMLInputElement)) return false;
    const type = (element.type || 'text').toLowerCase();
    if (expected === 'password') return type === 'password';
    if (expected === 'email') return type === 'email' || type === 'text';
    if (expected === 'tel' || expected === 'otp') return ['tel', 'text', 'number'].includes(type);
    return ['text', 'email', 'tel', 'search', 'url'].includes(type);
  }, control);
  if (!matches) throw new Error('declared field control does not match');
  return target;
}

async function usableInputs(locator: Locator): Promise<Locator[]> {
  const candidates: Locator[] = [];
  for (const candidate of await locator.all()) {
    const usable = await candidate.evaluate((element) => {
      if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement)
        || element.disabled || element.readOnly || element.hidden
        || (element instanceof HTMLInputElement && element.type === 'hidden')
        || element.getAttribute('aria-hidden') === 'true') {
        return false;
      }
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(centerX, centerY);
      return style.display !== 'none'
        && style.visibility !== 'hidden'
        && Number.parseFloat(style.opacity || '1') > 0.01
        && style.pointerEvents !== 'none'
        && rect.width > 0
        && rect.height > 0
        && centerX >= 0
        && centerY >= 0
        && centerX <= document.documentElement.clientWidth
        && centerY <= document.documentElement.clientHeight
        && hit !== null
        && (hit === element || element.contains(hit) || hit.contains(element));
    });
    if (usable) candidates.push(candidate);
  }
  return candidates;
}

export function parseInjectArguments(value: unknown): InjectArguments | null {
  if (!isRecord(value)) return null;
  const allowed = new Set(['profile', 'vaultId', 'entryId', 'reason', 'wait', 'noWait', 'pollInterval', 'form', 'formMap']);
  if (Object.keys(value).some((key) => !allowed.has(key))) return null;
  if (value.profile !== undefined && !boundedString(value.profile, 128)) return null;
  if (!boundedString(value.vaultId, 256) || !boundedString(value.entryId, 256)) return null;
  if (value.reason !== undefined && !boundedString(value.reason, 4096, true)) return null;
  if (value.wait !== undefined && !boundedString(value.wait, 32)) return null;
  if (value.pollInterval !== undefined && !boundedString(value.pollInterval, 32)) return null;
  if (value.noWait !== undefined && typeof value.noWait !== 'boolean') return null;
  const form = parseInjectForm(value.form);
  if (form === null) return null;
  if (value.formMap !== undefined && parseFormDiscoveryMap(value.formMap) === null) return null;
  return { ...(value as unknown as Omit<InjectArguments, 'form'>), form };
}

export function parseProviderCredential(
  line: string,
  nonce: string,
  entryId: string,
  expectedForm: InjectFormDefinition,
): ProviderCredential | null {
  return parseProviderCredentialDiagnostic(line, nonce, entryId, expectedForm).credential;
}

export type ProviderFrameDiagnostic =
  | 'provider-frame-invalid-json'
  | 'provider-frame-unexpected-fields'
  | 'provider-frame-binding-mismatch'
  | 'provider-frame-form-mismatch'
  | 'provider-frame-values-invalid';

export function parseProviderCredentialDiagnostic(
  line: string,
  nonce: string,
  entryId: string,
  expectedForm: InjectFormDefinition,
): { credential: ProviderCredential | null; code: ProviderFrameDiagnostic | null } {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return { credential: null, code: 'provider-frame-invalid-json' };
  }
  if (!isRecord(value)) return { credential: null, code: 'provider-frame-unexpected-fields' };
  const allowed = new Set([
    'protocol', 'type', 'provider', 'nonce', 'transactionId', 'grantId', 'entryId',
    'expectedDomain', 'form', 'values',
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))) return { credential: null, code: 'provider-frame-unexpected-fields' };
  if (value.protocol !== INJECT_PROTOCOL
    || value.type !== 'credential'
    || value.provider !== 'playwright'
    || value.nonce !== nonce
    || value.entryId !== entryId
    || !boundedString(value.transactionId, 256)
    || !boundedString(value.grantId, 256)
    || !boundedString(value.expectedDomain, 253)) {
    return { credential: null, code: 'provider-frame-binding-mismatch' };
  }
  const form = parseInjectForm(value.form);
  if (form === null || !sameInjectForm(form, expectedForm)) {
    return { credential: null, code: 'provider-frame-form-mismatch' };
  }
  const values = parseInjectValues(value.values, form);
  if (values === null) return { credential: null, code: 'provider-frame-values-invalid' };
  return {
    credential: { ...(value as unknown as Omit<ProviderCredential, 'form' | 'values'>), form, values },
    code: null,
  };
}

function sameInjectForm(left: InjectFormDefinition, right: InjectFormDefinition): boolean {
  if (left.version !== right.version || left.steps.length !== right.steps.length) return false;
  return left.steps.every((step, stepIndex) => {
    const expected = right.steps[stepIndex];
    if (expected === undefined || step.fields.length !== expected.fields.length
      || step.submit.action !== expected.submit.action
      || step.submit.selector !== expected.submit.selector) return false;
    const sameFields = step.fields.every((field, fieldIndex) => {
      const expectedField = expected.fields[fieldIndex];
      return expectedField !== undefined
        && field.entryFieldId === expectedField.entryFieldId
        && field.selector === expectedField.selector
        && field.control === expectedField.control;
    });
    if (!sameFields) return false;
    if (step.waitFor === undefined || expected.waitFor === undefined) {
      return step.waitFor === undefined && expected.waitFor === undefined;
    }
    return step.waitFor.selector === expected.waitFor.selector
      && step.waitFor.timeoutMs === expected.waitFor.timeoutMs;
  });
}

export function verifyDomain(url: string, expectedDomain: string): void {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') throw new Error('insecure origin');
  const active = getDomain(parsed.hostname, { allowPrivateDomains: true });
  const expected = getDomain(expectedDomain, { allowPrivateDomains: true });
  if (active === null || expected === null || active !== expected) {
    // Domains are public metadata; include them in the value-free diagnostic so
    // a legitimate redirect can be fixed without exposing credential material.
    throw new Error(`origin mismatch (${active ?? 'unknown'} != ${expected ?? 'unknown'})`);
  }
}

function readOneLine(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let length = 0;
    const onData = (chunk: Buffer | string): void => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const newline = bytes.indexOf(0x0a);
      const part = newline === -1 ? bytes : bytes.subarray(0, newline);
      chunks.push(part);
      length += part.length;
      if (length > MAX_PROVIDER_FRAME_BYTES) {
        cleanup();
        reject(new Error('provider frame too large'));
      } else if (newline !== -1) {
        cleanup();
        resolve(Buffer.concat(chunks, length).toString('utf8'));
      }
    };
    const onEnd = (): void => { cleanup(); reject(new Error('provider transport closed')); };
    const onError = (): void => { cleanup(); reject(new Error('provider transport failed')); };
    const cleanup = (): void => {
      stream.removeListener('data', onData);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
    };
    stream.on('data', onData);
    stream.once('end', onEnd);
    stream.once('error', onError);
  });
}

function waitForExit(child: ChildProcess): Promise<number> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve(child.exitCode);
    child.once('exit', (code) => resolve(code ?? 1));
    child.once('error', () => resolve(1));
  });
}

function toolError(message: string): CallToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function boundedString(value: unknown, max: number, allowEmpty = false): value is string {
  return typeof value === 'string' && value.length <= max && (allowEmpty || value.length > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
