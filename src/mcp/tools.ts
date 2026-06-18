import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { AgentConfig } from '../config/config.js';
import { Keypair } from '../crypto/keypair.js';
import {
  AgentApiError,
  searchEntries,
  getCredential,
  uploadInjectFailure,
  CredentialMethod,
  SigningContext,
} from '../http/agent-api.js';
import { decryptCredential } from '../crypto/decrypt.js';
import { parseSecret } from '../crypto/secret.js';
import { accessMessage, GET_EXPOSURE_WARNING } from '../credential/access.js';
import { runExecCapture } from '../exec/run-exec.js';
import { injectCredential, InjectablePage } from '../inject/inject-runner.js';
import { buildFailureReport, writeFailureReport } from '../inject/failure-report.js';

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

function ok(text: string): ToolResult {
  return { content: [{ type: 'text', text }] };
}

function fail(text: string): ToolResult {
  return { content: [{ type: 'text', text }], isError: true };
}

function errorMessage(err: unknown): string {
  if (err instanceof AgentApiError) return err.message;
  return `Unexpected error: ${(err as Error).message ?? String(err)}`;
}

// Discovery is org-wide via GET /api/agent/entries (agent-auth, metadata only).
// The legacy CVT-44 placeholders list_vaults / list_entries called JwtBearer (user)
// endpoints and returned 401 under agent-auth — they are intentionally not exposed.
export function registerTools(server: McpServer, config: AgentConfig, keypair: Keypair, signing?: SigningContext): void {
  server.registerTool(
    'search_entries',
    {
      description:
        "Search vault entries by name/url/description (e.g. 'facebook') across the agent's organization. " +
        'Returns candidates (id, vaultId, name, url, description) — metadata only, no secrets. ' +
        'Pick one and call get_credential / exec_with_credential / inject_credential with its vaultId+entryId.',
      inputSchema: z.object({
        query: z.string().min(2).describe('Search term — matched against entry name, url and description (min 2 chars)'),
      }),
    },
    async ({ query }) => {
      try {
        const result = await searchEntries(config, keypair, query.trim(), undefined, signing);
        return ok(JSON.stringify(result, null, 2));
      } catch (err) {
        return fail(errorMessage(err));
      }
    }
  );

  server.registerTool(
    'get_credential',
    {
      description:
        "Get a credential as PLAINTEXT. WARNING: this places the secret in your context — on a hosted model it leaves the user's machine. " +
        'Prefer exec_with_credential (runs a command with the secret in its environment) or inject_credential (fills a login form) so the secret never enters your context. ' +
        "If the agent has no grant yet, this requests one (user approves in the panel) and returns access:'pending' — call again shortly.",
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID'),
        reason: z.string().optional().describe('Justification shown to the approving user (required when first requesting access)'),
      }),
    },
    async ({ vaultId, entryId, reason }) => {
      try {
        const result = await getCredential(config, keypair, vaultId, entryId, { reason: reason?.trim(), method: 'get' }, signing);
        if (result.access === 'granted') {
          const secret = await decryptCredential(result, keypair);
          return ok(JSON.stringify(
            { access: 'granted', entryId: result.entryId, label: result.label, secret, warning: GET_EXPOSURE_WARNING },
            null,
            2,
          ));
        }
        const grantId = result.access === 'pending' ? result.grantId : undefined;
        return ok(JSON.stringify({ access: result.access, message: accessMessage(result.access, 'get', grantId) }, null, 2));
      } catch (err) {
        return fail(errorMessage(err));
      }
    }
  );

  server.registerTool(
    'exec_with_credential',
    {
      description:
        'Run a shell command with the credential injected as environment variables (CLAW_SECRET, CLAW_USERNAME, CLAW_PASSWORD, CLAW_<FIELD>). ' +
        'The secret is NOT returned to you — only the command output (with the secret masked) and exit code. ' +
        'Use this instead of get_credential whenever the secret is only needed to authenticate a command (curl, psql, git, …).',
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID'),
        command: z.array(z.string()).min(1).describe('Command and args, e.g. ["curl","-u","$CLAW_USERNAME:$CLAW_PASSWORD","https://api…"]'),
        reason: z.string().optional().describe('Justification shown to the approving user (required when first requesting access)'),
      }),
    },
    async ({ vaultId, entryId, command, reason }) => {
      const resolved = await resolveForTool(config, keypair, vaultId, entryId, 'exec', reason, signing);
      if ('error' in resolved) {
        return fail(resolved.error);
      }
      const result = await runExecCapture(command, resolved.secret);
      return ok(JSON.stringify({ exitCode: result.code, stdout: result.stdout, stderr: result.stderr }, null, 2));
    }
  );

  server.registerTool(
    'inject_credential',
    {
      description:
        "Fill a login form in a browser you control over the Chrome DevTools Protocol. The secret is typed into the page and NEVER returned to you. " +
        "The page's origin is verified against the entry's bound domain first (anti-phishing) — navigate to the real login page before calling. " +
        'Launch your browser with --remote-debugging-port and pass its CDP endpoint.',
      inputSchema: z.object({
        vaultId: z.string().describe('Vault ID'),
        entryId: z.string().describe('Entry ID'),
        cdp: z.string().describe('CDP endpoint of your running browser, e.g. http://localhost:9222'),
        reason: z.string().optional().describe('Justification shown to the approving user (required when first requesting access)'),
        pageUrl: z.string().optional().describe('Pick the open page whose URL starts with this prefix (default: first page)'),
        usernameSelector: z.string().optional().describe('Override CSS selector for the username field'),
        passwordSelector: z.string().optional().describe('Override CSS selector for the password field'),
        submitSelector: z.string().optional().describe('Override CSS selector for the submit button'),
      }),
    },
    async ({ vaultId, entryId, cdp, reason, pageUrl, usernameSelector, passwordSelector, submitSelector }) => {
      const resolved = await resolveForTool(config, keypair, vaultId, entryId, 'inject', reason, signing);
      if ('error' in resolved) {
        return fail(resolved.error);
      }
      if (!resolved.urlDomain) {
        return fail('entry has no bound URL — inject is only allowed for entries with a known site (anti-phishing).');
      }

      let chromium: typeof import('playwright-core').chromium;
      try {
        ({ chromium } = await import('playwright-core'));
      } catch {
        return fail('inject requires playwright-core (npm i -g playwright-core).');
      }

      let browser: import('playwright-core').Browser;
      try {
        browser = await chromium.connectOverCDP(cdp);
      } catch (err) {
        return fail(`could not connect to the browser at ${cdp}: ${(err as Error).message}`);
      }

      try {
        const pages = browser.contexts().flatMap((ctx) => ctx.pages());
        const page = pageUrl ? pages.find((p) => p.url().startsWith(pageUrl)) ?? pages[0] : pages[0];
        if (!page) {
          return fail('no open page found in the connected browser.');
        }
        const result = await injectCredential(page as unknown as InjectablePage, resolved.secret, {
          entryDomain: resolved.urlDomain,
          overrides: { usernameSelector, passwordSelector, submitSelector },
        });
        if (result.ok) {
          // `outcome` is a best-effort hint (succeeded/rejected/unknown) — the agent confirms from
          // its own browser. `rejected` means the form was driven fine but the credential was
          // likely refused (stale password), NOT a heuristic miss.
          return ok(JSON.stringify({ ok: true, steps: result.steps, outcome: result.outcome }, null, 2));
        }
        if (result.diagnostic) {
          const report = buildFailureReport({
            reason: result.reason,
            steps: result.steps,
            vaultId,
            entryId,
            entryDomain: resolved.urlDomain,
            pageUrl: result.diagnostic.url,
            html: result.diagnostic.html,
          });
          writeFailureReport(report);
          await uploadInjectFailure(config, keypair, {
            entryId,
            domain: report.entryDomain,
            reason: report.reason,
            pageOrigin: report.pageOrigin,
            controls: report.controls,
          }, signing);
        }
        return fail(`${result.reason} (steps: ${result.steps.join(' → ') || 'none'})`);
      } finally {
        await browser.close();
      }
    }
  );
}

/**
 * Shared resolve for the exec/inject tools: returns the parsed secret + trusted domain, or an
 * `error` string for any non-granted access state (so the tool reports it without throwing).
 */
async function resolveForTool(
  config: AgentConfig,
  keypair: Keypair,
  vaultId: string,
  entryId: string,
  method: CredentialMethod,
  reason?: string,
  signing?: SigningContext,
): Promise<{ secret: ReturnType<typeof parseSecret>; urlDomain: string | null } | { error: string }> {
  try {
    const result = await getCredential(config, keypair, vaultId, entryId, { reason: reason?.trim(), method }, signing);
    if (result.access !== 'granted') {
      const grantId = result.access === 'pending' ? result.grantId : undefined;
      return { error: accessMessage(result.access, method, grantId) };
    }
    const plaintext = await decryptCredential(result, keypair);
    return { secret: parseSecret(plaintext), urlDomain: result.urlDomain };
  } catch (err) {
    return { error: errorMessage(err) };
  }
}
