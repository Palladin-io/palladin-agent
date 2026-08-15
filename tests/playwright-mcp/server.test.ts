import { describe, expect, it } from 'vitest';
import { PassThrough } from 'node:stream';
import { chromium, type Page } from 'playwright';

import {
  fillAndSubmit,
  injectWithPalladin,
  parseInjectArguments,
  parseProviderCredential,
  parseProviderCredentialDiagnostic,
  verifyDomain,
  safeRuntimeStderrCode,
} from '../../packages/playwright-mcp/src/server.js';

const twoStepForm = {
  version: 1 as const,
  steps: [
    {
      fields: [{ entryFieldId: 'credential.username', selector: '#username', control: 'username' as const }],
      submit: { action: 'press-enter' as const, selector: '#username' },
      waitFor: { selector: '#password', timeoutMs: 20_000 },
    },
    {
      fields: [{ entryFieldId: 'credential.password', selector: '#password', control: 'password' as const }],
      submit: { action: 'press-enter' as const, selector: '#password' },
    },
  ],
};

const combinedForm = {
  version: 1 as const,
  steps: [{
    fields: [
      { entryFieldId: 'credential.username', selector: 'input[name="username"]', control: 'username' as const },
      { entryFieldId: 'credential.password', selector: 'input[name="password"]', control: 'password' as const },
    ],
    submit: { action: 'click' as const, selector: '#login-form button[type="submit"]' },
  }],
};

function credential(form = twoStepForm) {
  return {
    protocol: 'palladin.inject-provider.v1' as const,
    type: 'credential' as const,
    provider: 'playwright' as const,
    nonce: 'fixture-nonce',
    transactionId: 'fixture-transaction',
    grantId: 'fixture-grant',
    entryId: 'fixture-entry',
    expectedDomain: 'example.com',
    form,
    values: [
      { entryFieldId: 'credential.username', value: 'fixture-user' },
      { entryFieldId: 'credential.password', value: 'fixture-password' },
    ],
  };
}

describe('Playwright MCP Inject provider boundary', () => {
  it('maps only allowlisted runtime stderr to safe diagnostics', () => {
    expect(safeRuntimeStderrCode('Error: Access was denied by the vault owner.')).toBe('grant-denied');
    expect(safeRuntimeStderrCode('secret-password=do-not-return')).toBe('runtime-rejected');
    expect(safeRuntimeStderrCode('')).toBe('runtime-unavailable');
    expect(safeRuntimeStderrCode('x'.repeat(1_000_000))).toBe('runtime-rejected');
  });

  it('classifies rejected credential frames without exposing frame content', () => {
    const malformed = parseProviderCredentialDiagnostic('not-json-secret-canary', 'n'.repeat(64), 'entry', twoStepForm);
    expect(malformed.code).toBe('provider-frame-invalid-json');
    expect(JSON.stringify(malformed)).not.toContain('secret-canary');
    const valid = JSON.stringify({
      protocol: 'palladin.inject-provider.v1', type: 'credential', provider: 'playwright',
      nonce: 'n'.repeat(64), transactionId: 'tx', grantId: 'grant', entryId: 'entry',
      expectedDomain: 'example.com', form: twoStepForm,
      values: [{ entryFieldId: 'credential.username', value: 'username-secret-canary' },
        { entryFieldId: 'credential.password', value: 'password-secret-canary' }],
    });
    const mismatch = parseProviderCredentialDiagnostic(valid, 'wrong'.repeat(16), 'entry', twoStepForm);
    expect(mismatch.code).toBe('provider-frame-binding-mismatch');
    expect(JSON.stringify(mismatch)).not.toContain('secret-canary');
  });

  it('accepts the same validated form regardless of JSON object key order', () => {
    const reorderedForm = {
      steps: twoStepForm.steps.map((step) => ({
        ...(step.waitFor === undefined ? {} : {
          waitFor: { timeoutMs: step.waitFor.timeoutMs, selector: step.waitFor.selector },
        }),
        submit: { selector: step.submit.selector, action: step.submit.action },
        fields: step.fields.map((field) => ({
          control: field.control,
          selector: field.selector,
          entryFieldId: field.entryFieldId,
        })),
      })),
      version: 1,
    };
    const frame = JSON.stringify({
      values: [
        { value: 'fixture-user', entryFieldId: 'credential.username' },
        { value: 'fixture-password', entryFieldId: 'credential.password' },
      ],
      form: reorderedForm,
      expectedDomain: 'example.com', entryId: 'entry', grantId: 'grant',
      transactionId: 'tx', nonce: 'nonce', provider: 'playwright',
      type: 'credential', protocol: 'palladin.inject-provider.v1',
    });

    expect(parseProviderCredentialDiagnostic(frame, 'nonce', 'entry', twoStepForm).code).toBeNull();
  });

  it('propagates an allowlisted child stderr code through the orchestration result', async () => {
    // This path fails during the runtime handshake and must not depend on a
    // real browser process. Keeping the fixture at the boundary also avoids a
    // Windows Chromium teardown race obscuring the diagnostic assertion.
    const page = { url: () => 'https://example.com/login' } as Page;
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const stdin = new PassThrough();
    const child = Object.assign(new PassThrough(), {
      stdin,
      stdout,
      stderr,
      exitCode: 1,
      kill: () => { stdout.end(); stderr.end(); return true; },
    });
    const result = await injectWithPalladin(page, {
      vaultId: 'vault', entryId: 'entry', form: combinedForm,
    }, () => {
      queueMicrotask(() => {
        stderr.end('Error: Access was denied by the vault owner.\n');
        stdout.end();
      });
      return child as never;
    });
    const diagnostic = result.content.find((item) => item.type === 'text');
    expect(diagnostic?.type === 'text' ? diagnostic.text : '').toContain('(grant-denied)');
    expect(diagnostic?.type === 'text' ? diagnostic.text : '').not.toContain('Access was denied');
  });
  it('accepts only a bounded value-free form definition', () => {
    expect(parseInjectArguments({ vaultId: 'vault', entryId: 'entry', form: twoStepForm })).not.toBeNull();
    expect(parseInjectArguments({ vaultId: 'vault', entryId: 'entry' })).toBeNull();
    expect(parseInjectArguments({ vaultId: 'vault', entryId: 'entry', form: twoStepForm, selector: '#password' }))
      .toBeNull();
    expect(parseInjectArguments({
      vaultId: 'vault', entryId: 'entry', form: twoStepForm,
      cdp: 'ws://127.0.0.1:9222/devtools/browser/untrusted',
    })).toBeNull();
    expect(parseInjectArguments({
      vaultId: 'vault', entryId: 'entry',
      form: { ...twoStepForm, javascript: 'document.body.innerHTML = "owned"' },
    })).toBeNull();
  });

  it('binds the private credential frame to nonce, entry and the exact form', () => {
    const frame = JSON.stringify({ ...credential(), nonce: 'nonce', entryId: 'entry' });
    expect(parseProviderCredential(frame, 'nonce', 'entry', twoStepForm)).not.toBeNull();
    expect(parseProviderCredential(frame, 'different', 'entry', twoStepForm)).toBeNull();
    expect(parseProviderCredential(frame, 'nonce', 'entry', combinedForm)).toBeNull();
    expect(parseProviderCredential(
      frame.replace('"expectedDomain":"example.com"', '"expectedDomain":"example.com","selector":"#password"'),
      'nonce', 'entry', twoStepForm,
    )).toBeNull();
  });

  it('requires HTTPS and the authenticated host boundary', () => {
    expect(() => verifyDomain('https://login.example.com/path', 'example.com')).not.toThrow();
    expect(() => verifyDomain('https://deep.login.example.com/path', 'login.example.com')).not.toThrow();
    expect(() => verifyDomain('https://evil.example.com/path', 'login.example.com')).toThrow('origin mismatch');
    expect(() => verifyDomain('https://example.com/path', 'login.example.com')).toThrow('origin mismatch');
    expect(() => verifyDomain('http://example.com', 'example.com')).toThrow('insecure origin');
    expect(() => verifyDomain('https://example.net', 'example.com')).toThrow('origin mismatch');
  });

  it('executes the declared two-step login and ignores decoys', async () => {
    const browser = await chromium.launch({ channel: 'chrome', headless: true });
    try {
      const page = await browser.newPage();
      await page.route('https://example.com/login', async (route) => route.fulfill({
        contentType: 'text/html',
        body: `
          <form id="login-form">
            <label for="username">Email or username</label>
            <input id="username" name="username" type="text">
            <button type="submit">Next</button>
          </form>
          <input id="password-decoy" type="password" style="position:absolute;opacity:0;pointer-events:none">
          <script>
            document.querySelector('#login-form').addEventListener('submit', (event) => {
              event.preventDefault();
              event.currentTarget.innerHTML = '<label for="password">Password</label>' +
                '<input id="password" type="password"><button type="submit">Sign in</button>';
              event.currentTarget.addEventListener('submit', (passwordEvent) => {
                passwordEvent.preventDefault(); document.body.dataset.submitted = 'yes';
              }, { once: true });
            }, { once: true });
          </script>`,
      }));
      await page.goto('https://example.com/login');

      await fillAndSubmit(page, credential());

      expect(await page.locator('#password').inputValue()).toBe('fixture-password');
      expect(await page.locator('#password-decoy').inputValue()).toBe('');
      expect(await page.locator('body').getAttribute('data-submitted')).toBe('yes');
    } finally {
      await browser.close();
    }
  });

  it('waits for a client-rendered combined login surface', async () => {
    const browser = await chromium.launch({ channel: 'chrome', headless: true });
    try {
      const page = await browser.newPage();
      await page.route('https://example.com/login', async (route) => route.fulfill({
        contentType: 'text/html',
        body: `<main id="root"></main><script>
          setTimeout(() => {
            document.querySelector('#root').innerHTML = '<form id="login-form">' +
              '<input name="username"><input name="password" type="password">' +
              '<button type="submit">Sign in</button></form>';
            document.querySelector('#login-form').addEventListener('submit', (event) => {
              event.preventDefault(); document.body.dataset.submitted = 'yes';
            });
          }, 300);
        </script>`,
      }));
      await page.goto('https://example.com/login');
      await page.locator('#login-form').waitFor();

      await fillAndSubmit(page, credential(combinedForm));

      expect(await page.locator('input[name="username"]').inputValue()).toBe('fixture-user');
      expect(await page.locator('input[name="password"]').inputValue()).toBe('fixture-password');
      expect(await page.locator('body').getAttribute('data-submitted')).toBe('yes');
    } finally {
      await browser.close();
    }
  });

  it('fills a declared text control backed by a textarea', async () => {
    const browser = await chromium.launch({ channel: 'chrome', headless: true });
    try {
      const page = await browser.newPage();
      await page.route('https://example.com/login', async (route) => route.fulfill({
        contentType: 'text/html',
        body: `<form id="login-form"><textarea id="username"></textarea>
          <button id="submit" type="submit">Continue</button></form>
          <script>document.querySelector('#login-form').addEventListener('submit', (event) => {
            event.preventDefault(); document.body.dataset.submitted = 'yes';
          });</script>`,
      }));
      await page.goto('https://example.com/login');
      const textareaForm = {
        version: 1 as const,
        steps: [{
          fields: [{
            entryFieldId: 'credential.username', selector: '#username', control: 'text' as const,
          }],
          submit: { action: 'click' as const, selector: '#submit' },
        }],
      };

      await fillAndSubmit(page, credential(textareaForm));

      expect(await page.locator('#username').inputValue()).toBe('fixture-user');
      expect(await page.locator('body').getAttribute('data-submitted')).toBe('yes');
    } finally {
      await browser.close();
    }
  });

  it('re-resolves selectors after a same-origin document navigation', async () => {
    const browser = await chromium.launch({ channel: 'chrome', headless: true });
    try {
      const page = await browser.newPage();
      await page.route('https://example.com/**', async (route) => {
        if (new URL(route.request().url()).pathname === '/login') {
          await route.fulfill({ contentType: 'text/html', body: `
            <form method="get" action="/password"><input id="username" type="text">
            <button type="submit">Next</button></form>` });
        } else {
          await route.fulfill({ contentType: 'text/html', body: `
            <form id="password-form"><input id="password" type="password">
            <button type="submit">Sign in</button></form><script>
              document.querySelector('#password-form').addEventListener('submit', (event) => {
                event.preventDefault(); document.body.dataset.submitted = 'yes';
              });
            </script>` });
        }
      });
      await page.goto('https://example.com/login');

      await fillAndSubmit(page, credential());

      expect(new URL(page.url()).pathname).toBe('/password');
      expect(await page.locator('#password').inputValue()).toBe('fixture-password');
    } finally {
      await browser.close();
    }
  });

  it('classifies a public post-submit rate-limit alert without returning its text', async () => {
    const browser = await chromium.launch({ channel: 'chrome', headless: true });
    try {
      const page = await browser.newPage();
      await page.route('https://example.com/login', async (route) => route.fulfill({
        contentType: 'text/html',
        body: `<form id="login-form"><input id="username"><button id="next" type="submit">Next</button></form>
          <script>document.querySelector('#login-form').addEventListener('submit', (event) => {
            event.preventDefault(); document.body.insertAdjacentHTML('beforeend',
          '<div role="alert">We have temporarily limited your login. Please try again later.</div>');
          });</script>`,
      }));
      await page.goto('https://example.com/login');
      const rateLimitedForm = {
        version: 1 as const,
        steps: [
          {
            fields: [{ entryFieldId: 'credential.username', selector: '#username', control: 'username' as const }],
            submit: { action: 'click' as const, selector: '#next' },
            waitFor: { selector: '#password', timeoutMs: 500 },
          },
          {
            fields: [{ entryFieldId: 'credential.password', selector: '#password', control: 'password' as const }],
            submit: { action: 'press-enter' as const, selector: '#password' },
          },
        ],
      };

      await expect(fillAndSubmit(page, credential(rateLimitedForm))).rejects.toThrow('site-rate-limited');
      expect(await page.locator('#username').inputValue()).toBe('fixture-user');
      expect(await page.locator('[role="alert"]').isVisible()).toBe(true);
    } finally {
      await browser.close();
    }
  });

  it('retains the Discovery-visible username and public alert but clears the password', async () => {
    const browser = await chromium.launch({ channel: 'chrome', headless: true });
    try {
      const page = await browser.newPage();
      await page.route('https://example.com/login', async (route) => route.fulfill({
        contentType: 'text/html',
        body: `<form id="login-form"><input id="username"><input id="password" type="password">
          <button id="submit" type="submit">Sign in</button></form>
          <script>document.querySelector('#login-form').addEventListener('submit', (event) => {
            event.preventDefault(); document.body.insertAdjacentHTML('beforeend',
              '<div role="alert">Login was rejected.</div>');
          });</script>`,
      }));
      await page.goto('https://example.com/login');
      const rejectedForm = {
        version: 1 as const,
        steps: [{
          fields: [
            { entryFieldId: 'credential.username', selector: '#username', control: 'username' as const },
            { entryFieldId: 'credential.password', selector: '#password', control: 'password' as const },
          ],
          submit: { action: 'click' as const, selector: '#submit' },
          waitFor: { selector: '#success', timeoutMs: 500 },
        }],
      };

      await expect(fillAndSubmit(page, credential(rejectedForm))).rejects.toThrow('site-rejected');
      expect(await page.locator('#username').inputValue()).toBe('fixture-user');
      expect(await page.locator('#password').inputValue()).toBe('');
      expect(await page.locator('[role="alert"]').isVisible()).toBe(true);
    } finally {
      await browser.close();
    }
  });

  it('fails closed when a declared password selector targets a text control', async () => {
    const browser = await chromium.launch({ channel: 'chrome', headless: true });
    try {
      const page = await browser.newPage();
      await page.route('https://example.com/login', async (route) => route.fulfill({
        contentType: 'text/html', body: '<input id="password" type="text">',
      }));
      await page.goto('https://example.com/login');
      await expect(fillAndSubmit(page, {
        ...credential({
          version: 1,
          steps: [{
            fields: [{ entryFieldId: 'credential.password', selector: '#password', control: 'password' }],
            submit: { action: 'press-enter', selector: '#password' },
          }],
        }),
        expectedDomain: 'example.com',
        values: [{ entryFieldId: 'credential.password', value: 'fixture-password' }],
      })).rejects.toThrow('declared field control does not match');
    } finally {
      await browser.close();
    }
  });
});
