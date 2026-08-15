import { parseFormDiscoveryMap, type FormDiscoveryMap, type FormMapProvider } from './form-map.js';
import { formMapFingerprint } from './form-map-fingerprint.js';

type CatalogRow = readonly [domain: string, path: string, flow: 'one' | 'multi'];
const rows: CatalogRow[] = [
  ['accounts.google.com','/','multi'],['login.microsoftonline.com','/','multi'],['appleid.apple.com','/sign-in','one'],['github.com','/login','one'],['gitlab.com','/users/sign_in','one'],['app.slack.com','/client','multi'],['discord.com','/login','one'],['notion.so','/login','multi'],['www.dropbox.com','/login','one'],['zoom.us','/signin','multi'],['www.linkedin.com','/login','one'],['youtube.com','/signin','multi'],['login.salesforce.com','/','one'],['app.hubspot.com','/login','multi'],['www.zendesk.com','/login','multi'],['accounts.shopify.com','/store-login','multi'],['dashboard.stripe.com','/login','multi'],['id.atlassian.com','/login','multi'],['www.canva.com','/login','multi'],['www.figma.com','/login','multi'],['auth.miro.com','/login','multi'],['www.facebook.com','/login','one'],['www.instagram.com','/accounts/login/','one'],['x.com','/i/flow/login','multi'],['www.reddit.com','/login/','one'],['www.tiktok.com','/login','multi'],['www.pinterest.com','/login/','one'],['accounts.snapchat.com','/accounts/login','one'],['www.twitch.tv','/login','one'],['web.youtube.com','/','multi'],['web.whatsapp.com','/','multi'],['web.telegram.org','/','multi'],['www.amazon.com','/ap/signin','multi'],['signin.ebay.com','/ws/eBayISAPI.dll?SignIn','multi'],['www.netflix.com','/login','one'],['accounts.spotify.com','/en/login','one'],['www.airbnb.com','/login','multi'],['auth.uber.com','/v2/','multi'],['www.doordash.com','/consumer/login/','multi'],['account.booking.com','/sign-in','multi'],['chatgpt.com','/auth/login','multi'],['claude.ai','/login','multi'],['vercel.com','/login','multi'],['app.netlify.com','/login','multi'],['id.heroku.com','/login','one'],['hub.docker.com','/login','one'],['console.aws.amazon.com','/','multi'],['console.cloud.google.com','/','multi'],['cloud.oracle.com','/','multi'],['accounts.sap.com','/','multi'],
];

function form(flow: CatalogRow[2]) {
  const username = { entryFieldId: 'username', selector: 'input[autocomplete="username"]', control: 'username' as const };
  const password = { entryFieldId: 'password', selector: 'input[type="password"]', control: 'password' as const };
  const submit = { action: 'click' as const, selector: 'button[type="submit"],input[type="submit"]' };
  if (flow === 'one') return { version: 1 as const, steps: [{ fields: [username, password], submit }] };
  return { version: 1 as const, steps: [{ fields: [username], submit, waitFor: { selector: 'input[type="password"]' } }, { fields: [password], submit }] };
}

export const popularFormMaps: FormDiscoveryMap[] = rows.map(([domain, path, flow]) => {
  const siteForm = domain === 'zoom.us' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'username', selector: '#email', control: 'username' as const }], submit: { action: 'click' as const, selector: '#signin_btn_next' }, waitFor: { selector: 'input[type="password"]', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'password', selector: 'input[type="password"]', control: 'password' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' } },
  ] } : domain === 'www.dropbox.com' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'username', selector: 'input[name="susi_email"]', control: 'username' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]:has-text("Continue")' }, waitFor: { selector: 'input[type="password"]', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'password', selector: 'input[type="password"]', control: 'password' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' } },
  ] } : domain === 'www.instagram.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: 'input[name="email"]', control: 'username' as const },
      { entryFieldId: 'password', selector: 'input[name="pass"]', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: '[role="button"][aria-label="Log In"]' },
  }] } : domain === 'accounts.sap.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: '#j_username', control: 'username' as const },
      { entryFieldId: 'password', selector: '#j_password', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: '#logOnFormSubmit' },
  }] } : domain === 'www.pinterest.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: '#streamlined-login-email', control: 'username' as const },
      { entryFieldId: 'password', selector: '#streamlined-login-password', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: 'button[type="submit"]:has-text("Log in")' },
  }] } : domain === 'app.hubspot.com' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'username', selector: '#username', control: 'username' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]:has-text("Continue")' }, waitFor: { selector: 'input[type="password"]', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'password', selector: 'input[type="password"]', control: 'password' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' } },
  ] } : domain === 'www.airbnb.com' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'username', selector: '#phone-or-email', control: 'username' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]:has-text("Continue")' }, waitFor: { selector: 'input[type="password"]', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'password', selector: 'input[type="password"]', control: 'password' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' } },
  ] } : domain === 'auth.uber.com' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'username', selector: '#PHONE_NUMBER_or_EMAIL_ADDRESS', control: 'username' as const }], submit: { action: 'click' as const, selector: '#forward-button' }, waitFor: { selector: 'input[type="password"]', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'password', selector: 'input[type="password"]', control: 'password' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' } },
  ] } : domain === 'login.microsoftonline.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: 'input[name="loginfmt"]', control: 'username' as const },
      { entryFieldId: 'password', selector: 'input[name="passwd"]', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: '#idSIButton9' },
  }] } : domain === 'dashboard.stripe.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: '#email', control: 'username' as const },
      { entryFieldId: 'password', selector: '#old-password', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: 'button:has-text("Sign in")' },
  }] } : domain === 'account.booking.com' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'username', selector: '#username', control: 'username' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' }, waitFor: { selector: '#hidden-password', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'password', selector: '#hidden-password', control: 'password' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' } },
  ] } : domain === 'www.figma.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: '#email', control: 'username' as const },
      { entryFieldId: 'password', selector: '#current-password', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: 'button[type="submit"]:has-text("Log in")' },
  }] } : domain === 'vercel.com' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'username', selector: 'input[type="email"]', control: 'username' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]:has-text("Continue with Email")' }, waitFor: { selector: 'input[type="password"]', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'password', selector: 'input[type="password"]', control: 'password' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' } },
  ] } : domain === 'id.atlassian.com' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'username', selector: 'input[name="username"]', control: 'username' as const }], submit: { action: 'click' as const, selector: '#login-submit' }, waitFor: { selector: 'input[name="password"]', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'password', selector: 'input[name="password"]', control: 'password' as const }], submit: { action: 'click' as const, selector: '#login-submit' } },
  ] } : domain === 'id.heroku.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: '#email', control: 'username' as const },
      { entryFieldId: 'password', selector: '#password', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: 'button[type="submit"]:has-text("Log In")' },
  }] } : domain === 'login.salesforce.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: '#username', control: 'username' as const },
      { entryFieldId: 'password', selector: '#password', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: '#Login' },
  }] } : domain === 'www.twitch.tv' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: '#login-username', control: 'username' as const },
      { entryFieldId: 'password', selector: '#password-input', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: 'button[type="submit"]:has-text("Log In")' },
  }] } : domain === 'www.linkedin.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: 'input[type="email"] >> nth=1', control: 'username' as const },
      { entryFieldId: 'password', selector: 'input[type="password"] >> nth=1', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: ':is(button[type="submit"],button:has-text("Sign in"),button:has-text("Zaloguj się"))' },
  }] } : domain === 'www.netflix.com' ? { version: 1 as const, steps: [{
    fields: [
      { entryFieldId: 'username', selector: 'input[name="userLoginId"]', control: 'username' as const },
      { entryFieldId: 'password', selector: 'input[name="password"]', control: 'password' as const },
    ], submit: { action: 'click' as const, selector: 'button[type="submit"]' },
  }] } : domain === 'accounts.spotify.com' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'username', selector: 'input#username', control: 'username' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' }, waitFor: { selector: 'input[type="password"]', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'password', selector: 'input[type="password"]', control: 'password' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' } },
  ] } : domain === 'x.com' ? { version: 1 as const, steps: [
    { fields: [{ entryFieldId: 'credential.username', selector: '#jf-input-username_or_email', control: 'username' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' }, waitFor: { selector: 'input[name="password"]', timeoutMs: 45_000 } },
    { fields: [{ entryFieldId: 'credential.password', selector: 'input[name="password"]', control: 'password' as const }], submit: { action: 'click' as const, selector: 'button[type="submit"]' } },
  ] } : form(flow);
  const draft = { version: 1 as const, mapVersion: 1, domain, loginUrl: `https://${domain}${path}`, provider: 'playwright' as FormMapProvider, status: 'candidate' as const, fingerprint: '', form: siteForm };
  return parseInjectable({ ...draft, fingerprint: formMapFingerprint(draft) });
});

function parseInjectable(value: unknown): FormDiscoveryMap {
  const result = parseFormDiscoveryMap(value);
  if (result === null) throw new Error('popular form map catalog contains an invalid map');
  return result;
}
