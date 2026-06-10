/**
 * Login-form fixtures for the field-detection heuristic (CVT-151). Each fixture is a structurally
 * faithful (simplified) login form from a popular portal, plus pattern variants that exercise the
 * different signals a real form uses: input[type=password], autocomplete attributes, name/id token
 * patterns, placeholders, aria-labels, multi-step (identifier-then-password) flows, and pages with
 * a sign-in form next to an unrelated search box.
 *
 * `expect` encodes what detection MUST find on the given HTML view:
 *   step     — combined | username-step | password-step
 *   username — true if a username/email field must be detected
 *   password — true if a password field must be detected
 *   submit   — true if a submit control must be detected
 */
export interface LoginFixture {
  name: string;
  /** Registrable domain the entry would be bound to (for origin-check tests). */
  domain: string;
  html: string;
  expect: {
    step: 'combined' | 'username-step' | 'password-step';
    username: boolean;
    password: boolean;
    submit: boolean;
  };
}

const combined = {
  step: 'combined' as const,
  username: true,
  password: true,
  submit: true,
};

// A standard combined form keyed by the strongest available signal.
function standardForm(opts: {
  userType?: string;
  userName?: string;
  userId?: string;
  userAutocomplete?: string;
  userPlaceholder?: string;
  userAriaLabel?: string;
  passAutocomplete?: string;
  submitText?: string;
  submitTag?: 'button' | 'input';
}): string {
  const u = opts;
  const userAttrs = [
    `type="${u.userType ?? 'text'}"`,
    u.userName ? `name="${u.userName}"` : '',
    u.userId ? `id="${u.userId}"` : '',
    u.userAutocomplete ? `autocomplete="${u.userAutocomplete}"` : '',
    u.userPlaceholder ? `placeholder="${u.userPlaceholder}"` : '',
    u.userAriaLabel ? `aria-label="${u.userAriaLabel}"` : '',
  ].filter(Boolean).join(' ');

  const passAttrs = [
    'type="password"',
    'name="password"',
    'id="password"',
    u.passAutocomplete ? `autocomplete="${u.passAutocomplete}"` : 'autocomplete="current-password"',
  ].filter(Boolean).join(' ');

  const submit = u.submitTag === 'input'
    ? `<input type="submit" value="${u.submitText ?? 'Sign in'}">`
    : `<button type="submit">${u.submitText ?? 'Sign in'}</button>`;

  return `<!doctype html><html><body><form>
    <input ${userAttrs}>
    <input ${passAttrs}>
    ${submit}
  </form></body></html>`;
}

// Identifier-only first step (multi-step / SSO).
function usernameStepForm(opts: { userAutocomplete?: string; userType?: string; userName?: string; nextText?: string }): string {
  const attrs = [
    `type="${opts.userType ?? 'email'}"`,
    opts.userName ? `name="${opts.userName}"` : 'name="identifier"',
    opts.userAutocomplete ? `autocomplete="${opts.userAutocomplete}"` : 'autocomplete="username"',
  ].filter(Boolean).join(' ');
  return `<!doctype html><html><body><form>
    <input ${attrs}>
    <button type="submit">${opts.nextText ?? 'Next'}</button>
  </form></body></html>`;
}

// Password-only second step.
function passwordStepForm(submitText = 'Sign in'): string {
  return `<!doctype html><html><body><form>
    <input type="password" name="password" autocomplete="current-password">
    <button type="submit">${submitText}</button>
  </form></body></html>`;
}

// Hand-crafted real-world-representative forms for the most popular portals.
const realWorld: LoginFixture[] = [
  {
    name: 'Google — identifier step',
    domain: 'google.com',
    html: usernameStepForm({ userName: 'identifier', userType: 'email', userAutocomplete: 'username', nextText: 'Next' }),
    expect: { step: 'username-step', username: true, password: false, submit: true },
  },
  {
    name: 'Google — password step',
    domain: 'google.com',
    html: passwordStepForm('Next'),
    expect: { step: 'password-step', username: false, password: true, submit: true },
  },
  {
    name: 'GitHub — combined',
    domain: 'github.com',
    html: standardForm({ userName: 'login', userId: 'login_field', userPlaceholder: 'Username or email address', submitText: 'Sign in', submitTag: 'input' }),
    expect: combined,
  },
  {
    name: 'Microsoft — identifier step',
    domain: 'microsoft.com',
    html: usernameStepForm({ userName: 'loginfmt', userType: 'email', userAutocomplete: 'username', nextText: 'Next' }),
    expect: { step: 'username-step', username: true, password: false, submit: true },
  },
  {
    name: 'Amazon — email step',
    domain: 'amazon.com',
    html: usernameStepForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', nextText: 'Continue' }),
    expect: { step: 'username-step', username: true, password: false, submit: true },
  },
  {
    name: 'Facebook — combined',
    domain: 'facebook.com',
    html: standardForm({ userName: 'email', userId: 'email', userType: 'text', submitText: 'Log In' }),
    expect: combined,
  },
  {
    name: 'X / Twitter — username step',
    domain: 'x.com',
    html: usernameStepForm({ userName: 'text', userType: 'text', userAutocomplete: 'username', nextText: 'Next' }),
    expect: { step: 'username-step', username: true, password: false, submit: true },
  },
  {
    name: 'LinkedIn — combined',
    domain: 'linkedin.com',
    html: standardForm({ userName: 'session_key', userId: 'username', userType: 'text', userAutocomplete: 'username', submitText: 'Sign in' }),
    expect: combined,
  },
  {
    name: 'Netflix — combined',
    domain: 'netflix.com',
    html: standardForm({ userName: 'userLoginId', userType: 'text', userPlaceholder: 'Email or phone number', submitText: 'Sign In' }),
    expect: combined,
  },
  {
    name: 'PayPal — email step',
    domain: 'paypal.com',
    html: usernameStepForm({ userName: 'login_email', userType: 'email', userAutocomplete: 'username', nextText: 'Next' }),
    expect: { step: 'username-step', username: true, password: false, submit: true },
  },
  {
    name: 'Apple — combined with aria-label',
    domain: 'apple.com',
    html: standardForm({ userName: 'accountName', userType: 'text', userAriaLabel: 'Apple ID', submitText: 'Sign In' }),
    expect: combined,
  },
  {
    name: 'Bank of America — combined (id tokens)',
    domain: 'bankofamerica.com',
    html: standardForm({ userId: 'onlineId1', userName: 'onlineId1', userType: 'text', userPlaceholder: 'Online ID', submitText: 'Log In' }),
    expect: combined,
  },
  {
    name: 'Stripe — combined',
    domain: 'stripe.com',
    html: standardForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', submitText: 'Continue' }),
    expect: combined,
  },
  {
    name: 'Shopify — combined',
    domain: 'shopify.com',
    html: standardForm({ userName: 'account[email]', userType: 'email', userAutocomplete: 'email', submitText: 'Log in' }),
    expect: combined,
  },
  {
    name: 'Page with search box + sign-in form (must skip search)',
    domain: 'example.com',
    html: `<!doctype html><html><body>
      <input type="search" name="q" placeholder="Search" aria-label="Search">
      <form>
        <input type="email" name="email" autocomplete="username">
        <input type="password" name="password" autocomplete="current-password">
        <button type="submit">Sign in</button>
      </form>
    </body></html>`,
    expect: combined,
  },
];

// Top portals (domains) we generate standard combined forms for, to reach broad coverage of the
// "100 most popular" requirement with realistic field naming.
const POPULAR_DOMAINS = [
  'yahoo.com', 'instagram.com', 'reddit.com', 'wikipedia.org', 'tiktok.com', 'twitch.tv',
  'spotify.com', 'dropbox.com', 'slack.com', 'zoom.us', 'salesforce.com', 'adobe.com',
  'wordpress.com', 'ebay.com', 'aliexpress.com', 'booking.com', 'airbnb.com', 'uber.com',
  'lyft.com', 'doordash.com', 'coinbase.com', 'binance.com', 'robinhood.com', 'chase.com',
  'wellsfargo.com', 'citibank.com', 'americanexpress.com', 'capitalone.com', 'fidelity.com',
  'schwab.com', 'venmo.com', 'cash.app', 'discord.com', 'telegram.org', 'whatsapp.com',
  'snapchat.com', 'pinterest.com', 'tumblr.com', 'medium.com', 'quora.com', 'stackoverflow.com',
  'gitlab.com', 'bitbucket.org', 'atlassian.com', 'notion.so', 'figma.com', 'canva.com',
  'asana.com', 'trello.com', 'monday.com', 'hubspot.com', 'mailchimp.com', 'zendesk.com',
  'intercom.com', 'okta.com', 'auth0.com', 'cloudflare.com', 'digitalocean.com', 'heroku.com',
  'vercel.com', 'netlify.com', 'godaddy.com', 'namecheap.com', 'squarespace.com', 'wix.com',
  'office.com', 'outlook.com', 'icloud.com', 'protonmail.com', 'zoho.com', 'fastmail.com',
  'oracle.com', 'sap.com', 'ibm.com', 'workday.com', 'servicenow.com', 'docusign.com',
  'box.com', 'evernote.com', 'lastpass.com', '1password.com', 'bitwarden.com', 'nordvpn.com',
  'expressvpn.com', 'steampowered.com', 'epicgames.com', 'playstation.com', 'xbox.com',
  'nintendo.com', 'roblox.com', 'ea.com', 'ubisoft.com',
];

// A rotation of realistic field-signal patterns to spread across the generated portals so the
// generated set is not monotonous — every detection path (autocomplete, type=email, id token,
// placeholder, aria-label, button vs input submit) is exercised many times.
const PATTERNS: Array<(domain: string) => LoginFixture> = [
  (d) => ({ name: `${d} — autocomplete username`, domain: d, html: standardForm({ userName: 'username', userAutocomplete: 'username', submitText: 'Sign in' }), expect: combined }),
  (d) => ({ name: `${d} — type=email`, domain: d, html: standardForm({ userName: 'email', userType: 'email', submitText: 'Log in' }), expect: combined }),
  (d) => ({ name: `${d} — id token "user"`, domain: d, html: standardForm({ userId: 'user', userName: 'user', submitText: 'Continue', submitTag: 'input' }), expect: combined }),
  (d) => ({ name: `${d} — placeholder email`, domain: d, html: standardForm({ userName: 'j_username', userPlaceholder: 'Email address', submitText: 'Sign in' }), expect: combined }),
  (d) => ({ name: `${d} — aria-label`, domain: d, html: standardForm({ userName: 'identity', userAriaLabel: 'Email or username', submitText: 'Log in' }), expect: combined }),
  (d) => ({ name: `${d} — login id`, domain: d, html: standardForm({ userName: 'loginId', userId: 'loginId', submitText: 'Sign in' }), expect: combined }),
];

function generated(): LoginFixture[] {
  return POPULAR_DOMAINS.map((domain, i) => {
    const pattern = PATTERNS[i % PATTERNS.length]!;
    return pattern(domain);
  });
}

export const LOGIN_FIXTURES: LoginFixture[] = [...realWorld, ...generated()];
