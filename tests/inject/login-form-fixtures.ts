/**
 * Login-form fixtures for the field-detection heuristic (CVT-151). Each fixture reproduces the
 * *known field-identification signals* of a real service's sign-in form — the attributes a password
 * manager keys off (input types, autocomplete, name/id, placeholder, aria-label) and the flow shape
 * (combined vs multi-step) — not a byte-for-byte scrape. They exercise every detection path against
 * the structures the most popular portals actually use, plus deliberately awkward real-world cases
 * (no <form> wrapper, aria-label-only, React data-testid, a search box beside the sign-in form,
 * new-password vs current-password).
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

const COMBINED = { step: 'combined' as const, username: true, password: true, submit: true };
const USERNAME_STEP = { step: 'username-step' as const, username: true, password: false, submit: true };
const PASSWORD_STEP = { step: 'password-step' as const, username: false, password: true, submit: true };

// Combined form keyed by whatever signal the real site uses; only set what that site actually sets.
function combinedForm(u: {
  userType?: string;
  userName?: string;
  userId?: string;
  userAutocomplete?: string;
  userPlaceholder?: string;
  userAriaLabel?: string;
  passName?: string;
  passId?: string;
  passAutocomplete?: string;
  submitText?: string;
  submitTag?: 'button' | 'input';
  /** Omit the <form> wrapper to model React SPA sign-ins. */
  noForm?: boolean;
}): string {
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
    u.passName ? `name="${u.passName}"` : 'name="password"',
    u.passId ? `id="${u.passId}"` : '',
    `autocomplete="${u.passAutocomplete ?? 'current-password'}"`,
  ].filter(Boolean).join(' ');
  const submit = u.submitTag === 'input'
    ? `<input type="submit" value="${u.submitText ?? 'Log in'}">`
    : `<button type="submit">${u.submitText ?? 'Log in'}</button>`;
  const inner = `<input ${userAttrs}><input ${passAttrs}>${submit}`;
  return u.noForm
    ? `<!doctype html><html><body><div class="login">${inner}</div></body></html>`
    : `<!doctype html><html><body><form>${inner}</form></body></html>`;
}

// Identifier-only first view (multi-step / SSO).
function usernameStepForm(u: {
  userType?: string;
  userName?: string;
  userId?: string;
  userAutocomplete?: string;
  userPlaceholder?: string;
  userAriaLabel?: string;
  nextText?: string;
}): string {
  const attrs = [
    `type="${u.userType ?? 'text'}"`,
    u.userName ? `name="${u.userName}"` : '',
    u.userId ? `id="${u.userId}"` : '',
    u.userAutocomplete ? `autocomplete="${u.userAutocomplete}"` : '',
    u.userPlaceholder ? `placeholder="${u.userPlaceholder}"` : '',
    u.userAriaLabel ? `aria-label="${u.userAriaLabel}"` : '',
  ].filter(Boolean).join(' ');
  return `<!doctype html><html><body><form><input ${attrs}><button type="submit">${u.nextText ?? 'Next'}</button></form></body></html>`;
}

function passwordStepForm(passAutocomplete = 'current-password', submitText = 'Sign in'): string {
  return `<!doctype html><html><body><form><input type="password" name="password" autocomplete="${passAutocomplete}"><button type="submit">${submitText}</button></form></body></html>`;
}

// ── Top services — faithful to each site's real sign-in field signals ────────────────────────────
const services: LoginFixture[] = [
  // Multi-step identifier-first flows.
  { name: 'Google — identifier step', domain: 'google.com', html: usernameStepForm({ userId: 'identifierId', userName: 'identifier', userType: 'email', userAutocomplete: 'username', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Google — password step', domain: 'google.com', html: passwordStepForm('current-password', 'Next'), expect: PASSWORD_STEP },
  { name: 'Microsoft — loginfmt step', domain: 'microsoft.com', html: usernameStepForm({ userName: 'loginfmt', userType: 'email', userAutocomplete: 'username', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Microsoft — password step', domain: 'live.com', html: passwordStepForm('current-password', 'Sign in'), expect: PASSWORD_STEP },
  { name: 'X / Twitter — username step', domain: 'x.com', html: usernameStepForm({ userName: 'text', userType: 'text', userAutocomplete: 'username', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Amazon — email step', domain: 'amazon.com', html: usernameStepForm({ userId: 'ap_email', userName: 'email', userType: 'email', userAutocomplete: 'username', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'PayPal — email step', domain: 'paypal.com', html: usernameStepForm({ userId: 'email', userName: 'login_email', userType: 'email', userAutocomplete: 'username', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Yahoo — username step', domain: 'yahoo.com', html: usernameStepForm({ userId: 'login-username', userName: 'username', userType: 'text', userAutocomplete: 'username', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'eBay — userid step', domain: 'ebay.com', html: usernameStepForm({ userId: 'userid', userName: 'userid', userType: 'text', userPlaceholder: 'Email or username', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Coinbase — email step', domain: 'coinbase.com', html: usernameStepForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Adobe — email step', domain: 'adobe.com', html: usernameStepForm({ userId: 'EmailPage-EmailField', userName: 'username', userType: 'email', userAutocomplete: 'username', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Okta — identifier step', domain: 'okta.com', html: usernameStepForm({ userName: 'identifier', userType: 'text', userAutocomplete: 'username', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Atlassian — username step', domain: 'atlassian.com', html: usernameStepForm({ userId: 'username', userName: 'username', userType: 'email', userAutocomplete: 'username', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Binance — email step', domain: 'binance.com', html: usernameStepForm({ userName: 'username', userType: 'text', userAutocomplete: 'username', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'WhatsApp — phone step', domain: 'whatsapp.com', html: usernameStepForm({ userName: 'phone', userType: 'tel', userPlaceholder: 'Phone number', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Telegram — phone step', domain: 'telegram.org', html: usernameStepForm({ userName: 'phone', userType: 'tel', userAriaLabel: 'Your phone number', nextText: 'Next' }), expect: USERNAME_STEP },

  // Combined (single-view) sign-ins, each with its real field names.
  { name: 'Facebook', domain: 'facebook.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'text', passId: 'pass', passName: 'pass', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Instagram (aria-label, no email type)', domain: 'instagram.com', html: combinedForm({ userName: 'username', userType: 'text', userAriaLabel: 'Phone number, username, or email address', passName: 'password', submitText: 'Log in', noForm: true }), expect: COMBINED },
  { name: 'GitHub', domain: 'github.com', html: combinedForm({ userId: 'login_field', userName: 'login', userType: 'text', userPlaceholder: 'Username or email address', passId: 'password', passName: 'password', submitText: 'Sign in', submitTag: 'input' }), expect: COMBINED },
  { name: 'GitLab', domain: 'gitlab.com', html: combinedForm({ userId: 'user_login', userName: 'user[login]', userType: 'text', passName: 'user[password]', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'LinkedIn', domain: 'linkedin.com', html: combinedForm({ userId: 'username', userName: 'session_key', userType: 'text', userAutocomplete: 'username', passId: 'password', passName: 'session_password', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'Reddit', domain: 'reddit.com', html: combinedForm({ userId: 'loginUsername', userName: 'username', userType: 'text', userPlaceholder: 'Username', passId: 'loginPassword', submitText: 'Log In', noForm: true }), expect: COMBINED },
  { name: 'Netflix', domain: 'netflix.com', html: combinedForm({ userName: 'userLoginId', userType: 'text', userPlaceholder: 'Email or phone number', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Twitch', domain: 'twitch.tv', html: combinedForm({ userId: 'login-username', userName: 'username', userType: 'text', userAutocomplete: 'username', passId: 'password-input', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Spotify', domain: 'spotify.com', html: combinedForm({ userId: 'login-username', userName: 'username', userType: 'text', userAutocomplete: 'username', userPlaceholder: 'Email or username', passId: 'login-password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Discord', domain: 'discord.com', html: combinedForm({ userName: 'email', userType: 'text', userAriaLabel: 'Email or Phone Number', passName: 'password', submitText: 'Log In', noForm: true }), expect: COMBINED },
  { name: 'Snapchat', domain: 'snapchat.com', html: combinedForm({ userId: 'username', userName: 'username', userType: 'text', userPlaceholder: 'Username or email', passId: 'password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Pinterest', domain: 'pinterest.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', passName: 'password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'TikTok', domain: 'tiktok.com', html: combinedForm({ userName: 'username', userType: 'text', userPlaceholder: 'Email or username', passName: 'password', submitText: 'Log in', noForm: true }), expect: COMBINED },
  { name: 'Dropbox', domain: 'dropbox.com', html: combinedForm({ userName: 'login_email', userType: 'email', userAutocomplete: 'username', passName: 'login_password', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'Slack', domain: 'slack.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Zoom', domain: 'zoom.us', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', passId: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'WordPress', domain: 'wordpress.com', html: combinedForm({ userId: 'user_login', userName: 'log', userType: 'text', passId: 'user_pass', passName: 'pwd', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Wikipedia', domain: 'wikipedia.org', html: combinedForm({ userId: 'wpName1', userName: 'wpName', userType: 'text', passId: 'wpPassword1', passName: 'wpPassword', submitText: 'Log in' }), expect: COMBINED },
  { name: 'Apple (aria-label Apple ID)', domain: 'apple.com', html: combinedForm({ userName: 'accountName', userType: 'text', userAriaLabel: 'Apple ID', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Stripe', domain: 'stripe.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', submitText: 'Continue' }), expect: COMBINED },
  { name: 'Shopify', domain: 'shopify.com', html: combinedForm({ userName: 'account[email]', userType: 'email', userAutocomplete: 'email', submitText: 'Log in' }), expect: COMBINED },
  { name: 'Salesforce', domain: 'salesforce.com', html: combinedForm({ userId: 'username', userName: 'username', userType: 'text', userAutocomplete: 'username', passId: 'password', submitText: 'Log In', submitTag: 'input' }), expect: COMBINED },
  { name: 'Auth0', domain: 'auth0.com', html: combinedForm({ userName: 'username', userType: 'text', userAutocomplete: 'username', passName: 'password', submitText: 'Continue', noForm: true }), expect: COMBINED },
  { name: 'Bank of America', domain: 'bankofamerica.com', html: combinedForm({ userId: 'onlineId1', userName: 'onlineId1', userType: 'text', userPlaceholder: 'Online ID', passId: 'passcode1', passName: 'passcode1', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Chase', domain: 'chase.com', html: combinedForm({ userId: 'userId-input-field', userName: 'userId', userType: 'text', userPlaceholder: 'Username', passId: 'password-input-field', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'Wells Fargo', domain: 'wellsfargo.com', html: combinedForm({ userId: 'userid', userName: 'userid', userType: 'text', userPlaceholder: 'Username', passId: 'password', submitText: 'Sign On' }), expect: COMBINED },
  { name: 'Steam', domain: 'steampowered.com', html: combinedForm({ userId: 'input_username', userName: 'username', userType: 'text', userPlaceholder: 'Sign in with account name', passId: 'input_password', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'Epic Games', domain: 'epicgames.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Roblox', domain: 'roblox.com', html: combinedForm({ userId: 'login-username', userName: 'username', userType: 'text', userPlaceholder: 'Username/Email/Phone', passId: 'login-password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'PlayStation', domain: 'playstation.com', html: combinedForm({ userId: 'signin-entrance-input-signinId', userName: 'signinId', userType: 'email', userAutocomplete: 'username', passId: 'signin-password-input-password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Xbox', domain: 'xbox.com', html: usernameStepForm({ userName: 'loginfmt', userType: 'email', userAutocomplete: 'username', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Nintendo', domain: 'nintendo.com', html: combinedForm({ userId: 'login_id', userName: 'username', userType: 'text', userPlaceholder: 'Sign-in ID / Email address', passId: 'password', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'Booking.com', domain: 'booking.com', html: usernameStepForm({ userId: 'username', userName: 'username', userType: 'email', userAutocomplete: 'username', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Airbnb', domain: 'airbnb.com', html: combinedForm({ userName: 'user[email]', userType: 'email', userAutocomplete: 'username', submitText: 'Continue' }), expect: COMBINED },
  { name: 'Uber', domain: 'uber.com', html: usernameStepForm({ userId: 'PHONE_NUMBER_or_EMAIL_ADDRESS', userName: 'userInputData', userType: 'text', userPlaceholder: 'Enter phone number or email', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Coinbase Pro / exchange', domain: 'pro.coinbase.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', passName: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Robinhood', domain: 'robinhood.com', html: combinedForm({ userName: 'username', userType: 'text', userAutocomplete: 'username', passName: 'password', submitText: 'Log In', noForm: true }), expect: COMBINED },
  { name: 'American Express', domain: 'americanexpress.com', html: combinedForm({ userId: 'eliloUserID', userName: 'UserID', userType: 'text', userPlaceholder: 'User ID', passId: 'eliloPassword', passName: 'Password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Citibank', domain: 'citibank.com', html: combinedForm({ userId: 'username', userName: 'username', userType: 'text', userPlaceholder: 'User ID', passId: 'password', submitText: 'Sign On' }), expect: COMBINED },
  { name: 'Capital One', domain: 'capitalone.com', html: combinedForm({ userId: 'username', userName: 'username', userType: 'text', userPlaceholder: 'Username', passId: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Fidelity', domain: 'fidelity.com', html: combinedForm({ userId: 'userId-input', userName: 'userId', userType: 'text', userPlaceholder: 'Username', passId: 'password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Charles Schwab', domain: 'schwab.com', html: combinedForm({ userId: 'loginIdInput', userName: 'LoginId', userType: 'text', userPlaceholder: 'Login ID', passId: 'passwordInput', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Venmo', domain: 'venmo.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', passName: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Notion', domain: 'notion.so', html: usernameStepForm({ userId: 'notion-email-input', userName: 'email', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'Enter your email address...', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Figma', domain: 'figma.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'current-password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'Canva', domain: 'canva.com', html: usernameStepForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'Email', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Stack Overflow', domain: 'stackoverflow.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'Mailchimp', domain: 'mailchimp.com', html: combinedForm({ userId: 'username', userName: 'username', userType: 'text', userPlaceholder: 'Username', passId: 'password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'HubSpot', domain: 'hubspot.com', html: combinedForm({ userId: 'username', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'Zendesk', domain: 'zendesk.com', html: combinedForm({ userId: 'user_email', userName: 'user[email]', userType: 'email', userAutocomplete: 'username', passId: 'user_password', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'Cloudflare', domain: 'cloudflare.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', passName: 'password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'DigitalOcean', domain: 'digitalocean.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Heroku', domain: 'heroku.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'GoDaddy', domain: 'godaddy.com', html: combinedForm({ userId: 'username', userName: 'username', userType: 'text', userPlaceholder: 'Username or Customer #', passId: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Squarespace', domain: 'squarespace.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', passName: 'password', submitText: 'Log In', noForm: true }), expect: COMBINED },
  { name: 'Wix', domain: 'wix.com', html: combinedForm({ userId: 'input_email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'input_password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Proton Mail', domain: 'proton.me', html: combinedForm({ userId: 'username', userName: 'username', userType: 'text', userAutocomplete: 'username', passId: 'password', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'Zoho', domain: 'zoho.com', html: usernameStepForm({ userId: 'login_id', userName: 'LOGIN_ID', userType: 'text', userPlaceholder: 'Email address or mobile number', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Oracle Cloud', domain: 'oracle.com', html: combinedForm({ userId: 'idcs-signin-basic-signin-form-username', userName: 'username', userType: 'text', passId: 'idcs-signin-basic-signin-form-password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Workday', domain: 'workday.com', html: combinedForm({ userId: 'username', userName: 'username', userType: 'text', userPlaceholder: 'Username', passId: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'ServiceNow', domain: 'servicenow.com', html: combinedForm({ userId: 'user_name', userName: 'user_name', userType: 'text', userPlaceholder: 'Username', passId: 'user_password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'DocuSign', domain: 'docusign.com', html: usernameStepForm({ userId: 'username', userName: 'email', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'Email', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Box', domain: 'box.com', html: combinedForm({ userId: 'login', userName: 'login', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'Bitwarden', domain: 'bitwarden.com', html: usernameStepForm({ userId: 'login_email', userName: 'email', userType: 'email', userAutocomplete: 'username', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: '1Password', domain: '1password.com', html: usernameStepForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'Email', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'NordVPN', domain: 'nordvpn.com', html: usernameStepForm({ userName: 'username', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'Email', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'AliExpress', domain: 'aliexpress.com', html: combinedForm({ userId: 'fm-login-id', userName: 'loginId', userType: 'text', userPlaceholder: 'Email or phone number', passId: 'fm-login-password', passName: 'password', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'DoorDash', domain: 'doordash.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Lyft', domain: 'lyft.com', html: usernameStepForm({ userName: 'phoneNumber', userType: 'tel', userPlaceholder: 'Phone number', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Tumblr', domain: 'tumblr.com', html: combinedForm({ userId: 'signup_email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'signup_password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'Medium', domain: 'medium.com', html: usernameStepForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'Your email', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Quora', domain: 'quora.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', passName: 'password', submitText: 'Login' }), expect: COMBINED },
  { name: 'Bitbucket', domain: 'bitbucket.org', html: usernameStepForm({ userId: 'username', userName: 'username', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'Username or email', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Asana', domain: 'asana.com', html: usernameStepForm({ userName: 'e', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'name@company.com', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Trello', domain: 'trello.com', html: usernameStepForm({ userId: 'user', userName: 'user', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'Enter email', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Monday.com', domain: 'monday.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', passName: 'password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'Intercom', domain: 'intercom.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'Vercel', domain: 'vercel.com', html: usernameStepForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'you@domain.com', nextText: 'Continue with Email' }), expect: USERNAME_STEP },
  { name: 'Netlify', domain: 'netlify.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', passName: 'password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'Namecheap', domain: 'namecheap.com', html: combinedForm({ userId: 'LoginUserName', userName: 'LoginUserName', userType: 'text', userPlaceholder: 'Username', passId: 'LoginPassword', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'SAP', domain: 'sap.com', html: usernameStepForm({ userId: 'j_username', userName: 'j_username', userType: 'text', userAutocomplete: 'username', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'IBM', domain: 'ibm.com', html: usernameStepForm({ userId: 'username', userName: 'username', userType: 'email', userAutocomplete: 'username', userPlaceholder: 'IBMid or email', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'Evernote', domain: 'evernote.com', html: combinedForm({ userId: 'username', userName: 'username', userType: 'text', userPlaceholder: 'Email', passId: 'password', submitText: 'Sign in' }), expect: COMBINED },
  { name: 'Cash App', domain: 'cash.app', html: usernameStepForm({ userName: 'identifier', userType: 'text', userPlaceholder: 'Email or phone', nextText: 'Continue' }), expect: USERNAME_STEP },
  { name: 'EA', domain: 'ea.com', html: usernameStepForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', nextText: 'Next' }), expect: USERNAME_STEP },
  { name: 'Ubisoft', domain: 'ubisoft.com', html: combinedForm({ userName: 'email', userType: 'email', userAutocomplete: 'username', passName: 'password', submitText: 'Log In' }), expect: COMBINED },
  { name: 'ExpressVPN', domain: 'expressvpn.com', html: combinedForm({ userId: 'email', userName: 'email', userType: 'email', userAutocomplete: 'username', passId: 'password', submitText: 'Sign In' }), expect: COMBINED },
  { name: 'Fastmail', domain: 'fastmail.com', html: combinedForm({ userId: 'v-username', userName: 'username', userType: 'text', userAutocomplete: 'username', passId: 'v-password', submitText: 'Log in' }), expect: COMBINED },
  { name: 'iCloud', domain: 'icloud.com', html: usernameStepForm({ userId: 'account_name_text_field', userName: 'accountName', userType: 'email', userAutocomplete: 'username', nextText: 'Continue' }), expect: USERNAME_STEP },
];

// ── Real-world edge cases the heuristic must survive ─────────────────────────────────────────────
const edgeCases: LoginFixture[] = [
  {
    name: 'Edge: sign-in form beside a site search box (must skip search)',
    domain: 'example.com',
    html: `<!doctype html><html><body>
      <input type="search" name="q" placeholder="Search" aria-label="Search">
      <form>
        <input type="email" name="email" autocomplete="username">
        <input type="password" name="password" autocomplete="current-password">
        <button type="submit">Sign in</button>
      </form>
    </body></html>`,
    expect: COMBINED,
  },
  {
    name: 'Edge: change-password form present — pick current-password not new-password',
    domain: 'example.com',
    html: `<!doctype html><html><body><form>
      <input type="text" name="username" autocomplete="username">
      <input type="password" name="newPassword" autocomplete="new-password">
      <input type="password" name="currentPassword" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form></body></html>`,
    expect: COMBINED,
  },
  {
    name: 'Edge: React SPA with no <form> wrapper and data-testid',
    domain: 'example.com',
    html: `<!doctype html><html><body><div>
      <input type="text" data-testid="login-username" autocomplete="username">
      <input type="password" data-testid="login-password" autocomplete="current-password">
      <button type="submit">Continue</button>
    </div></body></html>`,
    expect: COMBINED,
  },
  {
    name: 'Edge: hidden CSRF input must be ignored',
    domain: 'example.com',
    html: `<!doctype html><html><body><form>
      <input type="hidden" name="csrf_token" value="abc123">
      <input type="email" name="email" autocomplete="username">
      <input type="password" name="password">
      <button type="submit">Log in</button>
    </form></body></html>`,
    expect: COMBINED,
  },
];

export const LOGIN_FIXTURES: LoginFixture[] = [...services, ...edgeCases];
