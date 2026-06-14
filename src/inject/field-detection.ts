/**
 * Login-form field detection (CVT-151). Pure DOM heuristics — the same approach password managers
 * (1Password, Bitwarden) use — so the CLI never asks the agent's LLM for JavaScript to run on the
 * page (that would hand the page our secret and open a prompt-injection channel). The agent may
 * optionally supply explicit selectors; otherwise we infer them here.
 *
 * The function is intentionally dependency-free and uses only standard DOM APIs, so it runs both
 * in the live page (via Playwright) and against parsed HTML in unit tests.
 *
 * Multi-step / multi-view forms (Google, Microsoft, many SSOs) ask for the identifier on one view
 * and the password on the next. We model this as a state: a view with a username field but no
 * usable password field is `username-step`; a view with a password field is `password-step`; a view
 * with both is `combined`.
 */

export type LoginStep = 'combined' | 'username-step' | 'password-step' | 'none';

export interface DetectedFields {
  step: LoginStep;
  usernameSelector: string | null;
  passwordSelector: string | null;
  /** The best submit/next candidate (first of [submitCandidates]); null when none found. */
  submitSelector: string | null;
  /**
   * All plausible submit/next controls in priority order. The runner clicks the first one that is
   * actually visible at click time — pure-DOM detection cannot see CSS visibility, so an explicit
   * `input[type=submit]` may be hidden (e.g. Facebook) while the real control is a `div[role=button]`.
   */
  submitCandidates: string[];
}

export interface SelectorOverrides {
  usernameSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
}

// Minimal structural subset of the DOM we rely on — lets callers pass a real Document or a parsed
// one without pulling in lib.dom types at every call site.
interface ElementLike {
  readonly tagName: string;
  readonly textContent?: string | null;
  getAttribute(name: string): string | null;
  closest(selector: string): ElementLike | null;
}
interface DocumentLike {
  querySelector(selector: string): ElementLike | null;
  querySelectorAll(selector: string): ArrayLike<ElementLike>;
}

const USERNAME_AUTOCOMPLETE = ['username', 'email'];
// Token patterns matched against name/id/placeholder/aria-label of a candidate text/email input.
// NOTE on localisation: the strong detection signals (autocomplete, input[type=email], and the
// name/id attributes — which are developer code, not UI text) are language-INVARIANT, so this token
// list only matters as a fallback when a field exposes ONLY a localised placeholder/aria-label. The
// English tokens cover the code-attribute case; the extra-language tokens widen the placeholder/
// aria-label fallback for the biggest locales. Real misses are recorded by the failure-capture
// (with the localised strings) so this list can be extended deliberately rather than by guesswork.
const USERNAME_TOKENS = [
  // English / code attributes (the common case, language-independent in practice)
  'email', 'e-mail', 'username', 'user-name', 'userid', 'user-id', 'user', 'login',
  'loginid', 'login-id', 'account', 'identifier', 'ident', 'phone', 'mobile', 'msisdn',
  // Localised placeholder/aria-label fallbacks (major locales)
  'correo', 'courriel', 'correo-electrónico', 'correo electrónico', // es / fr
  'usuario', 'utilisateur', 'benutzer', 'benutzername', // es / fr / de
  'identifiant', 'anmeldung', 'konto', 'cuenta', 'compte', // fr / de / es
  'teléfono', 'telefon', 'téléphone', 'móvil', 'handy', 'numer', 'numéro', // phone, various
  'e-poczta', 'poczta', 'użytkownik', 'login-użytkownika', // pl
];
// Tokens that disqualify a text input from being the username (search boxes, OTP, etc.).
const USERNAME_NEGATIVE_TOKENS = ['search', 'query', 'suche', 'recherche', 'buscar', 'szukaj', 'otp', 'code', 'token', 'captcha', 'coupon', 'promo', 'zip', 'postal'];

// Submit detection prefers button[type=submit]/input[type=submit] (language-invariant) FIRST; this
// token list is only a fallback for buttons without an explicit submit type. Hence the multi-locale
// verbs — but most real forms never reach this branch.
const SUBMIT_TOKENS = [
  'login', 'log-in', 'signin', 'sign-in', 'submit', 'continue', 'next',
  'connexion', 'connecter', 'suivant', // fr
  'anmelden', 'einloggen', 'weiter', // de
  'entrar', 'iniciar', 'continuar', 'siguiente', 'acceder', // es
  'accedi', 'avanti', // it
  'zaloguj', 'dalej', 'kontynuuj', // pl
  'войти', 'продолжить', // ru
  'ログイン', '次へ', // ja
];

function attrs(el: ElementLike): string {
  return [
    el.getAttribute('name'),
    el.getAttribute('id'),
    el.getAttribute('placeholder'),
    el.getAttribute('aria-label'),
    el.getAttribute('data-testid'),
    el.getAttribute('autocomplete'),
  ]
    .filter((v): v is string => !!v)
    .join(' ')
    .toLowerCase();
}

function escapeAttr(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// Build a stable, specific selector for an element. Prefer id, then attributes that uniquely
// identify SPA controls (data-testid, name, aria-label), then type/role — a bare tag is the last
// resort. The aria-label / data-testid / role steps matter for `div[role=button]` submit controls
// (X / Facebook) that carry no id or name.
function selectorFor(el: ElementLike): string {
  const tag = el.tagName.toLowerCase();
  const id = el.getAttribute('id');
  if (id) {
    return `#${cssEscapeId(id)}`;
  }
  const testid = el.getAttribute('data-testid');
  if (testid) {
    return `${tag}[data-testid="${escapeAttr(testid)}"]`;
  }
  const name = el.getAttribute('name');
  if (name) {
    return `${tag}[name="${escapeAttr(name)}"]`;
  }
  const ariaLabel = el.getAttribute('aria-label');
  if (ariaLabel) {
    return `${tag}[aria-label="${escapeAttr(ariaLabel)}"]`;
  }
  const type = el.getAttribute('type');
  if (type) {
    return `${tag}[type="${escapeAttr(type)}"]`;
  }
  const role = el.getAttribute('role');
  if (role) {
    return `${tag}[role="${escapeAttr(role)}"]`;
  }
  return tag;
}

// IDs may contain characters that need escaping in a CSS selector (`:`, `.`). Conservative escape.
function cssEscapeId(id: string): string {
  return id.replace(/([ #.;?%&,@+*~':"!^$[\]()=>|/\\])/g, '\\$1');
}

function hasToken(haystack: string, tokens: string[]): boolean {
  return tokens.some((t) => haystack.includes(t));
}

function toArray(list: ArrayLike<ElementLike>): ElementLike[] {
  const out: ElementLike[] = [];
  for (let i = 0; i < list.length; i++) {
    const el = list[i];
    if (el) {
      out.push(el);
    }
  }
  return out;
}

function isHidden(el: ElementLike): boolean {
  const type = (el.getAttribute('type') ?? '').toLowerCase();
  if (type === 'hidden') {
    return true;
  }
  const style = (el.getAttribute('style') ?? '').toLowerCase();
  if (style.includes('display:none') || style.includes('display: none')) {
    return true;
  }
  if (el.getAttribute('aria-hidden') === 'true') {
    return true;
  }
  return false;
}

/**
 * Find the password input: the first visible `input[type=password]` (with `autocomplete` other than
 * `new-password`, to skip "create account" forms when a sign-in field is present).
 */
function findPassword(doc: DocumentLike): ElementLike | null {
  const candidates = toArray(doc.querySelectorAll('input[type="password"]')).filter((el) => !isHidden(el));
  if (candidates.length === 0) {
    return null;
  }
  const currentFirst = candidates.find((el) => (el.getAttribute('autocomplete') ?? '') === 'current-password');
  return currentFirst ?? candidates[0] ?? null;
}

/**
 * Find the username input. Priority:
 *  1. autocomplete=username | email (the standards-blessed signal)
 *  2. input[type=email]
 *  3. a text/tel input whose attributes match a username token and not a negative token
 * A visible password field, if present, anchors the search to the same form so we don't grab an
 * unrelated text box elsewhere on the page.
 */
function findUsername(doc: DocumentLike, password: ElementLike | null): ElementLike | null {
  const form = password?.closest('form') ?? null;

  const scopedQuery = (selector: string): ElementLike[] => {
    const all = toArray(doc.querySelectorAll(selector)).filter((el) => !isHidden(el));
    if (!form) {
      return all;
    }
    const inForm = all.filter((el) => el.closest('form') === form);
    return inForm.length > 0 ? inForm : all;
  };

  for (const ac of USERNAME_AUTOCOMPLETE) {
    const byAutocomplete = scopedQuery(`input[autocomplete="${ac}"]`).find((el) => !isHidden(el));
    if (byAutocomplete) {
      return byAutocomplete;
    }
  }

  const byEmailType = scopedQuery('input[type="email"]')[0];
  if (byEmailType) {
    return byEmailType;
  }

  const textInputs = scopedQuery('input[type="text"], input[type="tel"], input:not([type])');
  const byToken = textInputs.find((el) => {
    const a = attrs(el);
    return hasToken(a, USERNAME_TOKENS) && !hasToken(a, USERNAME_NEGATIVE_TOKENS);
  });
  if (byToken) {
    return byToken;
  }

  // Fallback: a lone text input that sits in the same form as a password field is almost certainly
  // the username, even without recognizable tokens.
  if (form && textInputs.length === 1) {
    return textInputs[0] ?? null;
  }

  return null;
}

// Normalise away spaces / hyphens / underscores so a label like "Log in" matches the token "login"
// and "Sign-in" matches "signin". Applied to both sides of the submit-token comparison.
function normSubmit(value: string): string {
  return value.toLowerCase().replace(/[\s_-]+/g, '');
}

const SUBMIT_TOKENS_NORM = SUBMIT_TOKENS.map(normSubmit);

// A button's submit "label" — its visible text PLUS code attributes. textContent is what carries the
// label on SPA buttons (X/Facebook render submit as `div[role=button]` with the word as text, not as
// value/aria-label), so it is essential here.
function submitLabel(el: ElementLike): string {
  return normSubmit(
    [
      el.getAttribute('value'),
      el.getAttribute('aria-label'),
      el.getAttribute('id'),
      el.getAttribute('name'),
      el.getAttribute('data-testid'),
      el.textContent ?? null,
    ]
      .filter((v): v is string => !!v)
      .join(' '),
  );
}

function matchesSubmit(el: ElementLike): boolean {
  const label = submitLabel(el);
  return SUBMIT_TOKENS_NORM.some((t) => label.includes(t));
}

/**
 * Submit/next candidates in priority order (dedup, never hidden):
 *   1. explicit `button[type=submit]` / `input[type=submit]`
 *   2. `button` / `[role=button]` / `a[role=button]` whose label matches a submit/next verb
 *      (incl. visible text — covers SPA `div[role=button]` controls)
 *   3. a lone button in the form, by elimination
 * The runner picks the first that is actually visible at click time.
 */
function findSubmitCandidates(doc: DocumentLike, anchor: ElementLike | null): ElementLike[] {
  const form = anchor?.closest('form') ?? null;
  const scope = (selector: string): ElementLike[] => {
    const all = toArray(doc.querySelectorAll(selector)).filter((el) => !isHidden(el));
    if (!form) {
      return all;
    }
    const inForm = all.filter((el) => el.closest('form') === form);
    return inForm.length > 0 ? inForm : all;
  };

  const out: ElementLike[] = [];
  const add = (el: ElementLike | undefined | null): void => {
    if (el && !out.includes(el)) {
      out.push(el);
    }
  };

  for (const el of scope('button[type="submit"], input[type="submit"]')) {
    add(el);
  }
  const buttons = scope('button, input[type="button"], [role="button"], a[role="button"]');
  for (const el of buttons) {
    if (matchesSubmit(el)) {
      add(el);
    }
  }
  if (buttons.length === 1) {
    add(buttons[0]);
  }
  return out;
}

export function detectLoginFields(doc: DocumentLike, overrides?: SelectorOverrides): DetectedFields {
  const password = overrides?.passwordSelector ? doc.querySelector(overrides.passwordSelector) : findPassword(doc);
  const username = overrides?.usernameSelector
    ? doc.querySelector(overrides.usernameSelector)
    : findUsername(doc, password);

  const anchor = password ?? username;

  const usernameSelector = overrides?.usernameSelector ?? (username ? selectorFor(username) : null);
  const passwordSelector = overrides?.passwordSelector ?? (password ? selectorFor(password) : null);

  const submitCandidates = overrides?.submitSelector
    ? [overrides.submitSelector]
    : findSubmitCandidates(doc, anchor).map(selectorFor);
  const submitSelector = submitCandidates[0] ?? null;

  let step: LoginStep;
  if (password && username) {
    step = 'combined';
  } else if (password) {
    step = 'password-step';
  } else if (username) {
    step = 'username-step';
  } else {
    step = 'none';
  }

  return { step, usernameSelector, passwordSelector, submitSelector, submitCandidates };
}
