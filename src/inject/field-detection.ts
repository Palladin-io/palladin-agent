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
  submitSelector: string | null;
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
  getAttribute(name: string): string | null;
  closest(selector: string): ElementLike | null;
}
interface DocumentLike {
  querySelector(selector: string): ElementLike | null;
  querySelectorAll(selector: string): ArrayLike<ElementLike>;
}

const USERNAME_AUTOCOMPLETE = ['username', 'email'];
// Token patterns matched against name/id/placeholder/aria-label of a candidate text/email input.
const USERNAME_TOKENS = [
  'email', 'e-mail', 'username', 'user-name', 'userid', 'user-id', 'user', 'login',
  'loginid', 'login-id', 'account', 'identifier', 'ident', 'phone', 'mobile', 'msisdn',
];
// Tokens that disqualify a text input from being the username (search boxes, OTP, etc.).
const USERNAME_NEGATIVE_TOKENS = ['search', 'query', 'otp', 'code', 'token', 'captcha', 'coupon', 'promo', 'zip', 'postal'];

const SUBMIT_TOKENS = [
  'login', 'log-in', 'signin', 'sign-in', 'submit', 'continue', 'next', 'connexion',
  'anmelden', 'einloggen', 'entrar', 'iniciar', 'accedi', 'continuar', 'weiter',
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

// Build a stable, specific selector for an element: prefer id, then name, then a structural fallback.
function selectorFor(el: ElementLike): string {
  const tag = el.tagName.toLowerCase();
  const id = el.getAttribute('id');
  if (id) {
    return `#${cssEscapeId(id)}`;
  }
  const name = el.getAttribute('name');
  if (name) {
    return `${tag}[name="${escapeAttr(name)}"]`;
  }
  const type = el.getAttribute('type');
  if (type) {
    return `${tag}[type="${escapeAttr(type)}"]`;
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

function findSubmit(doc: DocumentLike, anchor: ElementLike | null): ElementLike | null {
  const form = anchor?.closest('form') ?? null;
  const scope = (selector: string): ElementLike[] => {
    const all = toArray(doc.querySelectorAll(selector)).filter((el) => !isHidden(el));
    if (!form) {
      return all;
    }
    const inForm = all.filter((el) => el.closest('form') === form);
    return inForm.length > 0 ? inForm : all;
  };

  const explicitSubmit = scope('button[type="submit"], input[type="submit"]')[0];
  if (explicitSubmit) {
    return explicitSubmit;
  }

  const buttons = scope('button, input[type="button"], [role="button"]');
  const byToken = buttons.find((el) => {
    const text = [el.getAttribute('value'), el.getAttribute('aria-label'), el.getAttribute('id'), el.getAttribute('name')]
      .filter((v): v is string => !!v)
      .join(' ')
      .toLowerCase();
    return hasToken(text, SUBMIT_TOKENS);
  });
  if (byToken) {
    return byToken;
  }

  // A single button in the form is the submit by elimination.
  return buttons.length === 1 ? buttons[0] ?? null : null;
}

export function detectLoginFields(doc: DocumentLike, overrides?: SelectorOverrides): DetectedFields {
  const password = overrides?.passwordSelector ? doc.querySelector(overrides.passwordSelector) : findPassword(doc);
  const username = overrides?.usernameSelector
    ? doc.querySelector(overrides.usernameSelector)
    : findUsername(doc, password);

  const anchor = password ?? username;
  const submit = overrides?.submitSelector ? doc.querySelector(overrides.submitSelector) : findSubmit(doc, anchor);

  const usernameSelector = overrides?.usernameSelector ?? (username ? selectorFor(username) : null);
  const passwordSelector = overrides?.passwordSelector ?? (password ? selectorFor(password) : null);
  const submitSelector = overrides?.submitSelector ?? (submit ? selectorFor(submit) : null);

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

  return { step, usernameSelector, passwordSelector, submitSelector };
}
