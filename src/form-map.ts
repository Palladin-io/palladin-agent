import { parseInjectForm, type InjectFormDefinition } from './inject-contract.js';

/** Public, value-free login discovery map. It never contains credentials or cookie values. */
export const FORM_MAP_VERSION = 1 as const;
export const MAX_MAP_OVERLAYS = 4;

export type FormMapStatus = 'candidate' | 'observed' | 'verified';
export type FormMapProvider = 'playwright' | 'agent-browser' | 'extension' | 'generic';

export interface CookieOverlayAction {
  selector: string;
  action: 'click';
}

export interface CookieOverlay {
  /** CMP/banner is expected on this public surface; absence is valid. */
  selectors: string[];
  dismiss: CookieOverlayAction;
  disappears?: string;
  frame?: 'top' | 'same-origin';
}

export interface FormDiscoveryMap {
  version: typeof FORM_MAP_VERSION;
  mapVersion?: number;
  domain: string;
  loginUrl: string;
  provider: FormMapProvider;
  status: FormMapStatus;
  fingerprint: string;
  form: InjectFormDefinition;
  cookieOverlays?: CookieOverlay[];
}

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SELECTOR = (value: unknown): value is string => typeof value === 'string'
  && value.length > 0 && utf8Length(value) <= 1024 && value === value.trim() && !value.includes('\0');

/**
 * Parse server-supplied maps fail-closed. Map actions are deliberately limited to clicking a
 * public selector; arbitrary JavaScript, cookie values, URLs and secret-bearing fields are not
 * representable by this contract.
 */
export function parseFormDiscoveryMap(value: unknown): FormDiscoveryMap | null {
  if (!record(value) || !onlyKeys(value, ['version', 'mapVersion', 'domain', 'loginUrl', 'provider', 'status', 'fingerprint', 'form', 'cookieOverlays'])
    || value.version !== FORM_MAP_VERSION || typeof value.domain !== 'string' || !DOMAIN.test(value.domain)
    || typeof value.loginUrl !== 'string' || !isHttpsOrigin(value.loginUrl, value.domain)
    || !['playwright', 'agent-browser', 'extension', 'generic'].includes(String(value.provider))
    || !['candidate', 'observed', 'verified'].includes(String(value.status))
    || typeof value.fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(value.fingerprint)
    || (value.mapVersion !== undefined && (typeof value.mapVersion !== 'number'
      || !Number.isSafeInteger(value.mapVersion) || value.mapVersion < 1
      || value.mapVersion > 2_147_483_647))
    ) return null;
  const form = parseInjectForm(value.form);
  if (form === null) return null;
  if (form.steps.some((step) => step.fields.some((field) => !validLoginField(field)))) return null;
  if (value.cookieOverlays !== undefined) {
    if (!Array.isArray(value.cookieOverlays) || value.cookieOverlays.length > MAX_MAP_OVERLAYS
      || value.cookieOverlays.some((overlay) => !validOverlay(overlay))) return null;
  }
  return { ...value, form } as FormDiscoveryMap;
}

function validLoginField(field: InjectFormDefinition['steps'][number]['fields'][number]): boolean {
  return (field.entryFieldId === 'credential.username'
      && ['email', 'tel', 'text', 'username'].includes(field.control))
    || (field.entryFieldId === 'credential.password' && field.control === 'password');
}

function validOverlay(value: unknown): value is CookieOverlay {
  return record(value) && onlyKeys(value, ['selectors', 'dismiss', 'disappears', 'frame'])
    && Array.isArray(value.selectors) && value.selectors.length > 0 && value.selectors.length <= 8
    && value.selectors.every(SELECTOR) && record(value.dismiss)
    && onlyKeys(value.dismiss, ['selector', 'action']) && value.dismiss.action === 'click'
    && SELECTOR(value.dismiss.selector)
    && (value.disappears === undefined || SELECTOR(value.disappears))
    && (value.frame === undefined || value.frame === 'top' || value.frame === 'same-origin');
}

function isHttpsOrigin(value: string, domain: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && utf8Length(value) <= 2048
      && url.hostname === domain && (url.port === '' || url.port === '443')
      && url.username === '' && url.password === '' && url.hash === ''
      && (url.search === '' || url.search === '?SignIn');
  } catch { return false; }
}
function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}
function onlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys); return Object.keys(value).every((key) => allowed.has(key));
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
