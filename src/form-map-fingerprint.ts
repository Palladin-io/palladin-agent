import { createHash } from 'node:crypto';
import type { FormDiscoveryMap } from './form-map.js';

export function formMapFingerprint(map: Pick<FormDiscoveryMap, 'domain' | 'loginUrl' | 'form'>): string {
  const shape = JSON.stringify({ domain: map.domain, loginUrl: new URL(map.loginUrl).pathname, form: map.form });
  return createHash('sha256').update(shape).digest('hex');
}
