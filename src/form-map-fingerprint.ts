import { createHash } from 'node:crypto';
import type { FormDiscoveryMap } from './form-map.js';

export function formMapFingerprint(map: Pick<FormDiscoveryMap, 'domain' | 'loginUrl' | 'form'>): string {
  const form = {
    version: map.form.version,
    steps: map.form.steps.map((step) => ({
      fields: step.fields.map((field) => ({
        entryFieldId: field.entryFieldId,
        selector: field.selector,
        control: field.control,
      })),
      submit: { action: step.submit.action, selector: step.submit.selector },
      ...(step.waitFor === undefined ? {} : {
        waitFor: {
          selector: step.waitFor.selector,
          ...(step.waitFor.timeoutMs === undefined ? {} : { timeoutMs: step.waitFor.timeoutMs }),
        },
      }),
    })),
  };
  const shape = JSON.stringify({ domain: map.domain, loginUrl: new URL(map.loginUrl).pathname, form });
  return createHash('sha256').update(shape).digest('hex');
}
