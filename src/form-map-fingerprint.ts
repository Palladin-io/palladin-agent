import { createHash } from 'node:crypto';
import type { FormDiscoveryMap } from './form-map.js';

export function formMapFingerprint(
  map: Pick<FormDiscoveryMap, 'domain' | 'loginUrl' | 'provider' | 'form' | 'cookieOverlays'>,
): string {
  const payload = {
    domain: map.domain,
    loginUrl: new URL(map.loginUrl).pathname,
    provider: map.provider,
    map: {
      version: map.form.version,
      form: {
        version: map.form.version,
        steps: map.form.steps.map((step) => ({
          fields: step.fields.map((field) => ({
            entryFieldId: field.entryFieldId,
            selector: field.selector,
            control: field.control,
          })),
          submit: {
            action: step.submit.action,
            selector: step.submit.selector,
          },
          ...(step.waitFor === undefined ? {} : {
            waitFor: {
              selector: step.waitFor.selector,
              ...(step.waitFor.timeoutMs === undefined ? {} : { timeoutMs: step.waitFor.timeoutMs }),
            },
          }),
        })),
      },
      ...(map.cookieOverlays === undefined || map.cookieOverlays.length === 0
        ? {} : {
          cookieOverlays: map.cookieOverlays.map((overlay) => ({
            selectors: overlay.selectors,
            dismiss: {
              selector: overlay.dismiss.selector,
              action: overlay.dismiss.action,
            },
            ...(overlay.disappears === undefined ? {} : { disappears: overlay.disappears }),
            ...(overlay.frame === undefined ? {} : { frame: overlay.frame }),
          })),
        }),
    },
  };
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}
