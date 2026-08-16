import { describe, expect, it } from 'vitest';

import { Readable } from 'node:stream';
import { captureRuntimeStderr, providerRuntimeEnvironment } from '../../packages/playwright-mcp/src/agent-runtime.js';

describe('provider runtime environment', () => {
  it('removes the gateway CA override but preserves required safe variables', () => {
    const environment = providerRuntimeEnvironment({
      NODE_EXTRA_CA_CERTS: '/tmp/gateway-ca.pem',
      PATH: '/usr/bin',
      PALLADIN_AGENT_PROFILE: 'openclaw-login-test',
    });
    expect(environment.NODE_EXTRA_CA_CERTS).toBeUndefined();
    expect(environment.PATH).toBe('/usr/bin');
    expect(environment.PALLADIN_AGENT_PROFILE).toBe('openclaw-login-test');
  });

  it('drains bounded stderr without forwarding an unbounded stream', async () => {
    const capture = captureRuntimeStderr(Readable.from([
      'Access was denied by the vault owner.',
      'x'.repeat(100_000),
    ]));
    const stderr = await capture.done;
    expect(stderr.startsWith('Access was denied by the vault owner.')).toBe(true);
    expect(Buffer.byteLength(stderr)).toBeLessThanOrEqual(64 * 1024);
  });
});
