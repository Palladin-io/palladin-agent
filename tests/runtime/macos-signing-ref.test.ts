import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const source = '0123456789abcdef0123456789abcdef01234567';
function authorize(overrides: Record<string, string> = {}) {
  return spawnSync('/bin/bash', ['packaging/macos/scripts/verify-signing-ref.sh'], {
    env: {
      ACTOR: 'patryk-roguszewski', EVENT_NAME: 'workflow_dispatch', REF_TYPE: 'tag',
      RELEASE_PIPELINE: 'false', SOURCE_SHA: source, TAG_SHA: source,
      MARKETING_VERSION: '0.0.5', REF_NAME: `signing-0.0.5-${source}`,
      ...overrides,
    },
  }).status;
}

describe.skipIf(process.platform === 'win32')('macOS signing authorization', () => {
  it('accepts exact owner candidate and release tags', () => {
    expect(authorize()).toBe(0);
    expect(authorize({ RELEASE_PIPELINE: 'true', REF_NAME: 'v0.0.5' })).toBe(0);
    expect(authorize({ RELEASE_PIPELINE: 'true', REF_NAME: 'v0.0.5+retry.2' })).toBe(0);
  });

  it.each([
    { ACTOR: 'other-maintainer' }, { EVENT_NAME: 'pull_request' }, { REF_TYPE: 'branch' },
    { TAG_SHA: 'a'.repeat(40) }, { SOURCE_SHA: '../main' }, { MARKETING_VERSION: '0.0.5;exit 0' },
    { REF_NAME: 'main' }, { REF_NAME: `signing-0.0.2-${source}` },
    { RELEASE_PIPELINE: 'true' }, { RELEASE_PIPELINE: 'true', REF_NAME: 'v0.0.1' },
    { RELEASE_PIPELINE: 'true', REF_NAME: 'v0.0.5+retry.0' },
    { RELEASE_PIPELINE: 'true', REF_NAME: 'v0.0.5+retry.invalid' },
    { RELEASE_PIPELINE: 'true', REF_NAME: 'v0.0.5+retry.2', MARKETING_VERSION: '0.0.2' },
  ])('rejects mismatched authorization context %j', (context) => {
    expect(authorize(context)).not.toBe(0);
  });
});
