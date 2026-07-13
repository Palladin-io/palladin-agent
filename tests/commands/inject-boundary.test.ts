import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  injectCommand,
  INJECT_UNAVAILABLE,
  INJECT_UNAVAILABLE_EXIT_CODE,
} from '../../src/commands/inject.js';

describe('inject command browser boundary', () => {
  const originalExitCode = process.exitCode;

  afterEach(() => {
    process.exitCode = originalExitCode;
    vi.restoreAllMocks();
  });

  it('rejects a fake CDP endpoint before opening an Agent profile', async () => {
    const getProfile = vi.fn(() => {
      throw new Error('profile must not be opened');
    });
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    await injectCommand(getProfile).parseAsync(
      ['vault-fixture', 'entry-fixture', '--cdp', 'http://127.0.0.1:9222'],
      { from: 'user' },
    );

    expect(getProfile).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledWith(`Error: ${INJECT_UNAVAILABLE} No Agent profile was opened.`);
    expect(process.exitCode).toBe(INJECT_UNAVAILABLE_EXIT_CODE);
  });
});
