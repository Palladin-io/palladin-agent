import { describe, it, expect } from 'vitest';
import { generateTotp, base32Encode, base32Decode, TotpError } from '../../src/credential/totp.js';

// RFC 6238 Appendix B test seeds (ASCII), encoded to base32 as the field descriptor stores them.
const SEED_SHA1 = base32Encode(Buffer.from('12345678901234567890', 'ascii'));
const SEED_SHA256 = base32Encode(Buffer.from('12345678901234567890123456789012', 'ascii'));
const SEED_SHA512 = base32Encode(Buffer.from('1234567890123456789012345678901234567890123456789012345678901234', 'ascii'));

describe('generateTotp — RFC 6238 Appendix B vectors', () => {
  const cases: Array<{ seconds: number; algorithm: 'SHA1' | 'SHA256' | 'SHA512'; secret: string; code: string }> = [
    { seconds: 59, algorithm: 'SHA1', secret: SEED_SHA1, code: '94287082' },
    { seconds: 59, algorithm: 'SHA256', secret: SEED_SHA256, code: '46119246' },
    { seconds: 59, algorithm: 'SHA512', secret: SEED_SHA512, code: '90693936' },
    { seconds: 1111111109, algorithm: 'SHA1', secret: SEED_SHA1, code: '07081804' },
    { seconds: 1111111111, algorithm: 'SHA1', secret: SEED_SHA1, code: '14050471' },
    { seconds: 1234567890, algorithm: 'SHA1', secret: SEED_SHA1, code: '89005924' },
    { seconds: 2000000000, algorithm: 'SHA1', secret: SEED_SHA1, code: '69279037' },
    { seconds: 20000000000, algorithm: 'SHA1', secret: SEED_SHA1, code: '65353130' },
  ];

  for (const { seconds, algorithm, secret, code } of cases) {
    it(`t=${seconds}s ${algorithm} → ${code}`, () => {
      const result = generateTotp({ secret, algorithm, digits: 8, period: 30 }, seconds * 1000);
      expect(result.code).toBe(code);
    });
  }
});

describe('generateTotp — defaults and window', () => {
  it('defaults to SHA1 / 6 digits / 30s', () => {
    const result = generateTotp({ secret: SEED_SHA1 }, 59 * 1000);
    // The 8-digit SHA1 vector is 94287082 → last 6 digits for the default 6-digit code.
    expect(result.code).toBe('287082');
    expect(result.code).toHaveLength(6);
  });

  it('reports seconds remaining in the current window', () => {
    expect(generateTotp({ secret: SEED_SHA1 }, 59 * 1000).expiresIn).toBe(1); // 59 % 30 = 29 → 1 left
    expect(generateTotp({ secret: SEED_SHA1 }, 30 * 1000).expiresIn).toBe(30); // window boundary
    expect(generateTotp({ secret: SEED_SHA1 }, 45 * 1000).expiresIn).toBe(15);
  });

  it('rejects an empty or non-base32 secret', () => {
    expect(() => generateTotp({ secret: '' })).toThrow(TotpError);
    expect(() => generateTotp({ secret: '!!!!' })).toThrow(TotpError);
  });
});

describe('base32', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = Buffer.from('the quick brown fox', 'utf8');
    expect(base32Decode(base32Encode(bytes)).equals(bytes)).toBe(true);
  });

  it('tolerates lowercase, spaces and padding', () => {
    const canonical = base32Decode('JBSWY3DPEHPK3PXP');
    expect(base32Decode('jbsw y3dp ehpk 3pxp').equals(canonical)).toBe(true);
    expect(base32Decode('JBSWY3DPEHPK3PXP====').equals(canonical)).toBe(true);
  });
});
