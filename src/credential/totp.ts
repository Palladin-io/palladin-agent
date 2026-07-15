import { createHmac } from 'node:crypto';

/**
 * A TOTP field's decrypted descriptor (see Vault Data Model v2 / spec §2). Stored inside the
 * encrypted blob as the `value` of a `totp` custom field — never the raw `otpauth://` URI, and
 * NEVER anything the server can read. `secret` is the shared key, base32-encoded (RFC 4648).
 */
export interface TotpParams {
  secret: string;
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
  digits?: number;
  period?: number;
  issuer?: string;
  account?: string;
}

export interface TotpCode {
  /** The current one-time code, left-padded to `digits`. */
  code: string;
  /** Seconds remaining in the current time window before the code rolls over. */
  expiresIn: number;
}

/** Parse a v2 JSON descriptor, a legacy otpauth URI, or a raw base32 setup key. */
export function parseTotpValue(value: string): TotpParams | null {
  const trimmed = value.trim();
  try {
    const raw = JSON.parse(trimmed) as unknown;
    if (typeof raw === 'object' && raw !== null) {
      const record = raw as Record<string, unknown>;
      if (typeof record.secret === 'string') {
        return normalizedParams(record.secret, record);
      }
    }
  } catch {
    // Legacy values are not JSON.
  }

  if (trimmed.slice(0, 'otpauth://'.length).toLowerCase() === 'otpauth://') {
    try {
      const uri = new URL(trimmed);
      if (uri.protocol !== 'otpauth:' || uri.hostname !== 'totp' || uri.pathname.length <= 1) return null;
      const secret = uri.searchParams.get('secret');
      if (!secret) return null;
      const algorithm = uri.searchParams.get('algorithm');
      const digitsRaw = uri.searchParams.get('digits');
      const periodRaw = uri.searchParams.get('period');
      const digits = numeric(digitsRaw);
      const period = numeric(periodRaw);
      if ((digitsRaw !== null && digits === undefined) || (periodRaw !== null && period === undefined)) {
        return null;
      }
      const record: Record<string, unknown> = {};
      if (algorithm !== null) record.algorithm = algorithm;
      if (digits !== undefined) record.digits = digits;
      if (period !== undefined) record.period = period;
      return normalizedParams(secret, record);
    } catch {
      return null;
    }
  }
  return trimmed ? { secret: trimmed } : null;
}

function normalizedParams(secret: string, record: Record<string, unknown>): TotpParams | null {
  const params: TotpParams = { secret };
  if (Object.hasOwn(record, 'algorithm')) {
    if (typeof record.algorithm !== 'string') return null;
    const algorithm = record.algorithm.toUpperCase();
    if (algorithm !== 'SHA1' && algorithm !== 'SHA256' && algorithm !== 'SHA512') return null;
    params.algorithm = algorithm;
  }
  if (Object.hasOwn(record, 'digits')) {
    if (typeof record.digits !== 'number'
      || !Number.isSafeInteger(record.digits)
      || record.digits < 1
      || record.digits > 10) return null;
    params.digits = record.digits;
  }
  if (Object.hasOwn(record, 'period')) {
    if (typeof record.period !== 'number'
      || !Number.isSafeInteger(record.period)
      || record.period < 1) return null;
    params.period = record.period;
  }
  return params;
}

function numeric(value: string | null): number | undefined {
  if (value === null || !/^\d+$/.test(value)) return undefined;
  return Number(value);
}

const DEFAULT_ALGORITHM = 'SHA1';
const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD = 30;

/**
 * Compute an RFC 6238 TOTP code locally (the server is zero-knowledge and never sees the secret).
 * The shared secret stays in this process; only the derived short-lived code may be surfaced.
 *
 * @param params the field's TOTP descriptor.
 * @param atMs   the instant to compute for, in epoch milliseconds (injectable for tests).
 */
export function generateTotp(params: TotpParams, atMs: number = Date.now()): TotpCode {
  const algorithm = params.algorithm ?? DEFAULT_ALGORITHM;
  const digits = params.digits ?? DEFAULT_DIGITS;
  const period = params.period ?? DEFAULT_PERIOD;

  if (digits < 6 || digits > 8) {
    throw new TotpError(`unsupported TOTP digits: ${digits} (expected 6-8)`);
  }
  if (period < 1) {
    throw new TotpError(`unsupported TOTP period: ${period}`);
  }

  const key = base32Decode(params.secret);
  if (key.length === 0) {
    throw new TotpError('TOTP secret is empty or not valid base32');
  }

  const seconds = Math.floor(atMs / 1000);
  const counter = Math.floor(seconds / period);
  const code = hotp(key, counter, algorithm, digits);
  const expiresIn = period - (seconds % period);
  return { code, expiresIn };
}

/** RFC 4226 HMAC-based OTP — the counter step underlying TOTP. */
function hotp(key: Buffer, counter: number, algorithm: string, digits: number): string {
  const counterBytes = Buffer.alloc(8);
  // 64-bit big-endian counter. writeBigUInt64BE keeps the full range without float precision loss.
  counterBytes.writeBigUInt64BE(BigInt(counter));

  const hmacName = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' }[algorithm];
  if (!hmacName) {
    throw new TotpError(`unsupported TOTP algorithm: ${algorithm}`);
  }

  const digest = createHmac(hmacName, key).update(counterBytes).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);

  return String(binary % 10 ** digits).padStart(digits, '0');
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decode a base32 (RFC 4648) string, tolerant of lowercase, spaces and `=` padding. */
export function base32Decode(input: string): Buffer {
  const clean = input.replace(/[\s=]/g, '').toUpperCase();
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new TotpError(`invalid base32 character in TOTP secret: "${char}"`);
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

/** Encode bytes as base32 (RFC 4648, no padding). Kept alongside the decoder for round-trip tests. */
export function base32Encode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return output;
}

export class TotpError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TotpError';
  }
}
