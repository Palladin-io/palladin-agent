import { describe, it, expect } from 'vitest';
import { parseDuration } from '../../src/credential/duration.js';

describe('parseDuration', () => {
  it('reads a bare number as seconds', () => {
    expect(parseDuration('30')).toBe(30_000);
    expect(parseDuration('0')).toBe(0);
    expect(parseDuration('90')).toBe(90_000);
  });

  it('reads s / m / h / ms suffixes', () => {
    expect(parseDuration('30s')).toBe(30_000);
    expect(parseDuration('3m')).toBe(180_000);
    expect(parseDuration('1h')).toBe(3_600_000);
    expect(parseDuration('500ms')).toBe(500);
    expect(parseDuration('1.5s')).toBe(1_500);
  });

  it('tolerates whitespace and case', () => {
    expect(parseDuration('  3M ')).toBe(180_000);
  });

  it('throws on garbage', () => {
    expect(() => parseDuration('soon')).toThrow(/invalid duration/);
    expect(() => parseDuration('3 days')).toThrow(/invalid duration/);
    expect(() => parseDuration('')).toThrow(/invalid duration/);
    expect(() => parseDuration('999999999999999999999h')).toThrow(/invalid duration/);
  });
});
