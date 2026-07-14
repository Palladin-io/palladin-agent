import { isDeepStrictEqual } from 'node:util';
import { expect } from 'vitest';

export function expectSensitiveEqual(actual: unknown, expected: unknown, label = 'sensitive value'): void {
  expect(isDeepStrictEqual(actual, expected), label).toBe(true);
}

export function expectSensitiveNotEqual(actual: unknown, expected: unknown, label = 'sensitive value'): void {
  expect(!isDeepStrictEqual(actual, expected), label).toBe(true);
}

export function expectSensitiveContains(actual: string, expected: string, label = 'sensitive value'): void {
  expect(actual.includes(expected), label).toBe(true);
}

export function expectSensitiveExcludes(actual: string, forbidden: string, label = 'sensitive value'): void {
  expect(!actual.includes(forbidden), label).toBe(true);
}

export function expectSensitiveMatches(actual: string, pattern: RegExp, label = 'sensitive value'): void {
  expect(pattern.test(actual), label).toBe(true);
}
