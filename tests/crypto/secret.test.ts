import { describe, it, expect } from 'vitest';
import { parseSecret } from '../../src/crypto/secret.js';

describe('parseSecret', () => {
  it('parses a CREDENTIAL payload', () => {
    const s = parseSecret(JSON.stringify({ username: 'alice', password: 'hunter2', url: 'https://x.com', notes: 'n' }));
    expect(s.username).toBe('alice');
    expect(s.password).toBe('hunter2');
    expect(s.url).toBe('https://x.com');
    expect(s.fields).toMatchObject({ username: 'alice', password: 'hunter2' });
  });

  it('parses a KEY payload (value, no username)', () => {
    const s = parseSecret(JSON.stringify({ value: 'sk-abc123', notes: 'api key' }));
    expect(s.username).toBeNull();
    expect(s.password).toBe('sk-abc123');
    expect(s.fields).toMatchObject({ value: 'sk-abc123' });
  });

  it('falls back to raw plaintext when not JSON', () => {
    const s = parseSecret('raw-secret-token');
    expect(s.username).toBeNull();
    expect(s.password).toBe('raw-secret-token');
    expect(s.fields.value).toBe('raw-secret-token');
  });

  it('falls back when JSON is a non-object', () => {
    const s = parseSecret('"just-a-string"');
    expect(s.password).toBe('"just-a-string"');
  });

  it('only keeps string fields', () => {
    const s = parseSecret(JSON.stringify({ value: 'v', count: 5, nested: { a: 1 } }));
    expect(s.fields).toEqual({ value: 'v' });
  });
});
