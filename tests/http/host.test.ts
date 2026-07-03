import { describe, it, expect } from 'vitest';
import { assertSecureHost, isLocalHost } from '../../src/http/client.js';

describe('assertSecureHost (CVT-219)', () => {
  it('allows https to any host', () => {
    expect(() => assertSecureHost('https://api.palladin.io')).not.toThrow();
    expect(() => assertSecureHost('https://api.stage.palladin.io')).not.toThrow();
  });

  it('allows http only for loopback hosts (local dev)', () => {
    expect(() => assertSecureHost('http://localhost:5000')).not.toThrow();
    expect(() => assertSecureHost('http://127.0.0.1:5000')).not.toThrow();
    expect(() => assertSecureHost('http://api.dev.localhost')).not.toThrow();
    expect(() => assertSecureHost('http://[::1]:5000')).not.toThrow();
  });

  it('rejects http to a remote host (would leak the API key in cleartext)', () => {
    expect(() => assertSecureHost('http://api.palladin.io')).toThrow(/cleartext/i);
    expect(() => assertSecureHost('http://192.168.1.10:5000')).toThrow(/cleartext/i);
  });

  it('rejects unsupported schemes', () => {
    expect(() => assertSecureHost('ftp://api.palladin.io')).toThrow(/scheme/i);
    expect(() => assertSecureHost('ws://localhost:5000')).toThrow(/scheme/i);
  });

  it('rejects an unparseable host', () => {
    expect(() => assertSecureHost('not a url')).toThrow(/invalid/i);
  });
});

describe('isLocalHost', () => {
  it('recognises loopback hosts', () => {
    expect(isLocalHost('localhost')).toBe(true);
    expect(isLocalHost('LOCALHOST')).toBe(true);
    expect(isLocalHost('127.0.0.1')).toBe(true);
    expect(isLocalHost('::1')).toBe(true);
    expect(isLocalHost('foo.localhost')).toBe(true);
  });

  it('rejects remote hosts', () => {
    expect(isLocalHost('api.palladin.io')).toBe(false);
    expect(isLocalHost('192.168.1.10')).toBe(false);
    expect(isLocalHost('notlocalhost.io')).toBe(false);
  });
});
