import type { Readable, Writable } from 'node:stream';

const MAX_LINE_BYTES = 256 * 1024;
const MAX_NATIVE_BYTES = 1024 * 1024;

type Pending = { resolve: (value: unknown) => void; reject: (error: Error) => void };

export class JsonLineChannel {
  private buffer = Buffer.alloc(0);
  private readonly pending: Pending[] = [];
  private failure: Error | undefined;

  constructor(private readonly readable: Readable, private readonly writable: Writable) {
    readable.on('data', (chunk: Buffer | string) => this.onData(chunk));
    readable.once('end', () => this.fail(new Error('channel closed')));
    readable.once('error', () => this.fail(new Error('channel failed')));
  }

  read(): Promise<unknown> {
    if (this.failure !== undefined) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      this.pending.push({ resolve, reject });
      this.drain();
    });
  }

  write(value: unknown): void {
    const encoded = `${JSON.stringify(value)}\n`;
    if (Buffer.byteLength(encoded, 'utf8') > MAX_LINE_BYTES) {
      throw new Error('channel frame too large');
    }
    this.writable.write(encoded);
  }
  end(value?: unknown): void { if (value !== undefined) this.write(value); this.writable.end(); }

  private onData(chunk: Buffer | string): void {
    this.buffer = Buffer.concat([this.buffer, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
    if (this.buffer.length > MAX_LINE_BYTES) return this.fail(new Error('channel frame too large'));
    this.drain();
  }

  private drain(): void {
    while (this.pending.length > 0) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline === -1) return;
      const frame = this.buffer.subarray(0, newline);
      this.buffer = this.buffer.subarray(newline + 1);
      const pending = this.pending.shift();
      if (pending === undefined) return;
      try { pending.resolve(JSON.parse(frame.toString('utf8')) as unknown); }
      catch { pending.reject(new Error('channel JSON is invalid')); }
      finally { frame.fill(0); }
    }
  }

  private fail(error: Error): void {
    if (this.failure !== undefined) return;
    this.failure = error;
    for (const pending of this.pending.splice(0)) pending.reject(error);
    this.buffer.fill(0);
    this.buffer = Buffer.alloc(0);
  }
}

export class ChromeNativeChannel {
  private buffer = Buffer.alloc(0);
  private readonly pending: Pending[] = [];
  private failure: Error | undefined;

  constructor(private readonly readable: Readable, private readonly writable: Writable) {
    readable.on('data', (chunk: Buffer | string) => this.onData(chunk));
    readable.once('end', () => this.fail(new Error('native channel closed')));
    readable.once('error', () => this.fail(new Error('native channel failed')));
  }

  read(): Promise<unknown> {
    if (this.failure !== undefined) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      this.pending.push({ resolve, reject });
      this.drain();
    });
  }

  write(value: unknown): void {
    const payload = Buffer.from(JSON.stringify(value), 'utf8');
    if (payload.length > MAX_NATIVE_BYTES) throw new Error('native message too large');
    const header = Buffer.alloc(4);
    header.writeUInt32LE(payload.length, 0);
    this.writable.write(Buffer.concat([header, payload]));
  }

  private onData(chunk: Buffer | string): void {
    this.buffer = Buffer.concat([this.buffer, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
    if (this.buffer.length > MAX_NATIVE_BYTES + 4) return this.fail(new Error('native frame too large'));
    this.drain();
  }

  private drain(): void {
    while (this.pending.length > 0 && this.buffer.length >= 4) {
      const length = this.buffer.readUInt32LE(0);
      if (length === 0 || length > MAX_NATIVE_BYTES) return this.fail(new Error('native frame length is invalid'));
      if (this.buffer.length < length + 4) return;
      const frame = this.buffer.subarray(4, length + 4);
      this.buffer = this.buffer.subarray(length + 4);
      const pending = this.pending.shift();
      if (pending === undefined) return;
      try { pending.resolve(JSON.parse(frame.toString('utf8')) as unknown); }
      catch { pending.reject(new Error('native JSON is invalid')); }
      finally { frame.fill(0); }
    }
  }

  private fail(error: Error): void {
    if (this.failure !== undefined) return;
    this.failure = error;
    for (const pending of this.pending.splice(0)) pending.reject(error);
    this.buffer.fill(0);
    this.buffer = Buffer.alloc(0);
  }
}
