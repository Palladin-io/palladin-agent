import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';

import { ChromeNativeChannel, JsonLineChannel } from '../../src/browser-host/channel.js';

describe('browser provider channels', () => {
  it('round-trips fragmented JSON-line frames without mixing messages', async () => {
    const inbound = new PassThrough();
    const outbound = new PassThrough();
    const channel = new JsonLineChannel(inbound, outbound);
    const first = channel.read();
    const second = channel.read();
    inbound.write('{"type":"prepare"}\n{"type":');
    inbound.write('"result"}\n');
    await expect(first).resolves.toEqual({ type: 'prepare' });
    await expect(second).resolves.toEqual({ type: 'result' });
  });

  it('uses Chrome Native Messaging little-endian framing', async () => {
    const inbound = new PassThrough();
    const outbound = new PassThrough();
    const channel = new ChromeNativeChannel(inbound, outbound);
    const written: Buffer[] = [];
    outbound.on('data', (chunk: Buffer) => written.push(chunk));
    channel.write({ outcome: 'ready' });
    const frame = Buffer.concat(written);
    expect(frame.readUInt32LE(0)).toBe(frame.length - 4);
    expect(JSON.parse(frame.subarray(4).toString('utf8'))).toEqual({ outcome: 'ready' });

    const response = Buffer.from('{"outcome":"injected"}', 'utf8');
    const header = Buffer.alloc(4);
    header.writeUInt32LE(response.length, 0);
    const received = channel.read();
    inbound.write(header.subarray(0, 2));
    inbound.write(Buffer.concat([header.subarray(2), response]));
    await expect(received).resolves.toEqual({ outcome: 'injected' });
  });

  it('rejects invalid and oversized frames', async () => {
    const lineIn = new PassThrough();
    const line = new JsonLineChannel(lineIn, new PassThrough());
    const invalid = line.read();
    lineIn.write('not-json\n');
    await expect(invalid).rejects.toThrow('JSON is invalid');

    const nativeIn = new PassThrough();
    const native = new ChromeNativeChannel(nativeIn, new PassThrough());
    const oversized = native.read();
    const header = Buffer.alloc(4);
    header.writeUInt32LE(1024 * 1024 + 1, 0);
    nativeIn.write(header);
    await expect(oversized).rejects.toThrow('length is invalid');
  });
});
