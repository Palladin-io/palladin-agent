import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const roots = process.argv.slice(2);
if (roots.length === 0 || roots.some((root) => !root.startsWith('/'))) process.exit(64);

const chunks = [];
let canarySize = 0;
for await (const chunk of process.stdin) {
  canarySize += chunk.length;
  if (canarySize > 128) process.exit(64);
  chunks.push(Buffer.from(chunk));
}
const canary = Buffer.concat(chunks);
for (const chunk of chunks) chunk.fill(0);
if (canary.length < 32) process.exit(64);

let totalBytes = 0;
const pending = roots.map((root) => resolve(root));
while (pending.length > 0) {
  const current = pending.pop();
  if (current === undefined) throw new Error('canary scan state is invalid');
  const metadata = lstatSync(current);
  if (metadata.isSymbolicLink()) throw new Error('canary scan rejected a symbolic link');
  if (metadata.isDirectory()) {
    for (const entry of readdirSync(current)) pending.push(join(current, entry));
    continue;
  }
  if (!metadata.isFile()) throw new Error('canary scan rejected an unsupported file type');
  totalBytes += metadata.size;
  if (totalBytes > 8 * 1024 * 1024) throw new Error('canary scan exceeded its byte bound');
  if (readFileSync(current).includes(canary)) throw new Error('bounded output or public state contained the stdin canary');
}

canary.fill(0);
process.stdout.write('bounded-output-and-public-state=stdin-canary-absent\n');
