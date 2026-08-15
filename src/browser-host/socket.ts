import { chmodSync, lstatSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

import { palladinRoot } from '../config/paths.js';

export const browserHostSocketPath = join(palladinRoot, 'browser-bridge.sock');

export function prepareBrowserHostSocket(): void {
  mkdirSync(palladinRoot, { recursive: true, mode: 0o700 });
  const root = lstatSync(palladinRoot);
  if (!root.isDirectory() || root.isSymbolicLink()
    || (process.getuid !== undefined && root.uid !== process.getuid())) {
    throw new Error('Palladin root is not owner-controlled');
  }
  chmodSync(palladinRoot, 0o700);
  try {
    const existing = lstatSync(browserHostSocketPath);
    if (!existing.isSocket() || existing.isSymbolicLink()
      || (process.getuid !== undefined && existing.uid !== process.getuid())) {
      throw new Error('browser host socket path is unsafe');
    }
    unlinkSync(browserHostSocketPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}
