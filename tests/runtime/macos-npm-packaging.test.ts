import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('macOS npm platform packages', () => {
  it.runIf(process.platform === 'darwin').each(['arm64', 'x64'])(
    'stages only the darwin/%s package around the signed universal app',
    (architecture) => {
      const temporary = mkdtempSync(join(tmpdir(), 'palladin-darwin-stage-'));
      try {
        const app = join(temporary, 'PalladinRuntime.app');
        const executableDirectory = join(app, 'Contents', 'MacOS');
        mkdirSync(executableDirectory, { recursive: true });
        writeFileSync(join(executableDirectory, 'palladin'), 'fixture');
        const output = join(temporary, 'output');
        execFileSync('bash', [
          'packaging/macos/scripts/stage-npm-platform-package.sh',
          '--architecture', architecture,
          '--app', app,
          '--output-dir', output,
        ]);
        const manifest = JSON.parse(readFileSync(join(output, 'package.json'), 'utf8')) as {
          name: string;
          version: string;
          private?: boolean;
          os: string[];
          cpu: string[];
          libc?: string[];
          files: string[];
          scripts?: unknown;
          dependencies?: unknown;
          optionalDependencies?: unknown;
        };
        expect(manifest).toMatchObject({
          name: `@palladin/runtime-darwin-${architecture}`,
          version: '0.1.0',
          os: ['darwin'],
          cpu: [architecture],
          files: ['PalladinRuntime.app/', 'README.md', 'LICENSE'],
        });
        expect(manifest.private).toBeUndefined();
        expect(manifest.libc).toBeUndefined();
        expect(manifest.scripts).toBeUndefined();
        expect(manifest.dependencies).toBeUndefined();
        expect(manifest.optionalDependencies).toBeUndefined();
      } finally {
        rmSync(temporary, { recursive: true, force: true });
      }
    },
  );
});
