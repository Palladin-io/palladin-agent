import { chmodSync, lstatSync, mkdirSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HOST_NAME = 'io.palladin.browser_bridge';
const EXTENSION_ID = /^[a-p]{32}$/;
const SUPPORTED_BROWSERS = new Set(['chrome', 'chrome-for-testing', 'chromium']);

export function isBrowserInstall(args: readonly string[]): boolean {
  return args[0] === 'browser' && args[1] === 'install';
}

export function installBrowserHost(args: readonly string[]): number {
  const index = args.indexOf('--extension-id');
  const extensionId = index === -1 ? undefined : args[index + 1];
  if (extensionId === undefined || !EXTENSION_ID.test(extensionId)) {
    process.stderr.write('Error: browser install requires --extension-id with the Palladin extension ID\n');
    return 1;
  }
  const browserIndex = args.indexOf('--browser');
  const browser = browserIndex === -1 ? 'chrome' : args[browserIndex + 1];
  if (browser === undefined || !SUPPORTED_BROWSERS.has(browser)) {
    process.stderr.write(
      'Error: browser install --browser must be chrome, chrome-for-testing, or chromium\n',
    );
    return 1;
  }
  const profileIndex = args.indexOf('--user-data-dir');
  const requestedProfile = profileIndex === -1 ? undefined : args[profileIndex + 1];
  if (requestedProfile !== undefined && !isAbsolute(requestedProfile)) {
    process.stderr.write('Error: browser install --user-data-dir must be an absolute path\n');
    return 1;
  }
  if (requestedProfile !== undefined && process.platform === 'win32') {
    process.stderr.write('Error: Windows native host installation requires the brokered installer\n');
    return 1;
  }
  let directory: string;
  if (requestedProfile !== undefined) {
    let profile: string;
    try {
      profile = realpathSync(requestedProfile);
      const info = lstatSync(profile);
      if (!info.isDirectory() || info.isSymbolicLink()
        || (process.getuid !== undefined && info.uid !== process.getuid())) {
        throw new Error('unsafe profile');
      }
    } catch {
      process.stderr.write('Error: browser install --user-data-dir is not owner-controlled\n');
      return 1;
    }
    directory = join(profile, 'NativeMessagingHosts');
  } else if (process.platform === 'darwin') {
    directory = join(
      homedir(),
      'Library',
      'Application Support',
      ...(browser === 'chrome'
        ? ['Google', 'Chrome']
        : browser === 'chrome-for-testing'
          ? ['Google', 'ChromeForTesting']
          : ['Chromium']),
      'NativeMessagingHosts',
    );
  } else if (process.platform === 'linux') {
    directory = join(
      homedir(),
      '.config',
      browser === 'chrome'
        ? 'google-chrome'
        : browser === 'chrome-for-testing'
          ? 'google-chrome-for-testing'
          : 'chromium',
      'NativeMessagingHosts',
    );
  } else {
    process.stderr.write('Error: Windows native host installation requires the brokered installer\n');
    return 1;
  }
  const host = fileURLToPath(new URL('./native-host.js', import.meta.url));
  chmodSync(host, 0o755);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const directoryInfo = lstatSync(directory);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()
    || (process.getuid !== undefined && directoryInfo.uid !== process.getuid())) {
    process.stderr.write('Error: browser native host directory is not owner-controlled\n');
    return 1;
  }
  chmodSync(directory, 0o700);
  const destination = join(directory, `${HOST_NAME}.json`);
  const temporary = `${destination}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify({
    name: HOST_NAME,
    description: 'Palladin Agent Inject bridge for the existing Palladin extension',
    path: host,
    type: 'stdio',
    allowed_origins: [`chrome-extension://${extensionId}/`],
  }, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, destination);
  chmodSync(destination, 0o600);
  process.stderr.write(`Palladin browser host installed for ${browser} and ${extensionId.slice(0, 8)}…${extensionId.slice(-6)}.\n`);
  return 0;
}

export function browserHostManifestDirectory(): string {
  return dirname(fileURLToPath(import.meta.url));
}
