#!/usr/bin/env node
import { launchNativeRuntime } from '../runtime/native-dispatch.js';
import { isExtensionInject, runExtensionInject } from '../browser-host/client.js';
import { installBrowserHost, isBrowserInstall } from '../browser-host/install.js';

const args = process.argv.slice(2);
const exitCode = isBrowserInstall(args)
  ? installBrowserHost(args)
  : isExtensionInject(args)
    ? await runExtensionInject(args)
    : await launchNativeRuntime(args);
process.exitCode = exitCode;
