#!/usr/bin/env node
import { launchNativeRuntime } from '../runtime/native-dispatch.js';

const exitCode = await launchNativeRuntime(process.argv.slice(2));
process.exitCode = exitCode;
