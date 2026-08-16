#!/usr/bin/env node
import { launchNativeRuntime } from '../runtime/native-dispatch.js';

const args = process.argv.slice(2);
const exitCode = await launchNativeRuntime(args);
process.exitCode = exitCode;
