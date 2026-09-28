import { createPublicKey, verify as verifySignature } from 'node:crypto';

import {
  VERSION_POLICY_BUNDLE_BASE64,
  VERSION_POLICY_PUBLIC_KEY_BASE64,
} from './version-policy-build.js';

const POLICY_SCHEMA_VERSION = 2;
const MAX_POLICY_BYTES = 64 * 1024;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const EXACT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SOURCE_SHA = /^[0-9a-f]{40}$/;
const THUMBPRINT = /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/;
const PACKAGE_NAME = /^@palladin\/(?:agent|runtime-(?:darwin|linux|win32)-[a-z0-9-]+)$/;

export interface VersionPolicyArtifact {
  packageName: string;
  version: string;
  sourceSha: string;
  executableSha256: string;
  workerExecutableSha256: string;
  authenticodePublisher?: string;
  authenticodeThumbprint?: string;
}

export interface VersionPolicyPayload {
  schemaVersion: 2;
  artifacts: VersionPolicyArtifact[];
}

export interface VersionPolicyEnvelope {
  signed: VersionPolicyPayload;
  signature: string;
}

export interface VerifiedArtifactBinding extends VersionPolicyArtifact {
  envelopeBase64: string;
}

export interface VersionPolicyRequest {
  packageName: string;
  version: string;
  executableSha256: string;
  sourceSha: string;
}

export class VersionPolicyError extends Error {
  public constructor(message = 'Palladin release signature verification failed') {
    super(message);
    this.name = 'VersionPolicyError';
  }
}

/** Every launch verifies the immutable signed manifest shipped with this exact release. */
export function loadBundledVerifiedArtifactBinding(
  request: VersionPolicyRequest,
): VerifiedArtifactBinding {
  const [bytes] = systemBundledPolicy();
  if (bytes === undefined) throw new VersionPolicyError();
  return verifyArtifactIntegrityBinding(bytes, request, {
    publicKeyBase64: VERSION_POLICY_PUBLIC_KEY_BASE64,
  });
}

export function verifyArtifactIntegrityBinding(
  bytes: Uint8Array,
  request: VersionPolicyRequest,
  options: { publicKeyBase64: string },
): VerifiedArtifactBinding {
  const envelope = parseAndVerifyVersionPolicy(bytes, options);
  const artifact = selectArtifact(envelope.signed, request.packageName, request.version);
  if (artifact.executableSha256 !== request.executableSha256
    || artifact.sourceSha !== request.sourceSha) throw new VersionPolicyError();
  return { ...artifact, envelopeBase64: Buffer.from(bytes).toString('base64') };
}

function systemBundledPolicy(): readonly Uint8Array[] {
  if (VERSION_POLICY_BUNDLE_BASE64 === '') return [];
  try {
    const bytes = Buffer.from(VERSION_POLICY_BUNDLE_BASE64, 'base64');
    if (bytes.length === 0 || bytes.length > MAX_POLICY_BYTES
      || bytes.toString('base64') !== VERSION_POLICY_BUNDLE_BASE64) return [];
    return [bytes];
  } catch {
    return [];
  }
}

export function parseAndVerifyVersionPolicy(
  bytes: Uint8Array,
  options: { publicKeyBase64: string },
): VersionPolicyEnvelope {
  if (bytes.length === 0 || bytes.length > MAX_POLICY_BYTES) throw new VersionPolicyError();
  let candidate: unknown;
  try {
    candidate = JSON.parse(Buffer.from(bytes).toString('utf8')) as unknown;
  } catch {
    throw new VersionPolicyError();
  }
  const envelope = parseEnvelope(candidate);
  if (Buffer.from(bytes).toString('utf8') !== canonicalizeVersionPolicyEnvelope(envelope)) {
    throw new VersionPolicyError();
  }
  validatePayloadShape(envelope.signed);
  const publicKey = decodeExactBase64(options.publicKeyBase64, 32);
  if (publicKey.every((byte) => byte === 0)) throw new VersionPolicyError();
  const signature = decodeExactBase64(envelope.signature, 64);
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, publicKey]);
  let verified = false;
  try {
    verified = verifySignature(
      null,
      Buffer.from(canonicalizeVersionPolicyPayload(envelope.signed), 'utf8'),
      createPublicKey({ key: spki, format: 'der', type: 'spki' }),
      signature,
    );
  } catch {
    throw new VersionPolicyError();
  }
  if (!verified) throw new VersionPolicyError();
  return envelope;
}

export function canonicalizeVersionPolicyEnvelope(envelope: VersionPolicyEnvelope): string {
  if (typeof envelope.signature !== 'string') throw new VersionPolicyError();
  decodeExactBase64(envelope.signature, 64);
  return `{"signature":${JSON.stringify(envelope.signature)},"signed":${canonicalizeVersionPolicyPayload(envelope.signed)}}`;
}

export function canonicalizeVersionPolicyPayload(payload: VersionPolicyPayload): string {
  validatePayloadShape(payload);
  const artifacts = payload.artifacts.map((artifact) => {
    const result: Record<string, string> = {};
    if (artifact.authenticodePublisher !== undefined) {
      result.authenticodePublisher = artifact.authenticodePublisher;
      result.authenticodeThumbprint = artifact.authenticodeThumbprint ?? '';
    }
    result.executableSha256 = artifact.executableSha256;
    result.packageName = artifact.packageName;
    result.sourceSha = artifact.sourceSha;
    result.version = artifact.version;
    result.workerExecutableSha256 = artifact.workerExecutableSha256;
    return result;
  });
  return JSON.stringify({
    artifacts,
    schemaVersion: payload.schemaVersion,
  });
}

export function selectArtifact(
  policy: VersionPolicyPayload,
  packageName: string,
  version: string,
): VersionPolicyArtifact {
  const matches = policy.artifacts.filter(
    (artifact) => artifact.packageName === packageName && artifact.version === version,
  );
  if (matches.length !== 1) throw new VersionPolicyError();
  return matches[0] as VersionPolicyArtifact;
}

function parseEnvelope(value: unknown): VersionPolicyEnvelope {
  const object = exactObject(value, ['signature', 'signed']);
  if (typeof object.signature !== 'string') throw new VersionPolicyError();
  const signed = parsePayload(object.signed);
  return { signed, signature: object.signature };
}

function parsePayload(value: unknown): VersionPolicyPayload {
  const object = exactObject(value, ['artifacts', 'schemaVersion']);
  if (!Array.isArray(object.artifacts)) throw new VersionPolicyError();
  const payload = {
    schemaVersion: object.schemaVersion,
    artifacts: object.artifacts.map(parseArtifact),
  };
  validatePayloadShape(payload);
  return payload;
}

function parseArtifact(value: unknown): VersionPolicyArtifact {
  if (!isRecord(value)) throw new VersionPolicyError();
  const windows = Object.hasOwn(value, 'authenticodePublisher')
    || Object.hasOwn(value, 'authenticodeThumbprint');
  const keys = windows
    ? ['authenticodePublisher', 'authenticodeThumbprint', 'executableSha256', 'packageName', 'sourceSha', 'version', 'workerExecutableSha256']
    : ['executableSha256', 'packageName', 'sourceSha', 'version', 'workerExecutableSha256'];
  const object = exactObject(value, keys);
  if (typeof object.packageName !== 'string' || typeof object.version !== 'string'
    || typeof object.sourceSha !== 'string'
    || typeof object.executableSha256 !== 'string'
    || typeof object.workerExecutableSha256 !== 'string') throw new VersionPolicyError();
  if (windows && (typeof object.authenticodePublisher !== 'string'
    || typeof object.authenticodeThumbprint !== 'string')) throw new VersionPolicyError();
  return {
    packageName: object.packageName,
    version: object.version,
    sourceSha: object.sourceSha,
    executableSha256: object.executableSha256,
    workerExecutableSha256: object.workerExecutableSha256,
    ...(windows ? {
      authenticodePublisher: object.authenticodePublisher as string,
      authenticodeThumbprint: object.authenticodeThumbprint as string,
    } : {}),
  };
}

function validatePayloadShape(value: unknown): asserts value is VersionPolicyPayload {
  if (!isRecord(value)
    || Object.keys(value).sort().join('\0') !== ['artifacts', 'schemaVersion'].sort().join('\0')
    || value.schemaVersion !== POLICY_SCHEMA_VERSION
    || !Array.isArray(value.artifacts) || value.artifacts.length === 0) {
    throw new VersionPolicyError();
  }
  const artifacts = value.artifacts as VersionPolicyArtifact[];
  let previous = '';
  for (const artifact of artifacts) {
    if (!isRecord(artifact)) throw new VersionPolicyError();
    const windowsKeys = typeof artifact.packageName === 'string'
      && artifact.packageName.startsWith('@palladin/runtime-win32-');
    const expectedKeys = windowsKeys
      ? ['authenticodePublisher', 'authenticodeThumbprint', 'executableSha256', 'packageName', 'sourceSha', 'version', 'workerExecutableSha256']
      : ['executableSha256', 'packageName', 'sourceSha', 'version', 'workerExecutableSha256'];
    if (typeof artifact.packageName !== 'string'
      || Object.keys(artifact).sort().join('\0') !== expectedKeys.sort().join('\0')
      || typeof artifact.version !== 'string' || typeof artifact.executableSha256 !== 'string'
      || typeof artifact.workerExecutableSha256 !== 'string'
      || typeof artifact.sourceSha !== 'string'
      || !PACKAGE_NAME.test(artifact.packageName) || !isExactVersion(artifact.version)
      || !SOURCE_SHA.test(artifact.sourceSha) || /^0{40}$/.test(artifact.sourceSha)
      || !SHA256.test(artifact.executableSha256)
      || !SHA256.test(artifact.workerExecutableSha256)) throw new VersionPolicyError();
    const windows = artifact.packageName.startsWith('@palladin/runtime-win32-');
    if (windows !== (typeof artifact.authenticodePublisher === 'string'
      && typeof artifact.authenticodeThumbprint === 'string')) throw new VersionPolicyError();
    if (windows) {
      const publisher = artifact.authenticodePublisher ?? '';
      if (publisher.trim() === '' || publisher.length > 256
        || [...publisher].some((character) => character < ' ' || character > '~')
        || !THUMBPRINT.test(artifact.authenticodeThumbprint ?? '')) throw new VersionPolicyError();
    }
    const identity = `${artifact.packageName}@${artifact.version}`;
    if (identity <= previous) throw new VersionPolicyError();
    previous = identity;
  }
}

function isExactVersion(value: string): boolean {
  if (!EXACT_VERSION.test(value)) return false;
  return value.split('.').every((part) => Number.isSafeInteger(Number(part)));
}

function decodeExactBase64(value: string, length: number): Buffer {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new VersionPolicyError();
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== length || decoded.toString('base64') !== value) {
    throw new VersionPolicyError();
  }
  return decoded;
}

function exactObject(value: unknown, expectedKeys: string[]): Record<string, unknown> {
  if (!isRecord(value)) throw new VersionPolicyError();
  const keys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new VersionPolicyError();
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
