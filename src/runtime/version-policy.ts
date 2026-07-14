import { createPublicKey, verify as verifySignature } from 'node:crypto';

import {
  VERSION_POLICY_BUNDLE_BASE64,
  VERSION_POLICY_PUBLIC_KEY_BASE64,
  VERSION_POLICY_SOURCE,
} from './version-policy-build.js';

const POLICY_SCHEMA_VERSION = 1;
const MAX_POLICY_BYTES = 64 * 1024;
const MAX_POLICY_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const EXACT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SOURCE_SHA = /^[0-9a-f]{40}$/;
const THUMBPRINT = /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
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
  schemaVersion: 1;
  sequence: number;
  source: string;
  issuedAt: string;
  expiresAt: string;
  minimumVersion: string;
  recommendedVersion: string;
  blockedVersions: string[];
  artifacts: VersionPolicyArtifact[];
}

export interface VersionPolicyEnvelope {
  signed: VersionPolicyPayload;
  signature: string;
}

export interface VerifiedArtifactBinding extends VersionPolicyArtifact {
  policySequence: number;
  policySource: string;
  /** Advisory only. The native secure-state gate is authoritative. */
  runtimeAllowed: boolean;
  envelopeBase64: string;
}

export interface VersionPolicyRequest {
  packageName: string;
  version: string;
  executableSha256: string;
  sourceSha: string;
}

export interface VersionPolicyLoaderOptions {
  fetch?: typeof globalThis.fetch;
  now?: Date;
  publicKeyBase64?: string;
  source?: string;
  timeoutMs?: number;
  /** Public bundled/cache candidates. Native secure state remains authoritative for rollback. */
  offlineEnvelopes?: readonly Uint8Array[];
}

export class VersionPolicyError extends Error {
  public constructor(message = 'Palladin version policy verification failed') {
    super(message);
    this.name = 'VersionPolicyError';
  }
}

export async function loadSystemVerifiedArtifactBinding(
  request: VersionPolicyRequest,
  options: VersionPolicyLoaderOptions = {},
): Promise<VerifiedArtifactBinding> {
  const source = options.source ?? VERSION_POLICY_SOURCE;
  const publicKey = options.publicKeyBase64 ?? VERSION_POLICY_PUBLIC_KEY_BASE64;
  const fetchPolicy = options.fetch ?? globalThis.fetch;
  const candidates = [...(options.offlineEnvelopes ?? systemBundledPolicy())];
  if (fetchPolicy !== undefined) {
    try {
      const timeout = AbortSignal.timeout(options.timeoutMs ?? 5_000);
      const response = await fetchPolicy(source, {
        method: 'GET',
        redirect: 'error',
        cache: 'no-store',
        credentials: 'omit',
        headers: { accept: 'application/json' },
        signal: timeout,
      });
      if (!response.ok || response.url !== source) throw new VersionPolicyError();
      const declaredLength = response.headers.get('content-length');
      if (declaredLength !== null && (!/^\d+$/.test(declaredLength)
        || Number(declaredLength) > MAX_POLICY_BYTES)) throw new VersionPolicyError();
      const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim();
      if (contentType !== 'application/json') throw new VersionPolicyError();
      const bytes = await readBoundedBody(response);
      candidates.push(bytes);
    } catch {
      // A still-valid signed bundled/cache candidate may provide bounded offline use.
    }
  }

  const verified: Array<{ envelope: VersionPolicyEnvelope; bytes: Uint8Array }> = [];
  for (const bytes of candidates) {
    try {
      const envelope = parseAndVerifyVersionPolicy(bytes, {
        publicKeyBase64: publicKey,
        source,
        now: options.now,
      });
      verified.push({ envelope, bytes });
    } catch {
      // Invalid public candidates are ignored; absence of a valid candidate fails closed below.
    }
  }
  verified.sort((left, right) => left.envelope.signed.sequence - right.envelope.signed.sequence);
  const selected = verified.at(-1);
  if (selected === undefined) throw new VersionPolicyError();
  if (verified.some((candidate) => candidate !== selected
    && candidate.envelope.signed.sequence === selected.envelope.signed.sequence
    && !Buffer.from(candidate.bytes).equals(Buffer.from(selected.bytes)))) {
    throw new VersionPolicyError();
  }
  const { envelope, bytes } = selected;
  const artifact = findArtifact(envelope.signed, request.packageName, request.version);
  if (artifact.executableSha256 !== request.executableSha256
    || artifact.sourceSha !== request.sourceSha) throw new VersionPolicyError();
  return {
    ...artifact,
    policySequence: envelope.signed.sequence,
    policySource: envelope.signed.source,
    runtimeAllowed: versionAllowed(envelope.signed, request.version),
    sourceSha: artifact.sourceSha,
    envelopeBase64: Buffer.from(bytes).toString('base64'),
  };
}

/**
 * Offline artifact-integrity gate for help/version/doctor. It intentionally ignores
 * dynamic revocation and freshness, but never skips the embedded signature or exact
 * package/version/source/hash binding. Dynamic native policy remains authoritative
 * before any identity-bearing command.
 */
export function loadBundledVerifiedArtifactBinding(
  request: VersionPolicyRequest,
): VerifiedArtifactBinding {
  const [bytes] = systemBundledPolicy();
  if (bytes === undefined) throw new VersionPolicyError();
  return verifyArtifactIntegrityBinding(bytes, request, {
    publicKeyBase64: VERSION_POLICY_PUBLIC_KEY_BASE64,
    source: VERSION_POLICY_SOURCE,
  });
}

export function verifyArtifactIntegrityBinding(
  bytes: Uint8Array,
  request: VersionPolicyRequest,
  options: { publicKeyBase64: string; source: string },
): VerifiedArtifactBinding {
  const envelope = parseAndVerifyVersionPolicyInternal(bytes, {
    ...options,
    enforceFreshness: false,
  });
  const artifact = findArtifact(envelope.signed, request.packageName, request.version);
  if (artifact.executableSha256 !== request.executableSha256
    || artifact.sourceSha !== request.sourceSha) throw new VersionPolicyError();
  return {
    ...artifact,
    policySequence: envelope.signed.sequence,
    policySource: envelope.signed.source,
    runtimeAllowed: true,
    envelopeBase64: Buffer.from(bytes).toString('base64'),
  };
}

async function readBoundedBody(response: Response): Promise<Buffer> {
  if (response.body === null) throw new VersionPolicyError();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > MAX_POLICY_BYTES) {
        await reader.cancel();
        throw new VersionPolicyError();
      }
      chunks.push(chunk.value);
    }
  } catch {
    await reader.cancel().catch(() => undefined);
    throw new VersionPolicyError();
  }
  if (length === 0) throw new VersionPolicyError();
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), length);
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
  options: {
    publicKeyBase64: string;
    source: string;
    now?: Date;
  },
): VersionPolicyEnvelope {
  return parseAndVerifyVersionPolicyInternal(bytes, { ...options, enforceFreshness: true });
}

/** Administrative verification for monotonic renewal after expiry. Runtime callers must not use it. */
export function parseAndVerifyHistoricalVersionPolicy(
  bytes: Uint8Array,
  options: { publicKeyBase64: string; source: string },
): VersionPolicyEnvelope {
  return parseAndVerifyVersionPolicyInternal(bytes, { ...options, enforceFreshness: false });
}

function parseAndVerifyVersionPolicyInternal(
  bytes: Uint8Array,
  options: {
    publicKeyBase64: string;
    source: string;
    now?: Date;
    enforceFreshness: boolean;
  },
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
  validatePayload(
    envelope.signed,
    options.source,
    options.now ?? new Date(),
    options.enforceFreshness,
  );
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
    blockedVersions: payload.blockedVersions,
    expiresAt: payload.expiresAt,
    issuedAt: payload.issuedAt,
    minimumVersion: payload.minimumVersion,
    recommendedVersion: payload.recommendedVersion,
    schemaVersion: payload.schemaVersion,
    sequence: payload.sequence,
    source: payload.source,
  });
}

export function selectArtifact(
  policy: VersionPolicyPayload,
  packageName: string,
  version: string,
): VersionPolicyArtifact {
  if (!versionAllowed(policy, version)) {
    throw new VersionPolicyError('This Palladin runtime version is blocked by signed policy');
  }
  return findArtifact(policy, packageName, version);
}

function findArtifact(
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

function versionAllowed(policy: VersionPolicyPayload, version: string): boolean {
  return isExactVersion(version) && compareVersions(version, policy.minimumVersion) >= 0
    && !policy.blockedVersions.includes(version);
}

function parseEnvelope(value: unknown): VersionPolicyEnvelope {
  const object = exactObject(value, ['signature', 'signed']);
  if (typeof object.signature !== 'string') throw new VersionPolicyError();
  const signed = parsePayload(object.signed);
  return { signed, signature: object.signature };
}

function parsePayload(value: unknown): VersionPolicyPayload {
  const object = exactObject(value, [
    'artifacts', 'blockedVersions', 'expiresAt', 'issuedAt', 'minimumVersion',
    'recommendedVersion', 'schemaVersion', 'sequence', 'source',
  ]);
  if (!Array.isArray(object.artifacts) || !Array.isArray(object.blockedVersions)) {
    throw new VersionPolicyError();
  }
  const payload = {
    schemaVersion: object.schemaVersion,
    sequence: object.sequence,
    source: object.source,
    issuedAt: object.issuedAt,
    expiresAt: object.expiresAt,
    minimumVersion: object.minimumVersion,
    recommendedVersion: object.recommendedVersion,
    blockedVersions: [...object.blockedVersions],
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

function validatePayload(
  payload: VersionPolicyPayload,
  expectedSource: string,
  now: Date,
  enforceFreshness: boolean,
): void {
  validatePayloadShape(payload);
  if (payload.source !== expectedSource) throw new VersionPolicyError();
  const issued = parseTimestamp(payload.issuedAt);
  const expires = parseTimestamp(payload.expiresAt);
  const nowMs = now.getTime();
  if (expires <= issued || expires - issued > MAX_POLICY_LIFETIME_MS
    || (enforceFreshness && (!Number.isFinite(nowMs) || issued > nowMs + CLOCK_SKEW_MS
      || expires <= nowMs))) {
    throw new VersionPolicyError();
  }
}

function validatePayloadShape(value: unknown): asserts value is VersionPolicyPayload {
  if (!isRecord(value)
    || Object.keys(value).sort().join('\0') !== [
      'artifacts', 'blockedVersions', 'expiresAt', 'issuedAt', 'minimumVersion',
      'recommendedVersion', 'schemaVersion', 'sequence', 'source',
    ].sort().join('\0')
    || value.schemaVersion !== POLICY_SCHEMA_VERSION
    || !Number.isSafeInteger(value.sequence) || (value.sequence as number) < 1
    || typeof value.source !== 'string'
    || typeof value.issuedAt !== 'string' || typeof value.expiresAt !== 'string'
    || typeof value.minimumVersion !== 'string' || !Array.isArray(value.blockedVersions)
    || typeof value.recommendedVersion !== 'string'
    || !Array.isArray(value.artifacts)
    || !isExactVersion(value.minimumVersion)
    || !isExactVersion(value.recommendedVersion) || value.artifacts.length === 0) {
    throw new VersionPolicyError();
  }
  const blocked = value.blockedVersions;
  if (blocked.some((version) => typeof version !== 'string' || !isExactVersion(version))
    || !strictlySorted(blocked as string[])) throw new VersionPolicyError();
  const artifacts = value.artifacts as VersionPolicyArtifact[];
  if (compareVersions(value.recommendedVersion, value.minimumVersion) < 0
    || (value.blockedVersions as string[]).includes(value.recommendedVersion)) {
    throw new VersionPolicyError();
  }
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

function parseTimestamp(value: string): number {
  if (!UTC_TIMESTAMP.test(value)) throw new VersionPolicyError();
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value.replace('Z', '.000Z')) {
    throw new VersionPolicyError();
  }
  return parsed;
}

function compareVersions(left: string, right: string): number {
  const leftParts = left.split('.').map(Number);
  const rightParts = right.split('.').map(Number);
  for (let index = 0; index < 3; index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
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

function strictlySorted(values: string[]): boolean {
  return values.every((value, index) => index === 0 || (values[index - 1] ?? '') < value);
}
