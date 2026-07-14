import { parseAndVerifyVersionPolicy } from '../../dist/runtime/version-policy.js';

const publicKeyIndex = process.argv.indexOf('--public-key');
if (publicKeyIndex < 0 || publicKeyIndex + 1 >= process.argv.length || process.argv.length !== 4) fail();
const publicKey = process.argv[publicKeyIndex + 1];
const source = 'https://releases.palladin.io/agent/version-policy.json';
const policyResponse = await fetch(source, {
  redirect: 'error',
  cache: 'no-store',
  headers: { accept: 'application/json' },
});
if (!policyResponse.ok || policyResponse.url !== source
  || Number(policyResponse.headers.get('content-length') ?? 0) > 64 * 1024) fail();
const policyBytes = await readBounded(policyResponse, 64 * 1024);
const envelope = parseAndVerifyVersionPolicy(policyBytes, {
  publicKeyBase64: publicKey,
  source,
});
if (Date.parse(envelope.signed.expiresAt) - Date.now() < 9 * 24 * 60 * 60 * 1000) fail();
const packages = ['@palladin/agent', ...[...new Set(envelope.signed.artifacts.map((artifact) => artifact.packageName))].sort()];
for (const name of packages) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
  const response = await fetch(url, { redirect: 'error', headers: { accept: 'application/json' } });
  if (!response.ok || response.url !== url) fail();
  const metadata = JSON.parse((await readBounded(response, 16 * 1024 * 1024)).toString('utf8'));
  if ((name === '@palladin/agent'
      && metadata?.['dist-tags']?.latest !== envelope.signed.recommendedVersion)
    || metadata?.versions?.[envelope.signed.recommendedVersion] === undefined
    || metadata.versions[envelope.signed.recommendedVersion].deprecated !== undefined) fail();
  for (const blocked of envelope.signed.blockedVersions) {
    if (metadata?.versions?.[blocked] !== undefined
      && (typeof metadata.versions[blocked].deprecated !== 'string'
        || metadata.versions[blocked].deprecated.length === 0)) fail();
  }
}
process.stdout.write(`Verified signed policy sequence ${envelope.signed.sequence} and public npm state without credentials.\n`);

function fail() {
  process.stderr.write('public registry state does not match the signed version policy\n');
  process.exit(1);
}

async function readBounded(response, maximum) {
  if (response.body === null) fail();
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    length += chunk.value.byteLength;
    if (length > maximum) { await reader.cancel(); fail(); }
    chunks.push(Buffer.from(chunk.value));
  }
  if (length === 0) fail();
  return Buffer.concat(chunks, length);
}
