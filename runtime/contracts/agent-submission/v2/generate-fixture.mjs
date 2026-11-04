import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

// Default dependencies come from the Agent's npm install. An optional package.json
// path permits generation using the protocol repository's identical sodium package.
const dependencyManifest = process.argv.find((arg) => arg.startsWith('--dependencies='))?.slice('--dependencies='.length)
const require = createRequire(dependencyManifest ?? new URL('../../../../package.json', import.meta.url))
const sodium = require('libsodium-wrappers')
await sodium.ready
const fixture = JSON.parse(fs.readFileSync(new URL('../v1/fixture.json', import.meta.url), 'utf8'))
const canonical = (value) => JSON.stringify(sort(value))
function sort(value) {
  if (Array.isArray(value)) return value.map(sort)
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sort(value[key])]))
  return value
}
const payload = {
  schema: 'palladin.agent-submission-payload.v2',
  identity: fixture.expectedPlaintext.identity,
  description: 'Synthetic captured account description',
  content: {
    username: 'synthetic-captured-user@example.invalid',
    customFields: [
      { id: 'custom:11112222-4333-8444-9555-666677778888', type: 'concealed', value: 'synthetic-Captured-Only-9!q' },
      { id: 'custom:22223333-4444-4555-8666-777788889999', label: 'Synthetic OTP', type: 'totp', value: { secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, issuer: 'Synthetic', account: null } },
    ],
  },
}
const nonce = Buffer.from(fixture.deterministicInputs.payloadNonce, 'hex')
const dek = Buffer.from(fixture.deterministicInputs.submissionDek, 'hex')
const aad = Buffer.from(`PLDNSUB1AAD${canonical(payload.identity)}`)
const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(Buffer.from(canonical(payload)), aad, null, nonce, dek)
const encodedPayload = Buffer.concat([nonce, ciphertext]).toString('base64url')
const signing = sodium.crypto_sign_seed_keypair(Buffer.from(fixture.deterministicInputs.agentEd25519Seed, 'hex'))
for (const submission of fixture.submissions) {
  submission.encodedPayload = encodedPayload
  delete submission.agentSignature
  const signatureInput = Buffer.concat([Buffer.from('PLDNSUB1SIG:AGENT-SUBMISSION:'), Buffer.from([0, 2]), Buffer.from(canonical(submission))])
  submission.agentSignature = Buffer.from(sodium.crypto_sign_detached(signatureInput, signing.privateKey)).toString('base64url')
}
fixture.expectedPlaintext = payload
fixture.payloadVersion = 2
fixture.warning = 'Deterministic synthetic conformance data. Every key, nonce and secret is invalid outside tests. V1 identity and wraps reused solely for cross-language payload-v2 conformance.'
const fixturePath = fileURLToPath(new URL('fixture.json', import.meta.url))
if (process.argv.includes('--write')) fs.writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`)
else assert.deepEqual(JSON.parse(fs.readFileSync(fixturePath, 'utf8')), fixture)
const opened = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, dek)
assert.deepEqual(JSON.parse(Buffer.from(opened).toString()), payload)
console.log('Payload v2 synthetic fixture verified.')
