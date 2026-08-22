# Palladin Inject provider secure session v1

This directory freezes the authenticated session used to carry existing
`palladin.inject-provider.v1` messages between the native host and the exact extension admitted by
the browser's Native Messaging allowlist. It does not change the inner `prepare`, `inject`, or
value-free result schemas.

The production macOS Chrome path uses this session. A plaintext stdio or owner-only socket is not
this security boundary.

## Pairing

The native host owns one installation-scoped Ed25519 signing key in OS secure storage. Explicit
pairing shows its fingerprint to the user. The extension persists only the full public key and
fingerprint after the user confirms the same value in both surfaces:

```text
fingerprint = base64url-no-pad(SHA-256(raw-host-ed25519-public-key))
```

`palladin browser install` prints the shortened fingerprint in the trusted terminal. When the
pairing screen opens, the extension sends one public, value-free discovery request to the exact
allowlisted native host:

```json
{
  "protocol": "palladin.inject-pairing.v1",
  "type": "pairing.discover",
  "extensionOrigin": "chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/",
  "challenge": "00000000-0000-4000-8000-000000000001"
}
```

The host validates the exact compiled extension origin and canonical UUIDv4 challenge, then echoes
both values with its public identity:

```json
{
  "protocol": "palladin.inject-pairing.v1",
  "type": "pairing.offer",
  "extensionOrigin": "chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/",
  "challenge": "00000000-0000-4000-8000-000000000001",
  "hostSigningPublicKey": "...",
  "fingerprint": "..."
}
```

The extension rejects unknown fields, stale challenges and mismatched fingerprints. The offer is
kept in memory and is not trust on first use: the user must compare the shortened fingerprint with
the independent CLI display and choose **Trust and pair** before the extension persists the full
public key and derived fingerprint. Native Messaging discovery cannot create or replace the pin.

Chrome Native Messaging's exact `allowed_origins` entry authenticates the extension to the host.
The compiled origin is
`chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/`. On macOS the host additionally requires a
Google-signed Chrome parent process before it loads the key. The signed handshake below
authenticates the host to the extension. Neither side treats a socket, process ID, argv value, or
nonce alone as authentication.

The CLI reaches this host through the separately mutually authenticated local protocol documented
in [`local-ipc.md`](local-ipc.md). Plaintext never crosses that socket.

## Handshake

All binary fields use canonical unpadded base64url. Keys and nonces are 32 bytes; the Ed25519
signature is 64 bytes.

Extension to host:

```json
{
  "protocol": "palladin.inject-provider.v1",
  "type": "session.open",
  "extensionNonce": "...",
  "extensionEphemeralPublicKey": "..."
}
```

Host to extension:

```json
{
  "protocol": "palladin.inject-provider.v1",
  "type": "session.ready",
  "extensionNonce": "...",
  "hostNonce": "...",
  "hostEphemeralPublicKey": "...",
  "hostSigningPublicKey": "...",
  "signature": "...",
  "sessionId": "..."
}
```

The signed transcript is the following exact byte string. `item` means
`u32-big-endian(byteLength) || bytes`:

```text
ASCII("palladin.inject-provider.v1\0extension-session-v1\0")
|| item(UTF8(exact browser-supplied extension origin))
|| item(raw extension nonce)
|| item(raw extension ephemeral X25519 public key)
|| item(raw host nonce)
|| item(raw host ephemeral X25519 public key)
|| item(raw host Ed25519 public key)
```

The extension requires the returned host key to equal its paired full key, verifies the Ed25519
signature and echoed extension nonce, and checks:

```text
sessionId = base64url-no-pad(SHA-256(
  ASCII("palladin.inject-provider.v1\0extension-session-id-v1\0")
  || transcript
  || raw signature
))
```

An all-zero X25519 shared value is invalid. Session material is:

```text
shared = X25519(local ephemeral private key, peer ephemeral public key)
salt = SHA-256(transcript)
material = HKDF-SHA256(
  IKM=shared,
  salt=salt,
  info=ASCII("palladin.inject-provider.v1\0extension-session-keys-v1\0"),
  length=112
)

material[0..32]   = host-to-extension key
material[32..64]  = extension-to-host key
material[64..88]  = host-to-extension nonce base
material[88..112] = extension-to-host nonce base
```

## Secure frames

Each direction starts at sequence `0` and accepts only its exact next value. Wire sequences are
canonical decimal u64 strings without leading zeroes. Replay, reordering, overflow, a different
session, malformed base64url, or failed AEAD authentication closes the operation without fallback.

```json
{
  "protocol": "palladin.inject-provider.v1",
  "type": "secure",
  "sessionId": "...",
  "sequence": "0",
  "ciphertext": "..."
}
```

For sequence `n`, copy the direction's 24-byte nonce base and XOR its final eight bytes with
`u64-big-endian(n)`. XChaCha20-Poly1305 AAD is:

```text
ASCII("palladin.inject-provider.v1\0extension-secure-frame-v1\0")
|| UTF8(sessionId)
|| 0x00
|| ASCII("host-to-extension" | "extension-to-host")
|| 0x00
|| u64-big-endian(sequence)
```

`ciphertext` is canonical unpadded base64url of the XChaCha20-Poly1305 ciphertext followed by its
16-byte tag. Plaintext is one serialized existing protocol message and is limited to 768 KiB.
Session material is wiped when the one-shot Native Messaging transaction ends.

[`secure-session.json`](secure-session.json) is the immutable synthetic interoperability vector.
