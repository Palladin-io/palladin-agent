# Palladin Inject provider secure session v1

This directory freezes the authenticated session used to carry existing
`palladin.inject-provider.v1` messages between the native host and the exact extension admitted by
the browser's Native Messaging allowlist. It does not change the inner `prepare`, `inject`, or
value-free result schemas.

The production macOS Chrome path uses this session. A plaintext stdio or owner-only socket is not
this security boundary.

## Browser/platform authorization

Chrome Native Messaging's exact `allowed_origins` entry identifies which extension may launch the
host. The compiled origin is
`chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/`. The Runtime accepts only Chrome's exact
browser-authored origin argument and, on macOS, validates the direct Google-signed Chrome parent
before it opens the host identity or local socket. An Extension ID inside a message payload has no
authority.

The extension stores no host key, fingerprint, pairing intent, account, or profile binding. The
native host owns one installation-scoped Ed25519 signing key in OS secure storage for the local
CLI↔host authentication and the encrypted host↔extension session. At the start of each Native
Messaging port it announces only the public key:

```json
{
  "protocol": "palladin.inject-provider.v1",
  "type": "session.offer",
  "hostSigningPublicKey": "..."
}
```

The extension accepts exactly these three fields, keeps the public key only for that port, and uses
it to validate the signed transcript below. This session-local key check binds the encrypted
channel; it is not the authority that lets the Runtime release a credential. That authority is the
browser/platform-authored official extension identity plus the separately authenticated local
CLI↔host hop.

The CLI reaches this host through the separately mutually authenticated local protocol documented
in [`local-ipc.md`](local-ipc.md). Plaintext never crosses that socket.

## Handshake

All binary fields use canonical unpadded base64url. Keys and nonces are 32 bytes; the Ed25519
signature is 64 bytes.

After `session.offer`, extension to host:

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

The extension requires the returned host key to equal the session-offer key, verifies the Ed25519
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
