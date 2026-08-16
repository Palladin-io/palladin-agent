# Palladin browser-host local IPC v1

`palladin.browser-host-ipc.v1` protects the local CLI-to-native-host hop. The Unix socket is an
owner-only rendezvous point, not the authentication boundary. Both processes load the same durable
browser-host Ed25519 identity from OS secure storage and prove possession before Inject data moves.

All messages use the same bounded four-byte little-endian length-prefixed JSON framing as Chrome
Native Messaging. Binary fields are canonical unpadded base64url.

The client sends `session.open` with `clientNonce`, `clientEphemeralPublicKey`, and
`clientSignature`. The signature covers length-prefixed nonce, X25519 key, and durable host public
key after the domain `palladin.browser-host-ipc.v1\0client-open-v1\0`. The host verifies it against
its own durable identity, proving that an arbitrary same-user process cannot drive the real host.

The host returns `session.ready` with the echoed client nonce, fresh host nonce and X25519 key,
`hostSignature`, and `sessionId`. Its signature covers both nonces, both ephemeral keys, and the
durable public key after `palladin.browser-host-ipc.v1\0session-v1\0`. The CLI verifies this
signature against the identity it loaded directly from OS secure storage, so a fake local socket
cannot receive a credential.

Both peers reject an all-zero X25519 shared value. HKDF-SHA256 derives 112 bytes using the session
transcript hash as salt and `palladin.browser-host-ipc.v1\0session-keys-v1\0` as info:

```text
material[0..32]   = host-to-client key
material[32..64]  = client-to-host key
material[64..88]  = host-to-client nonce base
material[88..112] = client-to-host nonce base
```

`secure` frames use canonical decimal sequence strings, XChaCha20-Poly1305, strict next-sequence
acceptance, and direction-bound AAD. Plaintext is limited to 768 KiB; outer frames are limited to
1 MiB. Authentication, replay, ordering, framing, timeout, or schema failure closes the one-shot
operation without fallback.
