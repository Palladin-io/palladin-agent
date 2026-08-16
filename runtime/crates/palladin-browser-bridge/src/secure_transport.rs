//! Authenticated, encrypted transport for the installed browser-extension provider.
//!
//! Chrome Native Messaging authenticates the exact allowlisted extension to the host. The
//! extension authenticates the host by pinning the public key shown during explicit pairing and
//! verifying this module's signed ephemeral handshake. Existing Inject protocol messages are then
//! carried inside directional, replay-protected XChaCha20-Poly1305 frames.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const INJECT_PROVIDER_PROTOCOL: &str = "palladin.inject-provider.v1";

const HANDSHAKE_DOMAIN: &[u8] = b"palladin.inject-provider.v1\0extension-session-v1\0";
const SESSION_ID_DOMAIN: &[u8] = b"palladin.inject-provider.v1\0extension-session-id-v1\0";
const KEY_DERIVATION_INFO: &[u8] = b"palladin.inject-provider.v1\0extension-session-keys-v1\0";
const FRAME_AAD_DOMAIN: &[u8] = b"palladin.inject-provider.v1\0extension-secure-frame-v1\0";
const NONCE_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const SESSION_MATERIAL_BYTES: usize = 112;
const MAX_EXTENSION_ORIGIN_BYTES: usize = 128;
const MAX_SECURE_PLAINTEXT_BYTES: usize = 768 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionSessionOpen {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub extension_nonce: String,
    pub extension_ephemeral_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostSessionReady {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub extension_nonce: String,
    pub host_nonce: String,
    pub host_ephemeral_public_key: String,
    pub host_signing_public_key: String,
    pub signature: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecureFrame {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub session_id: String,
    /// Canonical base-10 u64. A string avoids JavaScript's 53-bit integer boundary.
    pub sequence: String,
    pub ciphertext: String,
}

/// Durable signing identity owned by the native host and stored only in OS secure storage.
pub struct BrowserHostIdentity {
    signing: SigningKey,
}

impl BrowserHostIdentity {
    pub fn generate() -> Result<Self, SecureTransportError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| SecureTransportError::Randomness)?;
        let identity = Self::from_secret_bytes(bytes);
        bytes.zeroize();
        Ok(identity)
    }

    #[must_use]
    pub fn from_secret_bytes(mut bytes: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        Self { signing }
    }

    pub fn from_secret_slice(bytes: &[u8]) -> Result<Self, SecureTransportError> {
        let mut secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SecureTransportError::InvalidHostIdentity)?;
        let identity = Self::from_secret_bytes(secret);
        secret.zeroize();
        Ok(identity)
    }

    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    #[must_use]
    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.signing.verifying_key().as_bytes()))
    }

    pub(crate) fn sign_message(&self, message: &[u8]) -> [u8; SIGNATURE_BYTES] {
        self.signing.sign(message).to_bytes()
    }

    pub(crate) fn verifying_key_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.signing.verifying_key().to_bytes()
    }

    /// Accept one extension-created ephemeral challenge and create a fresh encrypted session.
    pub fn accept(
        &self,
        extension_origin: &str,
        open: &ExtensionSessionOpen,
    ) -> Result<(HostSessionReady, HostSecureSession), SecureTransportError> {
        let mut host_nonce = [0_u8; NONCE_BYTES];
        let mut host_ephemeral_secret = [0_u8; 32];
        getrandom::fill(&mut host_nonce).map_err(|_| SecureTransportError::Randomness)?;
        getrandom::fill(&mut host_ephemeral_secret)
            .map_err(|_| SecureTransportError::Randomness)?;
        let result =
            self.accept_with_material(extension_origin, open, host_nonce, host_ephemeral_secret);
        host_ephemeral_secret.zeroize();
        result
    }

    fn accept_with_material(
        &self,
        extension_origin: &str,
        open: &ExtensionSessionOpen,
        host_nonce: [u8; NONCE_BYTES],
        host_ephemeral_secret: [u8; 32],
    ) -> Result<(HostSessionReady, HostSecureSession), SecureTransportError> {
        validate_extension_origin(extension_origin)?;
        if open.protocol != INJECT_PROVIDER_PROTOCOL || open.message_type != "session.open" {
            return Err(SecureTransportError::InvalidHandshake);
        }
        let extension_nonce = decode_exact::<NONCE_BYTES>(&open.extension_nonce)?;
        let extension_ephemeral_public_key =
            decode_exact::<PUBLIC_KEY_BYTES>(&open.extension_ephemeral_public_key)?;
        let host_ephemeral_secret = StaticSecret::from(host_ephemeral_secret);
        let host_ephemeral_public_key = PublicKey::from(&host_ephemeral_secret).to_bytes();
        let host_signing_public_key = self.signing.verifying_key().to_bytes();
        let transcript = handshake_transcript(
            extension_origin,
            &extension_nonce,
            &extension_ephemeral_public_key,
            &host_nonce,
            &host_ephemeral_public_key,
            &host_signing_public_key,
        )?;
        let signature = self.signing.sign(&transcript).to_bytes();
        let session_id = session_id(&transcript, &signature);
        let shared = Zeroizing::new(
            host_ephemeral_secret
                .diffie_hellman(&PublicKey::from(extension_ephemeral_public_key))
                .to_bytes(),
        );
        if shared.iter().all(|byte| *byte == 0) {
            return Err(SecureTransportError::InvalidHandshake);
        }
        let keys = derive_session_material(&shared, &transcript)?;
        let session = HostSecureSession::from_material(session_id.clone(), keys);
        let ready = HostSessionReady {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "session.ready".to_owned(),
            extension_nonce: open.extension_nonce.clone(),
            host_nonce: URL_SAFE_NO_PAD.encode(host_nonce),
            host_ephemeral_public_key: URL_SAFE_NO_PAD.encode(host_ephemeral_public_key),
            host_signing_public_key: URL_SAFE_NO_PAD.encode(host_signing_public_key),
            signature: URL_SAFE_NO_PAD.encode(signature),
            session_id,
        };
        Ok((ready, session))
    }
}

impl std::fmt::Debug for BrowserHostIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserHostIdentity")
            .field("public_key", &"[PUBLIC KEY]")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// One duplex session. The host sends on the host-to-extension key and receives on the independent
/// extension-to-host key. Exact monotonically increasing counters reject replay and reordering.
pub struct HostSecureSession {
    session_id: String,
    send_key: Zeroizing<[u8; 32]>,
    receive_key: Zeroizing<[u8; 32]>,
    send_nonce_base: [u8; 24],
    receive_nonce_base: [u8; 24],
    send_sequence: u64,
    receive_sequence: u64,
}

impl HostSecureSession {
    fn from_material(
        session_id: String,
        material: Zeroizing<[u8; SESSION_MATERIAL_BYTES]>,
    ) -> Self {
        let mut send_key = [0_u8; 32];
        send_key.copy_from_slice(&material[..32]);
        let mut receive_key = [0_u8; 32];
        receive_key.copy_from_slice(&material[32..64]);
        let mut send_nonce_base = [0_u8; 24];
        send_nonce_base.copy_from_slice(&material[64..88]);
        let mut receive_nonce_base = [0_u8; 24];
        receive_nonce_base.copy_from_slice(&material[88..112]);
        Self {
            session_id,
            send_key: Zeroizing::new(send_key),
            receive_key: Zeroizing::new(receive_key),
            send_nonce_base,
            receive_nonce_base,
            send_sequence: 0,
            receive_sequence: 0,
        }
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn seal<T: Serialize>(&mut self, message: &T) -> Result<SecureFrame, SecureTransportError> {
        let mut plaintext = Zeroizing::new(
            serde_json::to_vec(message).map_err(|_| SecureTransportError::InvalidMessage)?,
        );
        if plaintext.is_empty() || plaintext.len() > MAX_SECURE_PLAINTEXT_BYTES {
            return Err(SecureTransportError::InvalidMessage);
        }
        let sequence = self.send_sequence;
        let nonce = frame_nonce(self.send_nonce_base, sequence);
        let aad = frame_aad(&self.session_id, FrameDirection::HostToExtension, sequence);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.send_key.as_ref()));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| SecureTransportError::Encryption)?;
        plaintext.zeroize();
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(SecureTransportError::SequenceExhausted)?;
        Ok(SecureFrame {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "secure".to_owned(),
            session_id: self.session_id.clone(),
            sequence: sequence.to_string(),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    pub fn open<T: DeserializeOwned>(
        &mut self,
        frame: &SecureFrame,
    ) -> Result<T, SecureTransportError> {
        if frame.protocol != INJECT_PROVIDER_PROTOCOL
            || frame.message_type != "secure"
            || frame.session_id != self.session_id
            || parse_sequence(&frame.sequence)? != self.receive_sequence
        {
            return Err(SecureTransportError::InvalidFrame);
        }
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&frame.ciphertext)
            .map_err(|_| SecureTransportError::InvalidFrame)?;
        if ciphertext.len() <= 16 || ciphertext.len() > MAX_SECURE_PLAINTEXT_BYTES + 16 {
            return Err(SecureTransportError::InvalidFrame);
        }
        let sequence = self.receive_sequence;
        let nonce = frame_nonce(self.receive_nonce_base, sequence);
        let aad = frame_aad(&self.session_id, FrameDirection::ExtensionToHost, sequence);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.receive_key.as_ref()));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SecureTransportError::Authentication)?;
        let plaintext = Zeroizing::new(plaintext);
        let value = serde_json::from_slice(plaintext.as_ref())
            .map_err(|_| SecureTransportError::InvalidMessage)?;
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or(SecureTransportError::SequenceExhausted)?;
        Ok(value)
    }
}

impl std::fmt::Debug for HostSecureSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostSecureSession")
            .field("session_id", &"[SESSION ID]")
            .field("keys", &"[REDACTED]")
            .field("send_sequence", &self.send_sequence)
            .field("receive_sequence", &self.receive_sequence)
            .finish()
    }
}

impl Drop for HostSecureSession {
    fn drop(&mut self) {
        self.send_nonce_base.zeroize();
        self.receive_nonce_base.zeroize();
        self.send_sequence.zeroize();
        self.receive_sequence.zeroize();
    }
}

#[derive(Clone, Copy)]
enum FrameDirection {
    HostToExtension,
    ExtensionToHost,
}

impl FrameDirection {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::HostToExtension => b"host-to-extension",
            Self::ExtensionToHost => b"extension-to-host",
        }
    }
}

fn validate_extension_origin(origin: &str) -> Result<(), SecureTransportError> {
    let Some(id) = origin
        .strip_prefix("chrome-extension://")
        .and_then(|value| value.strip_suffix('/'))
    else {
        return Err(SecureTransportError::InvalidExtensionOrigin);
    };
    if origin.len() > MAX_EXTENSION_ORIGIN_BYTES
        || id.len() != 32
        || !id.bytes().all(|byte| matches!(byte, b'a'..=b'p'))
    {
        return Err(SecureTransportError::InvalidExtensionOrigin);
    }
    Ok(())
}

fn handshake_transcript(
    origin: &str,
    extension_nonce: &[u8; 32],
    extension_ephemeral_public_key: &[u8; 32],
    host_nonce: &[u8; 32],
    host_ephemeral_public_key: &[u8; 32],
    host_signing_public_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, SecureTransportError> {
    validate_extension_origin(origin)?;
    let mut transcript = Zeroizing::new(Vec::with_capacity(320));
    transcript.extend_from_slice(HANDSHAKE_DOMAIN);
    append_bytes(&mut transcript, origin.as_bytes())?;
    append_bytes(&mut transcript, extension_nonce)?;
    append_bytes(&mut transcript, extension_ephemeral_public_key)?;
    append_bytes(&mut transcript, host_nonce)?;
    append_bytes(&mut transcript, host_ephemeral_public_key)?;
    append_bytes(&mut transcript, host_signing_public_key)?;
    Ok(transcript)
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<(), SecureTransportError> {
    let length = u32::try_from(value.len()).map_err(|_| SecureTransportError::InvalidHandshake)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn session_id(transcript: &[u8], signature: &[u8; SIGNATURE_BYTES]) -> String {
    let mut digest = Sha256::new();
    digest.update(SESSION_ID_DOMAIN);
    digest.update(transcript);
    digest.update(signature);
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn derive_session_material(
    shared: &[u8; 32],
    transcript: &[u8],
) -> Result<Zeroizing<[u8; SESSION_MATERIAL_BYTES]>, SecureTransportError> {
    let salt = Sha256::digest(transcript);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut material = Zeroizing::new([0_u8; SESSION_MATERIAL_BYTES]);
    hkdf.expand(KEY_DERIVATION_INFO, material.as_mut())
        .map_err(|_| SecureTransportError::KeyDerivation)?;
    Ok(material)
}

fn frame_nonce(mut base: [u8; 24], sequence: u64) -> [u8; 24] {
    for (target, sequence_byte) in base[16..].iter_mut().zip(sequence.to_be_bytes()) {
        *target ^= sequence_byte;
    }
    base
}

fn frame_aad(session_id: &str, direction: FrameDirection, sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(160);
    aad.extend_from_slice(FRAME_AAD_DOMAIN);
    aad.extend_from_slice(session_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(direction.label());
    aad.push(0);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], SecureTransportError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SecureTransportError::InvalidHandshake)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(SecureTransportError::InvalidHandshake);
    }
    decoded
        .try_into()
        .map_err(|_| SecureTransportError::InvalidHandshake)
}

fn parse_sequence(value: &str) -> Result<u64, SecureTransportError> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SecureTransportError::InvalidFrame);
    }
    value
        .parse()
        .map_err(|_| SecureTransportError::InvalidFrame)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SecureTransportError {
    #[error("browser host secure randomness is unavailable")]
    Randomness,
    #[error("browser host identity is invalid")]
    InvalidHostIdentity,
    #[error("browser extension origin is invalid")]
    InvalidExtensionOrigin,
    #[error("browser extension session handshake is invalid")]
    InvalidHandshake,
    #[error("browser extension session signature is invalid")]
    InvalidSignature,
    #[error("browser extension session key derivation failed")]
    KeyDerivation,
    #[error("browser extension secure frame is invalid")]
    InvalidFrame,
    #[error("browser extension secure frame encryption failed")]
    Encryption,
    #[error("browser extension secure frame authentication failed")]
    Authentication,
    #[error("browser extension secure message is invalid")]
    InvalidMessage,
    #[error("browser extension secure session sequence was exhausted")]
    SequenceExhausted,
}

/// Verify a host response against the public key pinned during explicit pairing. This helper is
/// also the canonical cross-language verification definition used to produce extension fixtures.
pub fn verify_host_ready(
    extension_origin: &str,
    open: &ExtensionSessionOpen,
    ready: &HostSessionReady,
    pinned_host_signing_public_key: &str,
) -> Result<(), SecureTransportError> {
    validate_extension_origin(extension_origin)?;
    if open.protocol != INJECT_PROVIDER_PROTOCOL
        || open.message_type != "session.open"
        || ready.protocol != INJECT_PROVIDER_PROTOCOL
        || ready.message_type != "session.ready"
        || ready.extension_nonce != open.extension_nonce
        || ready.host_signing_public_key != pinned_host_signing_public_key
    {
        return Err(SecureTransportError::InvalidHandshake);
    }
    let extension_nonce = decode_exact::<NONCE_BYTES>(&open.extension_nonce)?;
    let extension_ephemeral_public_key =
        decode_exact::<PUBLIC_KEY_BYTES>(&open.extension_ephemeral_public_key)?;
    let host_nonce = decode_exact::<NONCE_BYTES>(&ready.host_nonce)?;
    let host_ephemeral_public_key =
        decode_exact::<PUBLIC_KEY_BYTES>(&ready.host_ephemeral_public_key)?;
    let host_signing_public_key = decode_exact::<PUBLIC_KEY_BYTES>(&ready.host_signing_public_key)?;
    let signature = decode_exact::<SIGNATURE_BYTES>(&ready.signature)?;
    let transcript = handshake_transcript(
        extension_origin,
        &extension_nonce,
        &extension_ephemeral_public_key,
        &host_nonce,
        &host_ephemeral_public_key,
        &host_signing_public_key,
    )?;
    let verifying = VerifyingKey::from_bytes(&host_signing_public_key)
        .map_err(|_| SecureTransportError::InvalidSignature)?;
    verifying
        .verify(&transcript, &Signature::from_bytes(&signature))
        .map_err(|_| SecureTransportError::InvalidSignature)?;
    if ready.session_id != session_id(&transcript, &signature) {
        return Err(SecureTransportError::InvalidHandshake);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";

    fn extension_open(secret: [u8; 32], nonce: [u8; 32]) -> ExtensionSessionOpen {
        let secret = StaticSecret::from(secret);
        ExtensionSessionOpen {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "session.open".to_owned(),
            extension_nonce: URL_SAFE_NO_PAD.encode(nonce),
            extension_ephemeral_public_key: URL_SAFE_NO_PAD
                .encode(PublicKey::from(&secret).to_bytes()),
        }
    }

    fn extension_frame(
        host: &HostSecureSession,
        extension_secret: [u8; 32],
        open: &ExtensionSessionOpen,
        ready: &HostSessionReady,
        sequence: u64,
        message: &Value,
    ) -> SecureFrame {
        let extension_secret = StaticSecret::from(extension_secret);
        let host_public = PublicKey::from(
            decode_exact::<32>(&ready.host_ephemeral_public_key).expect("host public key"),
        );
        let shared = extension_secret.diffie_hellman(&host_public).to_bytes();
        let transcript = handshake_transcript(
            ORIGIN,
            &decode_exact(&open.extension_nonce).expect("extension nonce"),
            &decode_exact(&open.extension_ephemeral_public_key).expect("extension key"),
            &decode_exact(&ready.host_nonce).expect("host nonce"),
            &decode_exact(&ready.host_ephemeral_public_key).expect("host key"),
            &decode_exact(&ready.host_signing_public_key).expect("signing key"),
        )
        .expect("transcript");
        let material = derive_session_material(&shared, &transcript).expect("material");
        let mut key = [0_u8; 32];
        key.copy_from_slice(&material[32..64]);
        let mut nonce_base = [0_u8; 24];
        nonce_base.copy_from_slice(&material[88..112]);
        let nonce = frame_nonce(nonce_base, sequence);
        let aad = frame_aad(host.session_id(), FrameDirection::ExtensionToHost, sequence);
        let plaintext = serde_json::to_vec(message).expect("message");
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .expect("encrypt");
        SecureFrame {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "secure".to_owned(),
            session_id: host.session_id().to_owned(),
            sequence: sequence.to_string(),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        }
    }

    #[test]
    fn signed_handshake_is_origin_bound_and_uses_pinned_identity() {
        let identity = BrowserHostIdentity::from_secret_bytes([7_u8; 32]);
        let extension_secret = [11_u8; 32];
        let open = extension_open(extension_secret, [13_u8; 32]);
        let (ready, _) = identity
            .accept_with_material(ORIGIN, &open, [17_u8; 32], [19_u8; 32])
            .expect("handshake");

        verify_host_ready(ORIGIN, &open, &ready, &identity.public_key()).expect("pinned response");
        assert_eq!(
            verify_host_ready(
                "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/",
                &open,
                &ready,
                &identity.public_key(),
            ),
            Err(SecureTransportError::InvalidSignature)
        );
        assert_eq!(
            verify_host_ready(ORIGIN, &open, &ready, &URL_SAFE_NO_PAD.encode([23_u8; 32])),
            Err(SecureTransportError::InvalidHandshake)
        );
        let debug = format!("{identity:?}");
        assert!(!debug.contains(&URL_SAFE_NO_PAD.encode([7_u8; 32])));
        assert!(!debug.contains(&identity.public_key()));
    }

    #[test]
    fn extension_to_host_frames_are_authenticated_and_replay_protected() {
        let identity = BrowserHostIdentity::from_secret_bytes([29_u8; 32]);
        let extension_secret = [31_u8; 32];
        let open = extension_open(extension_secret, [37_u8; 32]);
        let (ready, mut host) = identity
            .accept_with_material(ORIGIN, &open, [41_u8; 32], [43_u8; 32])
            .expect("handshake");
        let frame = extension_frame(
            &host,
            extension_secret,
            &open,
            &ready,
            0,
            &json!({"type":"prepare.result","outcome":"ready"}),
        );

        let opened: Value = host.open(&frame).expect("authenticated frame");
        assert_eq!(opened["outcome"], "ready");
        assert_eq!(
            host.open::<Value>(&frame),
            Err(SecureTransportError::InvalidFrame)
        );
        let mut tampered = extension_frame(
            &host,
            extension_secret,
            &open,
            &ready,
            1,
            &json!({"type":"inject.result","outcome":"injected"}),
        );
        tampered.ciphertext.replace_range(..1, "A");
        assert_eq!(
            host.open::<Value>(&tampered),
            Err(SecureTransportError::Authentication)
        );
    }

    #[test]
    fn deterministic_handshake_vector_is_stable_for_extension_fixture() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../../contracts/inject-provider/v1/secure-session.json"
        ))
        .expect("secure session vector");
        let identity = BrowserHostIdentity::from_secret_bytes([1_u8; 32]);
        let open = extension_open([2_u8; 32], [3_u8; 32]);
        let (ready, mut host) = identity
            .accept_with_material(ORIGIN, &open, [4_u8; 32], [5_u8; 32])
            .expect("handshake");
        let frame = host
            .seal(&json!({"type":"prepare","nonce":"fixture-nonce"}))
            .expect("frame");
        let extension_frame = extension_frame(
            &host,
            [2_u8; 32],
            &open,
            &ready,
            0,
            &json!({"type":"prepare.result","outcome":"ready"}),
        );
        let opened: Value = host.open(&extension_frame).expect("extension vector frame");

        assert_eq!(
            serde_json::to_value(&open).expect("open value"),
            vector["open"]
        );
        assert_eq!(
            serde_json::to_value(&ready).expect("ready value"),
            vector["ready"]
        );
        assert_eq!(
            serde_json::to_value(&frame).expect("host frame value"),
            vector["firstHostFrame"]
        );
        assert_eq!(
            serde_json::to_value(&extension_frame).expect("extension frame value"),
            vector["firstExtensionFrame"]
        );
        assert_eq!(opened, vector["firstExtensionPlaintext"]);
        assert_eq!(ready.session_id, host.session_id());
        assert_eq!(frame.sequence, "0");
        assert!(
            !serde_json::to_string(&frame)
                .expect("serialize")
                .contains("fixture-nonce")
        );
    }

    #[test]
    fn malformed_origins_and_low_order_extension_keys_fail_closed() {
        let identity = BrowserHostIdentity::from_secret_bytes([47_u8; 32]);
        let open = extension_open([53_u8; 32], [59_u8; 32]);
        assert!(matches!(
            identity.accept("moz-extension://fixture/", &open),
            Err(SecureTransportError::InvalidExtensionOrigin)
        ));
        let low_order = ExtensionSessionOpen {
            extension_ephemeral_public_key: URL_SAFE_NO_PAD.encode([0_u8; 32]),
            ..open
        };
        assert!(matches!(
            identity.accept_with_material(ORIGIN, &low_order, [61_u8; 32], [67_u8; 32]),
            Err(SecureTransportError::InvalidHandshake)
        ));
    }
}
