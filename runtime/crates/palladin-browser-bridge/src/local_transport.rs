//! Mutually authenticated local transport between the CLI and the Native Messaging host.
//!
//! The Unix socket is only a rendezvous point. Both peers must prove possession of the durable
//! browser-host identity held in OS secure storage before any Inject message is accepted. Fresh
//! X25519 material derives independent directional XChaCha20-Poly1305 keys for every connection.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::secure_transport::{BrowserHostIdentity, SecureTransportError};

pub const LOCAL_TRANSPORT_PROTOCOL: &str = "palladin.browser-host-ipc.v1";

const CLIENT_OPEN_DOMAIN: &[u8] = b"palladin.browser-host-ipc.v1\0client-open-v1\0";
const SESSION_DOMAIN: &[u8] = b"palladin.browser-host-ipc.v1\0session-v1\0";
const SESSION_ID_DOMAIN: &[u8] = b"palladin.browser-host-ipc.v1\0session-id-v1\0";
const KEY_DERIVATION_INFO: &[u8] = b"palladin.browser-host-ipc.v1\0session-keys-v1\0";
const FRAME_AAD_DOMAIN: &[u8] = b"palladin.browser-host-ipc.v1\0secure-frame-v1\0";
const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const MATERIAL_BYTES: usize = 112;
const MAX_PLAINTEXT_BYTES: usize = 768 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalSessionOpen {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub client_nonce: String,
    pub client_ephemeral_public_key: String,
    pub client_signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalSessionReady {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub client_nonce: String,
    pub host_nonce: String,
    pub host_ephemeral_public_key: String,
    pub host_signature: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalSecureFrame {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub session_id: String,
    pub sequence: String,
    pub ciphertext: String,
}

pub struct LocalClientHandshake {
    client_nonce: [u8; KEY_BYTES],
    client_ephemeral_secret: Zeroizing<[u8; KEY_BYTES]>,
    client_ephemeral_public_key: [u8; KEY_BYTES],
    host_signing_public_key: [u8; KEY_BYTES],
}

impl LocalClientHandshake {
    pub fn start(
        identity: &BrowserHostIdentity,
    ) -> Result<(LocalSessionOpen, Self), SecureTransportError> {
        let mut client_nonce = [0_u8; KEY_BYTES];
        let mut client_ephemeral_secret = [0_u8; KEY_BYTES];
        getrandom::fill(&mut client_nonce).map_err(|_| SecureTransportError::Randomness)?;
        getrandom::fill(&mut client_ephemeral_secret)
            .map_err(|_| SecureTransportError::Randomness)?;
        let client_secret = StaticSecret::from(client_ephemeral_secret);
        let client_ephemeral_public_key = PublicKey::from(&client_secret).to_bytes();
        let host_signing_public_key = identity.verifying_key_bytes();
        let transcript = client_open_transcript(
            &client_nonce,
            &client_ephemeral_public_key,
            &host_signing_public_key,
        );
        let client_signature = identity.sign_message(&transcript);
        let open = LocalSessionOpen {
            protocol: LOCAL_TRANSPORT_PROTOCOL.to_owned(),
            message_type: "session.open".to_owned(),
            client_nonce: URL_SAFE_NO_PAD.encode(client_nonce),
            client_ephemeral_public_key: URL_SAFE_NO_PAD.encode(client_ephemeral_public_key),
            client_signature: URL_SAFE_NO_PAD.encode(client_signature),
        };
        Ok((
            open,
            Self {
                client_nonce,
                client_ephemeral_secret: Zeroizing::new(client_ephemeral_secret),
                client_ephemeral_public_key,
                host_signing_public_key,
            },
        ))
    }

    pub fn finish(
        self,
        ready: &LocalSessionReady,
    ) -> Result<LocalSecureSession, SecureTransportError> {
        if ready.protocol != LOCAL_TRANSPORT_PROTOCOL
            || ready.message_type != "session.ready"
            || ready.client_nonce != URL_SAFE_NO_PAD.encode(self.client_nonce)
        {
            return Err(SecureTransportError::InvalidHandshake);
        }
        let host_nonce = decode_exact::<KEY_BYTES>(&ready.host_nonce)?;
        let host_ephemeral_public_key =
            decode_exact::<KEY_BYTES>(&ready.host_ephemeral_public_key)?;
        let host_signature = decode_exact::<SIGNATURE_BYTES>(&ready.host_signature)?;
        let transcript = session_transcript(
            &self.client_nonce,
            &self.client_ephemeral_public_key,
            &host_nonce,
            &host_ephemeral_public_key,
            &self.host_signing_public_key,
        );
        let verifying = VerifyingKey::from_bytes(&self.host_signing_public_key)
            .map_err(|_| SecureTransportError::InvalidSignature)?;
        verifying
            .verify(&transcript, &Signature::from_bytes(&host_signature))
            .map_err(|_| SecureTransportError::InvalidSignature)?;
        if ready.session_id != session_id(&transcript, &host_signature) {
            return Err(SecureTransportError::InvalidHandshake);
        }
        let secret = StaticSecret::from(*self.client_ephemeral_secret);
        let shared = Zeroizing::new(
            secret
                .diffie_hellman(&PublicKey::from(host_ephemeral_public_key))
                .to_bytes(),
        );
        reject_zero_shared(&shared)?;
        let material = derive_material(&shared, &transcript)?;
        Ok(LocalSecureSession::from_material(
            ready.session_id.clone(),
            material,
            LocalRole::Client,
        ))
    }
}

pub fn accept_local_client(
    identity: &BrowserHostIdentity,
    open: &LocalSessionOpen,
) -> Result<(LocalSessionReady, LocalSecureSession), SecureTransportError> {
    let mut host_nonce = [0_u8; KEY_BYTES];
    let mut host_ephemeral_secret = [0_u8; KEY_BYTES];
    getrandom::fill(&mut host_nonce).map_err(|_| SecureTransportError::Randomness)?;
    getrandom::fill(&mut host_ephemeral_secret).map_err(|_| SecureTransportError::Randomness)?;
    let result =
        accept_local_client_with_material(identity, open, host_nonce, host_ephemeral_secret);
    host_ephemeral_secret.zeroize();
    result
}

fn accept_local_client_with_material(
    identity: &BrowserHostIdentity,
    open: &LocalSessionOpen,
    host_nonce: [u8; KEY_BYTES],
    host_ephemeral_secret: [u8; KEY_BYTES],
) -> Result<(LocalSessionReady, LocalSecureSession), SecureTransportError> {
    if open.protocol != LOCAL_TRANSPORT_PROTOCOL || open.message_type != "session.open" {
        return Err(SecureTransportError::InvalidHandshake);
    }
    let client_nonce = decode_exact::<KEY_BYTES>(&open.client_nonce)?;
    let client_ephemeral_public_key = decode_exact::<KEY_BYTES>(&open.client_ephemeral_public_key)?;
    let client_signature = decode_exact::<SIGNATURE_BYTES>(&open.client_signature)?;
    let host_signing_public_key = identity.verifying_key_bytes();
    let client_transcript = client_open_transcript(
        &client_nonce,
        &client_ephemeral_public_key,
        &host_signing_public_key,
    );
    let verifying = VerifyingKey::from_bytes(&host_signing_public_key)
        .map_err(|_| SecureTransportError::InvalidSignature)?;
    verifying
        .verify(
            &client_transcript,
            &Signature::from_bytes(&client_signature),
        )
        .map_err(|_| SecureTransportError::InvalidSignature)?;

    let host_secret = StaticSecret::from(host_ephemeral_secret);
    let host_ephemeral_public_key = PublicKey::from(&host_secret).to_bytes();
    let transcript = session_transcript(
        &client_nonce,
        &client_ephemeral_public_key,
        &host_nonce,
        &host_ephemeral_public_key,
        &host_signing_public_key,
    );
    let host_signature = identity.sign_message(&transcript);
    let session_id = session_id(&transcript, &host_signature);
    let shared = Zeroizing::new(
        host_secret
            .diffie_hellman(&PublicKey::from(client_ephemeral_public_key))
            .to_bytes(),
    );
    reject_zero_shared(&shared)?;
    let material = derive_material(&shared, &transcript)?;
    let ready = LocalSessionReady {
        protocol: LOCAL_TRANSPORT_PROTOCOL.to_owned(),
        message_type: "session.ready".to_owned(),
        client_nonce: open.client_nonce.clone(),
        host_nonce: URL_SAFE_NO_PAD.encode(host_nonce),
        host_ephemeral_public_key: URL_SAFE_NO_PAD.encode(host_ephemeral_public_key),
        host_signature: URL_SAFE_NO_PAD.encode(host_signature),
        session_id: session_id.clone(),
    };
    Ok((
        ready,
        LocalSecureSession::from_material(session_id, material, LocalRole::Host),
    ))
}

pub struct LocalSecureSession {
    session_id: String,
    send_key: Zeroizing<[u8; 32]>,
    receive_key: Zeroizing<[u8; 32]>,
    send_nonce_base: [u8; 24],
    receive_nonce_base: [u8; 24],
    send_direction: Direction,
    receive_direction: Direction,
    send_sequence: u64,
    receive_sequence: u64,
}

impl LocalSecureSession {
    fn from_material(
        session_id: String,
        material: Zeroizing<[u8; MATERIAL_BYTES]>,
        role: LocalRole,
    ) -> Self {
        let (send_key_range, receive_key_range, send_nonce_range, receive_nonce_range) = match role
        {
            LocalRole::Host => (0..32, 32..64, 64..88, 88..112),
            LocalRole::Client => (32..64, 0..32, 88..112, 64..88),
        };
        let mut send_key = [0_u8; 32];
        send_key.copy_from_slice(&material[send_key_range]);
        let mut receive_key = [0_u8; 32];
        receive_key.copy_from_slice(&material[receive_key_range]);
        let mut send_nonce_base = [0_u8; 24];
        send_nonce_base.copy_from_slice(&material[send_nonce_range]);
        let mut receive_nonce_base = [0_u8; 24];
        receive_nonce_base.copy_from_slice(&material[receive_nonce_range]);
        let (send_direction, receive_direction) = match role {
            LocalRole::Host => (Direction::HostToClient, Direction::ClientToHost),
            LocalRole::Client => (Direction::ClientToHost, Direction::HostToClient),
        };
        Self {
            session_id,
            send_key: Zeroizing::new(send_key),
            receive_key: Zeroizing::new(receive_key),
            send_nonce_base,
            receive_nonce_base,
            send_direction,
            receive_direction,
            send_sequence: 0,
            receive_sequence: 0,
        }
    }

    pub fn seal<T: Serialize>(
        &mut self,
        message: &T,
    ) -> Result<LocalSecureFrame, SecureTransportError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(message).map_err(|_| SecureTransportError::InvalidMessage)?,
        );
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(SecureTransportError::InvalidMessage);
        }
        let sequence = self.send_sequence;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.send_key.as_ref()));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&frame_nonce(self.send_nonce_base, sequence)),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &frame_aad(&self.session_id, self.send_direction, sequence),
                },
            )
            .map_err(|_| SecureTransportError::Encryption)?;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(SecureTransportError::SequenceExhausted)?;
        Ok(LocalSecureFrame {
            protocol: LOCAL_TRANSPORT_PROTOCOL.to_owned(),
            message_type: "secure".to_owned(),
            session_id: self.session_id.clone(),
            sequence: sequence.to_string(),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    pub fn open<T: DeserializeOwned>(
        &mut self,
        frame: &LocalSecureFrame,
    ) -> Result<T, SecureTransportError> {
        if frame.protocol != LOCAL_TRANSPORT_PROTOCOL
            || frame.message_type != "secure"
            || frame.session_id != self.session_id
            || parse_sequence(&frame.sequence)? != self.receive_sequence
        {
            return Err(SecureTransportError::InvalidFrame);
        }
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&frame.ciphertext)
            .map_err(|_| SecureTransportError::InvalidFrame)?;
        if ciphertext.len() <= 16 || ciphertext.len() > MAX_PLAINTEXT_BYTES + 16 {
            return Err(SecureTransportError::InvalidFrame);
        }
        let sequence = self.receive_sequence;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.receive_key.as_ref()));
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&frame_nonce(self.receive_nonce_base, sequence)),
                    Payload {
                        msg: &ciphertext,
                        aad: &frame_aad(&self.session_id, self.receive_direction, sequence),
                    },
                )
                .map_err(|_| SecureTransportError::Authentication)?,
        );
        let value = serde_json::from_slice(plaintext.as_ref())
            .map_err(|_| SecureTransportError::InvalidMessage)?;
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or(SecureTransportError::SequenceExhausted)?;
        Ok(value)
    }
}

impl std::fmt::Debug for LocalSecureSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalSecureSession")
            .field("session_id", &"[SESSION ID]")
            .field("keys", &"[REDACTED]")
            .field("send_sequence", &self.send_sequence)
            .field("receive_sequence", &self.receive_sequence)
            .finish()
    }
}

impl Drop for LocalSecureSession {
    fn drop(&mut self) {
        self.send_nonce_base.zeroize();
        self.receive_nonce_base.zeroize();
        self.send_sequence.zeroize();
        self.receive_sequence.zeroize();
    }
}

#[derive(Clone, Copy)]
enum LocalRole {
    Host,
    Client,
}

#[derive(Clone, Copy)]
enum Direction {
    HostToClient,
    ClientToHost,
}

impl Direction {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::HostToClient => b"host-to-client",
            Self::ClientToHost => b"client-to-host",
        }
    }
}

fn client_open_transcript(
    client_nonce: &[u8; 32],
    client_ephemeral_public_key: &[u8; 32],
    host_signing_public_key: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut transcript = Zeroizing::new(Vec::with_capacity(180));
    transcript.extend_from_slice(CLIENT_OPEN_DOMAIN);
    append_bytes(&mut transcript, client_nonce);
    append_bytes(&mut transcript, client_ephemeral_public_key);
    append_bytes(&mut transcript, host_signing_public_key);
    transcript
}

fn session_transcript(
    client_nonce: &[u8; 32],
    client_ephemeral_public_key: &[u8; 32],
    host_nonce: &[u8; 32],
    host_ephemeral_public_key: &[u8; 32],
    host_signing_public_key: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut transcript = Zeroizing::new(Vec::with_capacity(260));
    transcript.extend_from_slice(SESSION_DOMAIN);
    append_bytes(&mut transcript, client_nonce);
    append_bytes(&mut transcript, client_ephemeral_public_key);
    append_bytes(&mut transcript, host_nonce);
    append_bytes(&mut transcript, host_ephemeral_public_key);
    append_bytes(&mut transcript, host_signing_public_key);
    transcript
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("bounded handshake item");
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
}

fn session_id(transcript: &[u8], signature: &[u8; 64]) -> String {
    let mut digest = Sha256::new();
    digest.update(SESSION_ID_DOMAIN);
    digest.update(transcript);
    digest.update(signature);
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn derive_material(
    shared: &[u8; 32],
    transcript: &[u8],
) -> Result<Zeroizing<[u8; MATERIAL_BYTES]>, SecureTransportError> {
    let salt = Sha256::digest(transcript);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut material = Zeroizing::new([0_u8; MATERIAL_BYTES]);
    hkdf.expand(KEY_DERIVATION_INFO, material.as_mut())
        .map_err(|_| SecureTransportError::KeyDerivation)?;
    Ok(material)
}

fn reject_zero_shared(shared: &[u8; 32]) -> Result<(), SecureTransportError> {
    if shared.iter().all(|byte| *byte == 0) {
        Err(SecureTransportError::InvalidHandshake)
    } else {
        Ok(())
    }
}

fn frame_nonce(mut base: [u8; 24], sequence: u64) -> [u8; 24] {
    for (target, source) in base[16..].iter_mut().zip(sequence.to_be_bytes()) {
        *target ^= source;
    }
    base
}

fn frame_aad(session_id: &str, direction: Direction, sequence: u64) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn mutually_authenticated_channel_round_trips_and_rejects_replay() {
        let identity = BrowserHostIdentity::from_secret_bytes([7_u8; 32]);
        let (open, pending) = LocalClientHandshake::start(&identity).expect("client open");
        let (ready, mut host) = accept_local_client(&identity, &open).expect("host accept");
        let mut client = pending.finish(&ready).expect("client finish");

        let frame = client.seal(&json!({"type":"prepare"})).expect("seal");
        let value: Value = host.open(&frame).expect("open");
        assert_eq!(value, json!({"type":"prepare"}));
        assert_eq!(
            host.open::<Value>(&frame),
            Err(SecureTransportError::InvalidFrame)
        );

        let response = host
            .seal(&json!({"type":"prepare.result","outcome":"ready"}))
            .expect("seal response");
        let value: Value = client.open(&response).expect("open response");
        assert_eq!(value["outcome"], "ready");
    }

    #[test]
    fn wrong_identity_and_tampering_fail_closed() {
        let identity = BrowserHostIdentity::from_secret_bytes([11_u8; 32]);
        let attacker = BrowserHostIdentity::from_secret_bytes([13_u8; 32]);
        let (open, _) = LocalClientHandshake::start(&attacker).expect("attacker open");
        assert_eq!(
            accept_local_client(&identity, &open).unwrap_err(),
            SecureTransportError::InvalidSignature
        );

        let (open, pending) = LocalClientHandshake::start(&identity).expect("client open");
        let (mut ready, _) = accept_local_client(&identity, &open).expect("host accept");
        ready.host_signature.replace_range(0..1, "A");
        assert!(matches!(
            pending.finish(&ready),
            Err(SecureTransportError::InvalidSignature | SecureTransportError::InvalidHandshake)
        ));
    }
}
