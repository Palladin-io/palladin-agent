//! Synthetic extension peer exercises the actual host forwarding slice. It uses
//! the published secure-session wire algorithm and never opens OS credentials.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use super::*;
use palladin_browser_bridge::secure_transport::HostSecureSession;

pub(super) struct ExtensionPeer {
    material: [u8; 112],
    session_id: String,
}

impl ExtensionPeer {
    pub(super) fn start(identity: &BrowserHostIdentity) -> (HostSecureSession, Self) {
        let secret = StaticSecret::from([23; 32]);
        let public = PublicKey::from(&secret);
        let open = ExtensionSessionOpen {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "session.open".to_owned(),
            extension_nonce: URL_SAFE_NO_PAD.encode([24; 32]),
            extension_ephemeral_public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        };
        let (ready, session) = identity
            .accept(CHROME_EXTENSION_ORIGIN, &open)
            .expect("test handshake");
        let mut transcript = b"palladin.inject-provider.v1\0extension-session-v1\0".to_vec();
        let mut append = |bytes: &[u8]| {
            transcript.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            transcript.extend_from_slice(bytes);
        };
        append(CHROME_EXTENSION_ORIGIN.as_bytes());
        for encoded in [
            &open.extension_nonce,
            &open.extension_ephemeral_public_key,
            &ready.host_nonce,
            &ready.host_ephemeral_public_key,
            &ready.host_signing_public_key,
        ] {
            append(&URL_SAFE_NO_PAD.decode(encoded).expect("wire key"));
        }
        let host_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&ready.host_ephemeral_public_key)
            .expect("host key")
            .try_into()
            .expect("32 bytes");
        let shared = secret.diffie_hellman(&PublicKey::from(host_key));
        let mut material = [0; 112];
        Hkdf::<Sha256>::new(Some(&Sha256::digest(&transcript)), shared.as_bytes())
            .expand(
                b"palladin.inject-provider.v1\0extension-session-keys-v1\0",
                &mut material,
            )
            .expect("derive");
        (
            session,
            Self {
                material,
                session_id: ready.session_id,
            },
        )
    }

    fn aad_nonce(&self, incoming: bool, sequence: u64) -> (Vec<u8>, [u8; 24]) {
        let mut aad = b"palladin.inject-provider.v1\0extension-secure-frame-v1\0".to_vec();
        aad.extend_from_slice(self.session_id.as_bytes());
        aad.push(0);
        aad.extend_from_slice(if incoming {
            b"host-to-extension"
        } else {
            b"extension-to-host"
        });
        aad.push(0);
        aad.extend_from_slice(&sequence.to_be_bytes());
        let mut nonce: [u8; 24] = self.material[if incoming { 64..88 } else { 88..112 }]
            .try_into()
            .expect("nonce");
        for (byte, seq) in nonce[16..].iter_mut().zip(sequence.to_be_bytes()) {
            *byte ^= seq;
        }
        (aad, nonce)
    }

    pub(super) fn open(&self, frame: &SecureFrame, sequence: u64) -> Value {
        assert_eq!(frame.session_id, self.session_id);
        assert_eq!(frame.sequence, sequence.to_string());
        let (aad, nonce) = self.aad_nonce(true, sequence);
        let bytes = URL_SAFE_NO_PAD.decode(&frame.ciphertext).expect("frame");
        let plaintext = XChaCha20Poly1305::new_from_slice(&self.material[..32])
            .expect("key")
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &bytes,
                    aad: &aad,
                },
            )
            .expect("decrypt host frame");
        serde_json::from_slice(&plaintext).expect("synthetic message")
    }

    pub(super) fn seal(&self, value: Value, sequence: u64) -> SecureFrame {
        let (aad, nonce) = self.aad_nonce(false, sequence);
        let plaintext = serde_json::to_vec(&value).expect("synthetic message");
        let ciphertext = XChaCha20Poly1305::new_from_slice(&self.material[32..64])
            .expect("key")
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .expect("encrypt response");
        SecureFrame {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "secure".to_owned(),
            session_id: self.session_id.clone(),
            sequence: sequence.to_string(),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        }
    }
}
