use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use secrecy::SecretString;
use sha2::Sha256;
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

use crate::{CryptoError, X25519Identity};

const SUITE: &str = "palladin-agent-pairing-x25519-xchacha20poly1305-v1";
const HKDF_INFO: &[u8] = b"palladin/agent-pairing/v1/credential";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserPairingEnvelope {
    pub suite: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn open_browser_pairing_credential(
    pairing_id: &str,
    organization_id: &str,
    agent_id: &str,
    api_key_id: &str,
    recipient: &X25519Identity,
    envelope: &BrowserPairingEnvelope,
) -> Result<SecretString, CryptoError> {
    if envelope.suite != SUITE {
        return Err(CryptoError::UnsupportedSuite);
    }
    let ephemeral = decode_exact::<32>(&envelope.ephemeral_public_key)?;
    let nonce = decode_exact::<24>(&envelope.nonce)?;
    let mut ciphertext = Zeroizing::new(
        STANDARD
            .decode(&envelope.ciphertext)
            .map_err(|_| CryptoError::InvalidEncoding)?,
    );
    let shared = Zeroizing::new(
        recipient
            .static_secret()
            .diffie_hellman(&PublicKey::from(ephemeral))
            .to_bytes(),
    );
    if shared.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::AuthenticationFailed);
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(pairing_id.as_bytes()), shared.as_ref())
        .expand(HKDF_INFO, key.as_mut())
        .map_err(|_| CryptoError::InvalidLength)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| CryptoError::InvalidLength)?;
    let aad = format!(
        "palladin-agent-pairing-v1\n{pairing_id}\n{}\n{organization_id}\n{agent_id}\n{api_key_id}",
        STANDARD.encode(recipient.public_key()),
    );
    cipher
        .decrypt_in_place(XNonce::from_slice(&nonce), aad.as_bytes(), &mut *ciphertext)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let plaintext =
        String::from_utf8(ciphertext.to_vec()).map_err(|_| CryptoError::InvalidEncoding)?;
    if !plaintext.starts_with("pl_") {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(SecretString::from(plaintext))
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], CryptoError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    decoded.try_into().map_err(|_| CryptoError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305, XNonce,
        aead::{Aead, Payload},
    };
    use hkdf::Hkdf;
    use secrecy::ExposeSecret;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{BrowserPairingEnvelope, HKDF_INFO, SUITE, open_browser_pairing_credential};
    use crate::X25519Identity;

    #[test]
    fn opens_backend_compatible_envelope_and_binds_authoritative_scope() {
        let recipient = X25519Identity::from_private_bytes(vec![7; 32]).expect("recipient");
        let ephemeral = StaticSecret::from([9_u8; 32]);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient.public_key()));
        let mut key = [0_u8; 32];
        Hkdf::<Sha256>::new(
            Some(b"67ad9d63-f947-4b6c-8f64-e564d42d620f"),
            shared.as_bytes(),
        )
        .expand(HKDF_INFO, &mut key)
        .expect("hkdf");
        let nonce = [3_u8; 24];
        let aad = format!(
            "palladin-agent-pairing-v1\n67ad9d63-f947-4b6c-8f64-e564d42d620f\n{}\n11111111-1111-4111-8111-111111111111\n22222222-2222-4222-8222-222222222222\n33333333-3333-4333-8333-333333333333",
            STANDARD.encode(recipient.public_key()),
        );
        let ciphertext = XChaCha20Poly1305::new_from_slice(&key)
            .expect("key")
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: b"pl_secret",
                    aad: aad.as_bytes(),
                },
            )
            .expect("encrypt");
        let envelope = BrowserPairingEnvelope {
            suite: SUITE.to_owned(),
            ephemeral_public_key: STANDARD.encode(PublicKey::from(&ephemeral).as_bytes()),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        };

        let opened = open_browser_pairing_credential(
            "67ad9d63-f947-4b6c-8f64-e564d42d620f",
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            &recipient,
            &envelope,
        )
        .expect("open");
        assert!(opened.expose_secret() == "pl_secret");
        assert!(
            open_browser_pairing_credential(
                "77ad9d63-f947-4b6c-8f64-e564d42d620f",
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                "33333333-3333-4333-8333-333333333333",
                &recipient,
                &envelope,
            )
            .is_err()
        );
        assert!(
            open_browser_pairing_credential(
                "67ad9d63-f947-4b6c-8f64-e564d42d620f",
                "99999999-9999-4999-8999-999999999999",
                "22222222-2222-4222-8222-222222222222",
                "33333333-3333-4333-8333-333333333333",
                &recipient,
                &envelope,
            )
            .is_err()
        );
    }
}
