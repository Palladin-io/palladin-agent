use base64::{Engine, engine::general_purpose::STANDARD};
use blake2::{Blake2b, Digest, digest::consts::U24};
use crypto_secretbox::{Kdf, KeyInit, XSalsa20Poly1305, aead::Aead};
use salsa20::Salsa20;
use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

use crate::{CryptoError, X25519Identity};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedCredential {
    pub re_encrypted_blob: String,
    pub nonce: String,
    pub agent_wrapped_dek: String,
}

pub struct DecryptedCredential(SecretSlice<u8>);

impl DecryptedCredential {
    #[must_use]
    pub fn expose_for_authorized_operation(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for DecryptedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecryptedCredential([REDACTED])")
    }
}

pub fn decrypt_credential(
    envelope: &EncryptedCredential,
    identity: &X25519Identity,
) -> Result<DecryptedCredential, CryptoError> {
    let wrapped_dek = decode_base64(&envelope.agent_wrapped_dek)?;
    let blob = decode_base64(&envelope.re_encrypted_blob)?;
    let nonce = decode_array::<24>(&envelope.nonce)?;
    let dek = unseal_dek(&wrapped_dek, identity)?;

    let cipher = XSalsa20Poly1305::new(dek.as_slice().into());
    let plaintext = cipher
        .decrypt((&nonce).into(), blob.as_slice())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(DecryptedCredential(plaintext.into()))
}

fn unseal_dek(
    wrapped_dek: &[u8],
    identity: &X25519Identity,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if wrapped_dek.len() <= 48 {
        return Err(CryptoError::InvalidLength);
    }

    let ephemeral_bytes: [u8; 32] = wrapped_dek[..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)?;
    let ephemeral_public = PublicKey::from(ephemeral_bytes);
    let static_secret = identity.static_secret();
    let shared_secret = Zeroizing::new(static_secret.diffie_hellman(&ephemeral_public));

    let precomputed_key = Zeroizing::new(<Salsa20 as Kdf>::kdf(
        shared_secret.as_bytes().into(),
        &Default::default(),
    ));
    let seal_nonce = seal_nonce(&ephemeral_bytes, identity.public_key());
    let cipher = XSalsa20Poly1305::new(&precomputed_key);
    let dek = Zeroizing::new(
        cipher
            .decrypt((&seal_nonce).into(), &wrapped_dek[32..])
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    if dek.len() != 32 {
        return Err(CryptoError::InvalidLength);
    }
    Ok(dek)
}

fn seal_nonce(ephemeral_public: &[u8; 32], recipient_public: &[u8; 32]) -> [u8; 24] {
    let mut hasher = Blake2b::<U24>::new();
    hasher.update(ephemeral_public);
    hasher.update(recipient_public);
    hasher.finalize().into()
}

fn decode_base64(value: &str) -> Result<Vec<u8>, CryptoError> {
    STANDARD
        .decode(value)
        .map_err(|_| CryptoError::InvalidEncoding)
}

fn decode_array<const SIZE: usize>(value: &str) -> Result<[u8; SIZE], CryptoError> {
    decode_base64(value)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::DecryptedCredential;

    #[test]
    fn plaintext_debug_is_redacted() {
        let plaintext = DecryptedCredential(b"synthetic-plaintext".to_vec().into());
        let debug = format!("{plaintext:?}");
        assert_eq!(debug, "DecryptedCredential([REDACTED])");
        assert!(!debug.contains("synthetic-plaintext"));
    }
}
