#![forbid(unsafe_code)]

mod envelope;
mod identity;
mod signing;

pub use envelope::{DecryptedCredential, EncryptedCredential, decrypt_credential};
pub use identity::{Ed25519Identity, X25519Identity, verify_profile_binding};
pub use signing::{
    SignatureHeaders, body_sha256_base64, canonical_request, generate_nonce_base64, sign_request,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CryptoError {
    #[error("cryptographic input has an invalid length")]
    InvalidLength,
    #[error("cryptographic input has an invalid encoding")]
    InvalidEncoding,
    #[error("cryptographic authentication failed")]
    AuthenticationFailed,
    #[error("cryptographic random generation failed")]
    RandomGenerationFailed,
    #[error("request signing input is invalid")]
    InvalidSigningInput,
}
