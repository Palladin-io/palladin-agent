#![forbid(unsafe_code)]

mod envelope;
mod identity;
mod signing;
mod vault_v2;

pub use envelope::{DecryptedCredential, EncryptedCredential, decrypt_credential};
pub use identity::{Ed25519Identity, X25519Identity, verify_profile_binding};
pub use signing::{
    SignatureHeaders, body_sha256_base64, canonical_request, generate_nonce_base64, sign_request,
};
pub use vault_v2::{
    ALGORITHM_SUITE, AadField, AadProfile, AadValue, EnvelopeHeader, HkdfContext, PROTOCOL_VERSION,
    SecretBytes, SignatureProfile, decode_base64url, decrypt_envelope, derive_projection_key,
    encode_aad, key_fingerprint, open_sealed_box, verify_domain_signature,
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
    #[error("unsupported cryptographic protocol")]
    UnsupportedProtocol,
    #[error("cryptographic input is stale")]
    StaleInput,
    #[error("cryptographic input does not match its declared profile")]
    InvalidProfile,
}
