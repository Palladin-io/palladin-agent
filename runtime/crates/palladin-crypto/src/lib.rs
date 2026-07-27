#![forbid(unsafe_code)]

mod envelope;
mod identity;
mod signing;
mod suite;

pub use envelope::{
    CredentialEnvelopeContext, DecryptedCredential, EncryptedCredential, GrantEnvelopeBinding,
    GrantEnvelopeDescriptor, GrantEnvelopeScope, WrappedGrantDek, WrappedGrantDekDescriptor,
    decrypt_credential, decrypt_credential_at,
};
pub use identity::{Ed25519Identity, X25519Identity, verify_profile_binding};
pub use signing::{
    SignatureHeaders, body_sha256_base64, canonical_request, generate_nonce_base64, sign_request,
};
pub use suite::{
    CryptoSuiteRegistry, EncodedSuitePayload, EnvelopeBinding, EnvelopeDescriptor, EnvelopePurpose,
    EnvelopeScope, InstantBinding, RecipientKeyKind, SealedWrappedKey, VAULT_XCHACHA_V1,
    WrapperContext, WrapperPurpose, X25519_WRAPPER_V1, X25519SealedBoxSuite, XChaChaVaultSuite,
    compute_field_set_commitment, compute_key_fingerprint,
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
    #[error("cryptographic suite is not supported")]
    UnsupportedSuite,
    #[error("cryptographic envelope descriptor is invalid")]
    InvalidDescriptor,
}
