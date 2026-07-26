#![forbid(unsafe_code)]

mod envelope;
mod grant;
mod identity;
mod manifest;
mod signing;
mod vault_v2;

pub use envelope::{DecryptedCredential, EncryptedCredential, decrypt_credential};
pub use grant::{
    DecryptedGrantPayload, ExpectedGrantContext, GrantEnvelopeV2, decrypt_grant_payload,
};
pub use identity::{Ed25519Identity, X25519Identity, verify_profile_binding};
pub use manifest::{
    AgentIdentityBinding, MemberPairingConfirmation, PairingCandidate, PairingRelayStatus,
    PairingTranscript, PairingVault, PinnedVaultTrust, TrustedVdkSet, VaultManifestV2,
    confirm_pairing, confirm_pairing_from_relay, prepare_pairing, verify_current_manifest,
    verify_manifest_update,
};
pub use signing::{
    SignatureHeaders, body_sha256_base64, canonical_request, generate_nonce_base64, sign_request,
};
pub use vault_v2::{
    ALGORITHM_SUITE, AadField, AadProfile, AadValue, EncryptedReasonContext,
    EncryptedReasonEnvelope, EncryptedReasonHeader, EnvelopeHeader, HkdfContext, PROTOCOL_VERSION,
    SecretBytes, SignatureProfile, decode_base64url, decrypt_envelope, derive_projection_key,
    encode_aad, encrypt_reason, key_fingerprint, open_sealed_box, verify_domain_signature,
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
