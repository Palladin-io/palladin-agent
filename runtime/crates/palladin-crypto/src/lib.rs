#![forbid(unsafe_code)]

mod envelope;
mod grant;
mod identity;
mod local_cache;
mod manifest;
mod reason;
mod script_execution;
mod signing;
mod suite;
mod vault_v2;

pub use envelope::{
    AgentVaultKeyWrapper, AgentVaultKeyWrapperDescriptor, AgentWrappedVaultKey,
    CredentialEnvelopeContext, DecryptedCredential, EncryptedCredential,
    FullCredentialEnvelopeContext, FullScriptMemberSecretContext, GrantEnvelopeBinding,
    GrantEnvelopeDescriptor, GrantEnvelopeScope, MemberSecretBinding, MemberSecretDescriptor,
    MemberSecretEnvelope, VaultEntryKeyDescriptor, VaultEntryKeyEnvelope, VaultKeyBinding,
    WrappedGrantDek, WrappedGrantDekDescriptor, decrypt_credential, decrypt_credential_at,
    decrypt_full_credential, decrypt_full_credential_at, decrypt_full_script_member_secret,
    verify_agent_wrapped_vault_key_producer,
};
pub use grant::{
    DecryptedGrantPayload, ExpectedGrantContext, GrantEnvelopeV2, decrypt_grant_payload,
};
pub use identity::{Ed25519Identity, X25519Identity, verify_profile_binding};
pub use local_cache::{open_local_discovery_cache, seal_local_discovery_cache};
pub use manifest::{
    AgentIdentityBinding, MemberPairingConfirmation, PairingCandidate, PairingRelayStatus,
    PairingTranscript, PairingVault, PinnedVaultTrust, TrustedVdkSet, VaultManifestV2,
    confirm_pairing, confirm_pairing_from_relay, prepare_pairing, verify_current_manifest,
    verify_manifest_update,
};
pub use reason::{
    EncryptedReasonBinding, EncryptedReasonContext, EncryptedReasonDescriptor,
    EncryptedReasonEnvelope, EncryptedReasonScope, ReasonWrapperDescriptor, WrappedReasonDek,
    encrypt_reason,
};
pub use script_execution::{
    ExpectedScriptExecutionPackageContext, OpenedScriptExecutionPackage,
    OpenedScriptExecutionReference, ScriptExecutionAuthorization, ScriptExecutionBinding,
    ScriptExecutionEncryptedPackage, ScriptExecutionManifest, ScriptExecutionMetadata,
    ScriptExecutionParameter, ScriptExecutionParameterType, ScriptExecutionParameters,
    ScriptExecutionReference, ScriptExecutionScope, ScriptExecutionTransportScope,
    encode_script_execution_parameters, open_script_execution_package,
    validate_script_execution_parameters,
};
pub use signing::{
    SignatureHeaders, body_sha256_base64, canonical_request, generate_nonce_base64, sign_request,
};
pub use suite::{
    CryptoSuiteRegistry, EncodedSuitePayload, EnvelopeBinding, EnvelopeDescriptor, EnvelopePurpose,
    EnvelopeScope, InstantBinding, RecipientKeyKind, SealedWrappedKey, VAULT_XCHACHA_V1,
    WrapperContext, WrapperPurpose, X25519_WRAPPER_V1, X25519SealedBoxSuite, XChaChaVaultSuite,
    compute_field_set_commitment, compute_key_fingerprint,
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
    #[error("FULL grant binding has an invalid encoding")]
    InvalidFullGrantBindingEncoding,
    #[error("FULL grant wrapped Vault key has an invalid encoding")]
    InvalidFullGrantVaultKeyEncoding,
    #[error("FULL grant Entry key envelope has an invalid encoding")]
    InvalidFullGrantEntryKeyEncoding,
    #[error("FULL grant MemberSecret descriptor has an invalid encoding")]
    InvalidFullGrantMemberSecretDescriptorEncoding,
    #[error("FULL grant MemberSecret ciphertext has an invalid encoding")]
    InvalidFullGrantMemberSecretCiphertextEncoding,
    #[error("FULL grant MemberSecret plaintext has an invalid encoding")]
    InvalidFullGrantMemberSecretPlaintextEncoding,
    #[error("decrypted grant payload has an invalid encoding")]
    InvalidGrantPayloadEncoding,
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
    #[error("unsupported cryptographic protocol")]
    UnsupportedProtocol,
    #[error("cryptographic input is stale")]
    StaleInput,
    #[error("cryptographic input does not match its declared profile")]
    InvalidProfile,
}
