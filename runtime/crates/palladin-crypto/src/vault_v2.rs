use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use blake2::{Blake2b, Digest as BlakeDigest, digest::consts::U24};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use crypto_secretbox::{Kdf, XSalsa20Poly1305};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use salsa20::Salsa20;
use secrecy::{ExposeSecret, SecretSlice};
use sha2::Sha256;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

use crate::{CryptoError, X25519Identity};

pub const PROTOCOL_VERSION: u16 = 2;
pub const ALGORITHM_SUITE: u16 = 1;
const AAD_MAGIC: &[u8; 8] = b"PLDNV2AD";
const HKDF_MAGIC: &[u8; 8] = b"PLDNV2HK";
const HKDF_INFO: &[u8] = b"palladin:vault-v2:";
const MAX_SEALED_BOX_BYTES: usize = 512;
const MAX_SIGNATURE_PAYLOAD_BYTES: usize = 256 * 1024;

pub struct SecretBytes(SecretSlice<u8>);

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    #[must_use]
    pub fn expose_for_crypto_operation(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeHeader {
    pub protocol_version: u16,
    pub algorithm_suite: u16,
    pub resource_kind: u16,
    pub projection_kind: u16,
    pub resource_revision: u64,
    pub key_version: u32,
    pub member_key_generation: u32,
}

impl EnvelopeHeader {
    pub fn validate_supported(self) -> Result<(), CryptoError> {
        if self.protocol_version != PROTOCOL_VERSION || self.algorithm_suite != ALGORITHM_SUITE {
            return Err(CryptoError::UnsupportedProtocol);
        }
        if self.resource_kind == 0
            || self.projection_kind == 0
            || self.resource_revision == 0
            || self.key_version == 0
            || self.member_key_generation == 0
        {
            return Err(CryptoError::InvalidProfile);
        }
        Ok(())
    }

    pub fn validate_freshness(
        self,
        minimum_revision: u64,
        minimum_key_version: u32,
        minimum_member_generation: u32,
    ) -> Result<(), CryptoError> {
        self.validate_supported()?;
        if self.resource_revision < minimum_revision
            || self.key_version < minimum_key_version
            || self.member_key_generation < minimum_member_generation
        {
            return Err(CryptoError::StaleInput);
        }
        Ok(())
    }

    pub fn validate_profile(self, profile: AadProfile) -> Result<(), CryptoError> {
        self.validate_supported()?;
        let expected = match profile {
            AadProfile::MemberVaultMetadata => (1, 1),
            AadProfile::MemberIndex => (2, 2),
            AadProfile::MemberSecret => (2, 3),
            AadProfile::AgentDiscovery => (2, 4),
            AadProfile::EntryKeyWrapper => (2, 8),
            AadProfile::VaultPrivateKey => (1, 7),
            AadProfile::VaultDiscoveryKey => (1, 12),
            AadProfile::EncryptedReason => (3, 5),
            AadProfile::GrantPayload => (4, 6),
        };
        if (self.resource_kind, self.projection_kind) != expected {
            return Err(CryptoError::InvalidProfile);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AadProfile {
    MemberVaultMetadata,
    MemberIndex,
    MemberSecret,
    AgentDiscovery,
    EntryKeyWrapper,
    VaultPrivateKey,
    VaultDiscoveryKey,
    EncryptedReason,
    GrantPayload,
}

impl AadProfile {
    fn required_tags(self) -> &'static [u8] {
        match self {
            Self::MemberVaultMetadata => &[1, 2, 3, 4, 5, 7, 8, 9, 10],
            Self::MemberIndex | Self::AgentDiscovery => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            Self::MemberSecret => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20],
            Self::EntryKeyWrapper => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21],
            Self::VaultPrivateKey => &[1, 2, 3, 4, 5, 7, 8, 9, 10, 21, 22],
            Self::VaultDiscoveryKey => &[1, 2, 3, 4, 5, 7, 8, 9, 10, 21],
            Self::EncryptedReason => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 17, 18],
            Self::GrantPayload => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 17, 18, 19],
        }
    }

    fn optional_tags(self) -> &'static [u8] {
        if self == Self::GrantPayload {
            &[15, 16]
        } else {
            &[]
        }
    }

    fn maximum_ciphertext_bytes(self) -> usize {
        match self {
            Self::MemberVaultMetadata | Self::AgentDiscovery => 16 * 1024,
            Self::MemberIndex => 32 * 1024,
            Self::MemberSecret | Self::GrantPayload => 256 * 1024,
            Self::EntryKeyWrapper => 64,
            Self::VaultPrivateKey | Self::VaultDiscoveryKey => 256,
            Self::EncryptedReason => 4 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AadValue {
    U16(u16),
    U32(u32),
    U64(u64),
    Uuid(Uuid),
    Bytes(Vec<u8>),
    Instant(String),
}

impl AadValue {
    fn type_code(&self) -> u8 {
        match self {
            Self::U16(_) => 1,
            Self::U32(_) => 2,
            Self::U64(_) => 3,
            Self::Uuid(_) => 4,
            Self::Bytes(_) => 5,
            Self::Instant(_) => 6,
        }
    }

    fn encoded(&self) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::U16(value) => Ok(value.to_be_bytes().to_vec()),
            Self::U32(value) => Ok(value.to_be_bytes().to_vec()),
            Self::U64(value) => Ok(value.to_be_bytes().to_vec()),
            Self::Uuid(value) => Ok(value.as_bytes().to_vec()),
            Self::Bytes(value) if !value.is_empty() && value.len() <= 64 => Ok(value.clone()),
            Self::Instant(value) if canonical_instant(value) => Ok(value.as_bytes().to_vec()),
            _ => Err(CryptoError::InvalidEncoding),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AadField {
    pub tag: u8,
    pub value: AadValue,
}

fn field_matches(fields: &[AadField], tag: u8, expected: &AadValue) -> bool {
    fields
        .iter()
        .find(|field| field.tag == tag)
        .is_some_and(|field| &field.value == expected)
}

pub fn encode_aad(profile: AadProfile, fields: &[AadField]) -> Result<Vec<u8>, CryptoError> {
    let required = profile.required_tags();
    let optional = profile.optional_tags();
    let mut previous = 0u8;
    for field in fields {
        if field.tag <= previous
            || (!required.contains(&field.tag) && !optional.contains(&field.tag))
            || expected_type_code(field.tag) != Some(field.value.type_code())
        {
            return Err(CryptoError::InvalidProfile);
        }
        previous = field.tag;
    }
    if fields.len() > u8::MAX as usize
        || required
            .iter()
            .any(|tag| !fields.iter().any(|field| field.tag == *tag))
    {
        return Err(CryptoError::InvalidProfile);
    }

    let mut output = Vec::with_capacity(12 + fields.len() * 8);
    output.extend_from_slice(AAD_MAGIC);
    output.push(1);
    output.push(fields.len() as u8);
    output.extend_from_slice(&0u16.to_be_bytes());
    for field in fields {
        let value = field.value.encoded()?;
        let length = u16::try_from(value.len()).map_err(|_| CryptoError::InvalidLength)?;
        output.extend_from_slice(&[field.tag, field.value.type_code()]);
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(&value);
    }
    Ok(output)
}

fn expected_type_code(tag: u8) -> Option<u8> {
    match tag {
        1 | 2 | 3 | 7 | 14 | 20 | 22 => Some(1),
        9 | 10 | 16 | 17 | 21 => Some(2),
        8 | 19 => Some(3),
        4 | 5 | 6 | 11 | 12 | 13 => Some(4),
        18 => Some(5),
        15 => Some(6),
        _ => None,
    }
}

fn canonical_instant(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(20..=27).contains(&bytes.len()) || !value.ends_with('Z') || value.contains('+') {
        return false;
    }
    let base = &value[..value.len() - 1];
    let (seconds, fraction) = base
        .split_once('.')
        .map_or((base, None), |(seconds, fraction)| {
            (seconds, Some(fraction))
        });
    if seconds.len() != 19
        || seconds.as_bytes()[4] != b'-'
        || seconds.as_bytes()[7] != b'-'
        || seconds.as_bytes()[10] != b'T'
        || seconds.as_bytes()[13] != b':'
        || seconds.as_bytes()[16] != b':'
        || !seconds
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13 | 16) || byte.is_ascii_digit())
    {
        return false;
    }
    let fraction_is_canonical = fraction.is_none_or(|fraction| {
        (1..=6).contains(&fraction.len())
            && fraction.bytes().all(|byte| byte.is_ascii_digit())
            && !fraction.ends_with('0')
    });
    fraction_is_canonical && OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HkdfContext {
    pub resource_kind: u16,
    pub organization_id: Uuid,
    pub vault_id: Uuid,
    pub entry_id: Option<Uuid>,
    pub key_version: u32,
    pub member_key_generation: u32,
    pub purpose_id: u16,
}

pub fn derive_projection_key(
    base_key: &[u8],
    context: HkdfContext,
) -> Result<SecretBytes, CryptoError> {
    let purpose_matches_resource = match context.purpose_id {
        1 => context.resource_kind == 1,
        2..=4 => context.resource_kind == 2,
        5 => true,
        _ => false,
    };
    if base_key.len() != 32
        || !purpose_matches_resource
        || !matches!(context.resource_kind, 1 | 2)
        || context.key_version == 0
        || context.member_key_generation == 0
        || (context.resource_kind == 1 && context.entry_id.is_some())
        || (context.resource_kind == 2 && context.entry_id.is_none())
    {
        return Err(CryptoError::InvalidProfile);
    }

    let mut salt_input = Zeroizing::new(Vec::with_capacity(64));
    salt_input.extend_from_slice(HKDF_MAGIC);
    salt_input.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    salt_input.extend_from_slice(&context.resource_kind.to_be_bytes());
    salt_input.extend_from_slice(context.organization_id.as_bytes());
    salt_input.extend_from_slice(context.vault_id.as_bytes());
    match context.entry_id {
        Some(entry_id) => salt_input.extend_from_slice(entry_id.as_bytes()),
        None => salt_input.extend_from_slice(&[0u8; 16]),
    }
    salt_input.extend_from_slice(&context.key_version.to_be_bytes());
    salt_input.extend_from_slice(&context.member_key_generation.to_be_bytes());
    let salt = Sha256::digest(&*salt_input);

    let mut info = Vec::with_capacity(HKDF_INFO.len() + 2);
    info.extend_from_slice(HKDF_INFO);
    info.extend_from_slice(&context.purpose_id.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), base_key);
    let mut output = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(&info, &mut output)
        .map_err(|_| CryptoError::InvalidLength)?;
    Ok(SecretBytes::new(output.to_vec()))
}

fn decrypt_xchacha20_poly1305(
    header: EnvelopeHeader,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, CryptoError> {
    header.validate_supported()?;
    if key.len() != 32 || nonce.len() != 24 || ciphertext.len() < 16 {
        return Err(CryptoError::InvalidLength);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(SecretBytes::new(plaintext))
}

pub fn decrypt_envelope(
    profile: AadProfile,
    header: EnvelopeHeader,
    key: &[u8],
    nonce: &[u8],
    aad_fields: &[AadField],
    ciphertext: &[u8],
) -> Result<SecretBytes, CryptoError> {
    header.validate_profile(profile)?;
    if !field_matches(aad_fields, 1, &AadValue::U16(header.protocol_version))
        || !field_matches(aad_fields, 2, &AadValue::U16(header.algorithm_suite))
        || !field_matches(aad_fields, 3, &AadValue::U16(header.resource_kind))
        || !field_matches(aad_fields, 7, &AadValue::U16(header.projection_kind))
        || !field_matches(aad_fields, 8, &AadValue::U64(header.resource_revision))
        || !field_matches(aad_fields, 9, &AadValue::U32(header.key_version))
        || !field_matches(aad_fields, 10, &AadValue::U32(header.member_key_generation))
    {
        return Err(CryptoError::InvalidProfile);
    }
    if ciphertext.len() > profile.maximum_ciphertext_bytes() {
        return Err(CryptoError::InvalidLength);
    }
    let aad = encode_aad(profile, aad_fields)?;
    decrypt_xchacha20_poly1305(header, key, nonce, &aad, ciphertext)
}

pub fn key_fingerprint(key_kind: u16, raw_public_key: &[u8]) -> Result<[u8; 32], CryptoError> {
    if !(1..=5).contains(&key_kind) || raw_public_key.len() != 32 {
        return Err(CryptoError::InvalidLength);
    }
    let mut input = Vec::with_capacity(44);
    input.extend_from_slice(b"PLDNV2FP");
    input.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    input.extend_from_slice(&key_kind.to_be_bytes());
    input.extend_from_slice(raw_public_key);
    Ok(Sha256::digest(input).into())
}

pub fn open_sealed_box(
    sealed: &[u8],
    identity: &X25519Identity,
) -> Result<SecretBytes, CryptoError> {
    if sealed.len() <= 48 || sealed.len() > MAX_SEALED_BOX_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    let ephemeral_bytes: [u8; 32] = sealed[..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)?;
    let ephemeral_public = PublicKey::from(ephemeral_bytes);
    let static_secret = identity.static_secret();
    let shared_secret = Zeroizing::new(static_secret.diffie_hellman(&ephemeral_public));
    let precomputed_key = Zeroizing::new(<Salsa20 as Kdf>::kdf(
        shared_secret.as_bytes().into(),
        &Default::default(),
    ));
    let mut hasher = Blake2b::<U24>::new();
    hasher.update(ephemeral_bytes);
    hasher.update(identity.public_key());
    let nonce: [u8; 24] = hasher.finalize().into();
    let cipher = XSalsa20Poly1305::new(&precomputed_key);
    let plaintext = cipher
        .decrypt((&nonce).into(), &sealed[32..])
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(SecretBytes::new(plaintext))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureProfile {
    VaultManifest,
    EncryptedReason,
}

impl SignatureProfile {
    fn domain_prefix(self) -> &'static [u8] {
        match self {
            Self::VaultManifest => b"PLDNV2SIG:VAULT-MANIFEST:",
            Self::EncryptedReason => b"PLDNV2SIG:ENCRYPTED-REASON:",
        }
    }
}

pub fn verify_domain_signature(
    profile: SignatureProfile,
    protocol_version: u16,
    canonical_json: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if protocol_version != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedProtocol);
    }
    if canonical_json.is_empty() || canonical_json.len() > MAX_SIGNATURE_PAYLOAD_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    let public_key: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)?;
    let signature: &[u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)?;
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidEncoding)?;
    let domain_prefix = profile.domain_prefix();
    let mut input = Vec::with_capacity(domain_prefix.len() + 2 + canonical_json.len());
    input.extend_from_slice(domain_prefix);
    input.extend_from_slice(&protocol_version.to_be_bytes());
    input.extend_from_slice(canonical_json);
    verifying_key
        .verify(&input, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub fn decode_base64url(value: &str) -> Result<Vec<u8>, CryptoError> {
    if value.contains('=') {
        return Err(CryptoError::InvalidEncoding);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use super::{EnvelopeHeader, SecretBytes};
    use crate::CryptoError;

    #[test]
    fn secret_debug_is_redacted() {
        let canary = "synthetic-canary";
        let secret = SecretBytes::new(canary.as_bytes().to_vec());
        let debug = format!("{secret:?}");
        assert_eq!(debug, "SecretBytes([REDACTED])");
        assert!(!debug.contains(canary));
    }

    #[test]
    fn unsupported_and_stale_headers_fail_before_crypto() {
        let header = EnvelopeHeader {
            protocol_version: 2,
            algorithm_suite: 1,
            resource_kind: 2,
            projection_kind: 3,
            resource_revision: 7,
            key_version: 4,
            member_key_generation: 3,
        };
        assert_eq!(
            header.validate_freshness(8, 4, 3),
            Err(CryptoError::StaleInput)
        );
        assert_eq!(
            EnvelopeHeader {
                protocol_version: 1,
                ..header
            }
            .validate_supported(),
            Err(CryptoError::UnsupportedProtocol)
        );
        assert_eq!(
            EnvelopeHeader {
                algorithm_suite: 99,
                ..header
            }
            .validate_supported(),
            Err(CryptoError::UnsupportedProtocol)
        );
    }
}
