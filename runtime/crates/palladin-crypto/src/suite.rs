use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core::OsRng;
use secrecy::{ExposeSecret, SecretBox, SecretSlice};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{CryptoError, X25519Identity};

pub const VAULT_XCHACHA_V1: &str = "palladin-vault-xchacha-v1";
pub const X25519_WRAPPER_V1: &str = "palladin-x25519-sealed-box-v1";

const MAX_SUITE_PAYLOAD_BYTES: usize = 1024 * 1024;
const XCHACHA_NONCE_BYTES: usize = 24;
const POLY1305_TAG_BYTES: usize = 16;
const KEY_BYTES: usize = 32;
const DESCRIPTOR_MAGIC: &[u8; 8] = b"PLDNENV2";
const KDF_MAGIC: &[u8; 8] = b"PLDNKDF2";
const PROTOCOL_VERSION: u16 = 2;
const MAX_SUITE_ID_BYTES: usize = 64;

const SCOPE_ORGANIZATION: u16 = 1 << 0;
const SCOPE_VAULT: u16 = 1 << 1;
const SCOPE_ENTRY: u16 = 1 << 2;
const SCOPE_GRANT_OR_REQUEST: u16 = 1 << 3;
const SCOPE_AGENT: u16 = 1 << 4;
const SCOPE_MEMBER: u16 = 1 << 5;
const WRAPPER_CONTEXT_MAGIC: &[u8; 8] = b"PLDNX2W1";
const WRAPPED_KEY_MAGIC: &[u8; 8] = b"PLDNX2K1";
const WRAPPER_HASH_DOMAIN: &[u8; 9] = b"PLDNX2CTX";
const FINGERPRINT_DOMAIN: &[u8; 8] = b"PLDNV2FP";
const SEALED_BOX_OVERHEAD: usize = 48;
const WRAPPED_KEY_PLAINTEXT_BYTES: usize = 72;
const SEALED_WRAPPED_KEY_BYTES: usize = WRAPPED_KEY_PLAINTEXT_BYTES + SEALED_BOX_OVERHEAD;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum EnvelopePurpose {
    MemberVaultMetadata = 1,
    VaultDiscoveryKey = 2,
    VaultAgentMessagePrivateKey = 3,
    VaultManifestSigningPrivateKey = 4,
    MemberIndex = 5,
    MemberSecret = 6,
    AgentDiscovery = 7,
    EntryDekByVaultKey = 8,
    EncryptedReason = 9,
    GrantPayload = 10,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeScope {
    pub organization_id: [u8; 16],
    pub vault_id: [u8; 16],
    pub entry_id: Option<[u8; 16]>,
    pub grant_or_request_id: Option<[u8; 16]>,
    pub agent_id: Option<[u8; 16]>,
    pub member_id: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstantBinding {
    pub unix_seconds: i64,
    pub nanosecond: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopeBinding {
    None,
    MemberSecret {
        operation: u16,
    },
    VaultKey {
        wrapping_vault_key_version: u32,
    },
    Reason {
        wrapper_suite_id: String,
        agent_message_key_version: u32,
        recipient_vault_message_key_fingerprint: [u8; 32],
        requested_methods: u16,
    },
    Grant {
        entry_revision: u64,
        wrapper_suite_id: String,
        recipient_agent_key_version: u32,
        recipient_agent_key_fingerprint: [u8; 32],
        approved_methods: u16,
        field_set_commitment: [u8; 32],
        expires_at: Option<InstantBinding>,
        remaining_uses: Option<u32>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum WrapperPurpose {
    MemberVaultKey = 1,
    AgentVdk = 2,
    ReasonDek = 3,
    GrantDek = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RecipientKeyKind {
    AgentX25519 = 1,
    AgentEd25519 = 2,
    VaultSigningEd25519 = 3,
    VaultMessageX25519 = 4,
    MemberX25519 = 5,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrapperContext {
    pub protocol_version: u16,
    pub wrapper_suite_id: String,
    pub purpose: WrapperPurpose,
    pub scope: EnvelopeScope,
    pub resource_revision: u64,
    pub wrapped_key_version: u32,
    pub member_key_generation: Option<u32>,
    pub recipient_key_kind: RecipientKeyKind,
    pub recipient_key_version: u32,
    pub recipient_fingerprint: [u8; 32],
    pub parent_descriptor_hash: Option<[u8; 32]>,
}

impl WrapperContext {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        validate_wrapper_context(self)?;
        let suite = self.wrapper_suite_id.as_bytes();
        let bitmap = scope_bitmap(&self.scope);
        let mut encoded = Vec::with_capacity(192);
        encoded.extend_from_slice(WRAPPER_CONTEXT_MAGIC);
        push_u16(&mut encoded, self.protocol_version);
        push_u16(
            &mut encoded,
            u16::try_from(suite.len()).map_err(|_| CryptoError::InvalidLength)?,
        );
        encoded.extend_from_slice(suite);
        push_u16(&mut encoded, self.purpose as u16);
        push_u16(&mut encoded, bitmap);
        push_scope_id(
            &mut encoded,
            bitmap,
            SCOPE_ORGANIZATION,
            self.scope.organization_id,
        );
        push_scope_id(&mut encoded, bitmap, SCOPE_VAULT, self.scope.vault_id);
        push_optional_scope_id(&mut encoded, bitmap, SCOPE_ENTRY, self.scope.entry_id);
        push_optional_scope_id(
            &mut encoded,
            bitmap,
            SCOPE_GRANT_OR_REQUEST,
            self.scope.grant_or_request_id,
        );
        push_optional_scope_id(&mut encoded, bitmap, SCOPE_AGENT, self.scope.agent_id);
        push_optional_scope_id(&mut encoded, bitmap, SCOPE_MEMBER, self.scope.member_id);
        push_u64(&mut encoded, self.resource_revision);
        push_u32(&mut encoded, self.wrapped_key_version);
        push_optional_u32(&mut encoded, self.member_key_generation);
        push_u16(&mut encoded, self.recipient_key_kind as u16);
        push_u32(&mut encoded, self.recipient_key_version);
        encoded.extend_from_slice(&self.recipient_fingerprint);
        match self.parent_descriptor_hash {
            Some(hash) => {
                encoded.push(1);
                encoded.extend_from_slice(&hash);
            }
            None => encoded.push(0),
        }
        Ok(encoded)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SealedWrappedKey(Vec<u8>);

impl SealedWrappedKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        CryptoSuiteRegistry::validate_wrapper(X25519_WRAPPER_V1, &bytes)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SealedWrappedKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedWrappedKey")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

pub struct X25519SealedBoxSuite;

impl X25519SealedBoxSuite {
    pub fn wrap(
        key: &SecretBox<[u8; KEY_BYTES]>,
        recipient_public_key: [u8; 32],
        context: &WrapperContext,
    ) -> Result<SealedWrappedKey, CryptoError> {
        verify_recipient(&recipient_public_key, context)?;
        let context_hash = wrapper_context_hash(context)?;
        let mut plaintext = Zeroizing::new([0_u8; WRAPPED_KEY_PLAINTEXT_BYTES]);
        plaintext[..8].copy_from_slice(WRAPPED_KEY_MAGIC);
        plaintext[8..40].copy_from_slice(key.expose_secret());
        plaintext[40..].copy_from_slice(&context_hash);
        let recipient = crypto_box::PublicKey::from(recipient_public_key);
        let sealed = recipient
            .seal(&mut OsRng, plaintext.as_ref())
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        SealedWrappedKey::from_bytes(sealed)
    }

    pub fn unwrap(
        wrapped: &SealedWrappedKey,
        recipient: &X25519Identity,
        context: &WrapperContext,
    ) -> Result<SecretBox<[u8; KEY_BYTES]>, CryptoError> {
        verify_recipient(recipient.public_key(), context)?;
        let secret = crypto_box::SecretKey::from_bytes(recipient.static_secret().to_bytes());
        let plaintext = Zeroizing::new(
            secret
                .unseal(wrapped.as_bytes())
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );
        if plaintext.len() != WRAPPED_KEY_PLAINTEXT_BYTES
            || plaintext[..8].ct_eq(WRAPPED_KEY_MAGIC).unwrap_u8() != 1
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        let expected_hash = wrapper_context_hash(context)?;
        if plaintext[40..].ct_eq(&expected_hash).unwrap_u8() != 1 {
            return Err(CryptoError::AuthenticationFailed);
        }
        let key: [u8; KEY_BYTES] = plaintext[8..40]
            .try_into()
            .map_err(|_| CryptoError::InvalidLength)?;
        Ok(SecretBox::new(Box::new(key)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeDescriptor {
    pub protocol_version: u16,
    pub crypto_suite_id: String,
    pub purpose: EnvelopePurpose,
    pub scope: EnvelopeScope,
    pub resource_revision: u64,
    pub key_version: u32,
    pub member_key_generation: Option<u32>,
    pub binding: EnvelopeBinding,
}

impl EnvelopeDescriptor {
    pub fn canonical_aad(&self) -> Result<Vec<u8>, CryptoError> {
        validate_descriptor(self)?;
        let suite = self.crypto_suite_id.as_bytes();
        let mut encoded = Vec::with_capacity(192);
        encoded.extend_from_slice(DESCRIPTOR_MAGIC);
        push_u16(&mut encoded, self.protocol_version);
        push_u16(
            &mut encoded,
            u16::try_from(suite.len()).map_err(|_| CryptoError::InvalidLength)?,
        );
        encoded.extend_from_slice(suite);
        push_u16(&mut encoded, self.purpose as u16);

        let bitmap = scope_bitmap(&self.scope);
        push_u16(&mut encoded, bitmap);
        push_scope_id(
            &mut encoded,
            bitmap,
            SCOPE_ORGANIZATION,
            self.scope.organization_id,
        );
        push_scope_id(&mut encoded, bitmap, SCOPE_VAULT, self.scope.vault_id);
        push_optional_scope_id(&mut encoded, bitmap, SCOPE_ENTRY, self.scope.entry_id);
        push_optional_scope_id(
            &mut encoded,
            bitmap,
            SCOPE_GRANT_OR_REQUEST,
            self.scope.grant_or_request_id,
        );
        push_optional_scope_id(&mut encoded, bitmap, SCOPE_AGENT, self.scope.agent_id);
        push_optional_scope_id(&mut encoded, bitmap, SCOPE_MEMBER, self.scope.member_id);
        push_u64(&mut encoded, self.resource_revision);
        push_u32(&mut encoded, self.key_version);
        push_optional_u32(&mut encoded, self.member_key_generation);
        encode_binding(&mut encoded, &self.binding);
        Ok(encoded)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EncodedSuitePayload(Vec<u8>);

impl EncodedSuitePayload {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() < XCHACHA_NONCE_BYTES + POLY1305_TAG_BYTES
            || bytes.len() > MAX_SUITE_PAYLOAD_BYTES
        {
            return Err(CryptoError::InvalidLength);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for EncodedSuitePayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncodedSuitePayload")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

pub struct CryptoSuiteRegistry;

impl CryptoSuiteRegistry {
    pub fn validate_envelope(
        descriptor: &EnvelopeDescriptor,
        payload: &EncodedSuitePayload,
    ) -> Result<(), CryptoError> {
        match descriptor.crypto_suite_id.as_str() {
            VAULT_XCHACHA_V1 => validate_xchacha_payload(payload.as_bytes()),
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }

    pub fn validate_wrapper(suite_id: &str, payload: &[u8]) -> Result<(), CryptoError> {
        match suite_id {
            X25519_WRAPPER_V1 if payload.len() == SEALED_WRAPPED_KEY_BYTES => Ok(()),
            X25519_WRAPPER_V1 => Err(CryptoError::InvalidLength),
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }
}

fn validate_wrapper_context(context: &WrapperContext) -> Result<(), CryptoError> {
    let suite = context.wrapper_suite_id.as_bytes();
    if context.protocol_version != PROTOCOL_VERSION
        || suite != X25519_WRAPPER_V1.as_bytes()
        || context.resource_revision == 0
        || context.wrapped_key_version == 0
        || context.recipient_key_version == 0
        || context.recipient_fingerprint == [0; 32]
        || context.scope.organization_id == [0; 16]
        || context.scope.vault_id == [0; 16]
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    let vault_scope = SCOPE_ORGANIZATION | SCOPE_VAULT;
    let entry_agent_scope = vault_scope | SCOPE_ENTRY | SCOPE_GRANT_OR_REQUEST | SCOPE_AGENT;
    let actual_scope = scope_bitmap(&context.scope);
    let valid = match context.purpose {
        WrapperPurpose::MemberVaultKey => {
            actual_scope == vault_scope | SCOPE_MEMBER
                && context.recipient_key_kind == RecipientKeyKind::MemberX25519
                && context.parent_descriptor_hash.is_none()
        }
        WrapperPurpose::AgentVdk => {
            actual_scope == vault_scope | SCOPE_AGENT
                && context.recipient_key_kind == RecipientKeyKind::AgentX25519
                && context.parent_descriptor_hash.is_none()
        }
        WrapperPurpose::ReasonDek => {
            actual_scope == entry_agent_scope
                && context.recipient_key_kind == RecipientKeyKind::VaultMessageX25519
                && context.parent_descriptor_hash.is_some()
        }
        WrapperPurpose::GrantDek => {
            actual_scope == entry_agent_scope
                && context.recipient_key_kind == RecipientKeyKind::AgentX25519
                && context.parent_descriptor_hash.is_some()
        }
    };
    if !valid {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(())
}

fn wrapper_context_hash(context: &WrapperContext) -> Result<[u8; 32], CryptoError> {
    let context_bytes = context.canonical_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(WRAPPER_HASH_DOMAIN);
    hasher.update(context_bytes);
    Ok(hasher.finalize().into())
}

fn verify_recipient(
    recipient_public_key: &[u8; 32],
    context: &WrapperContext,
) -> Result<(), CryptoError> {
    let fingerprint = compute_key_fingerprint(recipient_public_key, context.recipient_key_kind);
    if fingerprint
        .ct_eq(&context.recipient_fingerprint)
        .unwrap_u8()
        != 1
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(())
}

pub fn compute_key_fingerprint(public_key: &[u8; 32], key_kind: RecipientKeyKind) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update((key_kind as u16).to_be_bytes());
    hasher.update(public_key);
    hasher.finalize().into()
}

pub struct XChaChaVaultSuite;

impl XChaChaVaultSuite {
    pub fn derive_key(
        root_key: &[u8],
        descriptor: &EnvelopeDescriptor,
    ) -> Result<SecretBox<[u8; KEY_BYTES]>, CryptoError> {
        if root_key.len() != KEY_BYTES {
            return Err(CryptoError::InvalidLength);
        }
        validate_descriptor(descriptor)?;
        let context = encode_kdf_context(descriptor)?;
        let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
        Hkdf::<Sha256>::new(None, root_key)
            .expand(&context, output.as_mut())
            .map_err(|_| CryptoError::InvalidLength)?;
        Ok(SecretBox::new(Box::new(*output)))
    }

    pub fn seal(
        key: &SecretBox<[u8; KEY_BYTES]>,
        plaintext: &[u8],
        canonical_aad: &[u8],
    ) -> Result<EncodedSuitePayload, CryptoError> {
        let mut nonce = [0_u8; XCHACHA_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::RandomGenerationFailed)?;
        Self::seal_with_nonce(key, plaintext, canonical_aad, nonce)
    }

    pub fn open(
        key: &SecretBox<[u8; KEY_BYTES]>,
        payload: &EncodedSuitePayload,
        canonical_aad: &[u8],
    ) -> Result<SecretSlice<u8>, CryptoError> {
        CryptoSuiteRegistry::validate_envelope_payload(VAULT_XCHACHA_V1, payload)?;
        let (nonce, ciphertext) = payload.as_bytes().split_at(XCHACHA_NONCE_BYTES);
        let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: canonical_aad,
                },
            )
            .map(SecretSlice::from)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn seal_with_nonce(
        key: &SecretBox<[u8; KEY_BYTES]>,
        plaintext: &[u8],
        canonical_aad: &[u8],
        nonce: [u8; XCHACHA_NONCE_BYTES],
    ) -> Result<EncodedSuitePayload, CryptoError> {
        if plaintext.len() > MAX_SUITE_PAYLOAD_BYTES - XCHACHA_NONCE_BYTES - POLY1305_TAG_BYTES {
            return Err(CryptoError::InvalidLength);
        }
        let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: canonical_aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let mut encoded = Vec::with_capacity(XCHACHA_NONCE_BYTES + ciphertext.len());
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        EncodedSuitePayload::from_bytes(encoded)
    }
}

fn encode_kdf_context(descriptor: &EnvelopeDescriptor) -> Result<Vec<u8>, CryptoError> {
    let bitmap = scope_bitmap(&descriptor.scope);
    let mut encoded = Vec::with_capacity(128);
    encoded.extend_from_slice(KDF_MAGIC);
    push_u16(&mut encoded, descriptor.protocol_version);
    push_ascii(&mut encoded, &descriptor.crypto_suite_id)?;
    push_u16(&mut encoded, descriptor.purpose as u16);
    push_u16(&mut encoded, bitmap);
    push_scope_id(
        &mut encoded,
        bitmap,
        SCOPE_ORGANIZATION,
        descriptor.scope.organization_id,
    );
    push_scope_id(&mut encoded, bitmap, SCOPE_VAULT, descriptor.scope.vault_id);
    push_optional_scope_id(&mut encoded, bitmap, SCOPE_ENTRY, descriptor.scope.entry_id);
    push_optional_scope_id(
        &mut encoded,
        bitmap,
        SCOPE_GRANT_OR_REQUEST,
        descriptor.scope.grant_or_request_id,
    );
    push_optional_scope_id(&mut encoded, bitmap, SCOPE_AGENT, descriptor.scope.agent_id);
    push_optional_scope_id(
        &mut encoded,
        bitmap,
        SCOPE_MEMBER,
        descriptor.scope.member_id,
    );
    push_u32(&mut encoded, descriptor.key_version);
    push_optional_u32(&mut encoded, descriptor.member_key_generation);
    Ok(encoded)
}

impl CryptoSuiteRegistry {
    fn validate_envelope_payload(
        suite_id: &str,
        payload: &EncodedSuitePayload,
    ) -> Result<(), CryptoError> {
        match suite_id {
            VAULT_XCHACHA_V1 => validate_xchacha_payload(payload.as_bytes()),
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }
}

fn validate_xchacha_payload(payload: &[u8]) -> Result<(), CryptoError> {
    if payload.len() < XCHACHA_NONCE_BYTES + POLY1305_TAG_BYTES
        || payload.len() > MAX_SUITE_PAYLOAD_BYTES
    {
        return Err(CryptoError::InvalidLength);
    }
    Ok(())
}

fn validate_descriptor(descriptor: &EnvelopeDescriptor) -> Result<(), CryptoError> {
    let suite = descriptor.crypto_suite_id.as_bytes();
    if descriptor.protocol_version != PROTOCOL_VERSION
        || descriptor.resource_revision == 0
        || descriptor.key_version == 0
        || descriptor.member_key_generation == Some(0)
        || suite.is_empty()
        || suite.len() > MAX_SUITE_ID_BYTES
        || !suite.is_ascii()
        || suite != VAULT_XCHACHA_V1.as_bytes()
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    if descriptor.scope.organization_id == [0; 16] || descriptor.scope.vault_id == [0; 16] {
        return Err(CryptoError::InvalidDescriptor);
    }
    let entry_scope = SCOPE_ORGANIZATION | SCOPE_VAULT | SCOPE_ENTRY;
    let actual_scope = scope_bitmap(&descriptor.scope);
    let valid = match (&descriptor.purpose, &descriptor.binding) {
        (
            EnvelopePurpose::MemberVaultMetadata | EnvelopePurpose::VaultDiscoveryKey,
            EnvelopeBinding::None,
        ) => actual_scope == SCOPE_ORGANIZATION | SCOPE_VAULT,
        (
            EnvelopePurpose::VaultAgentMessagePrivateKey
            | EnvelopePurpose::VaultManifestSigningPrivateKey,
            EnvelopeBinding::VaultKey { .. },
        ) => actual_scope == SCOPE_ORGANIZATION | SCOPE_VAULT,
        (EnvelopePurpose::MemberIndex | EnvelopePurpose::AgentDiscovery, EnvelopeBinding::None) => {
            actual_scope == entry_scope
        }
        (EnvelopePurpose::MemberSecret, EnvelopeBinding::MemberSecret { .. })
        | (EnvelopePurpose::EntryDekByVaultKey, EnvelopeBinding::VaultKey { .. }) => {
            actual_scope == entry_scope
        }
        (EnvelopePurpose::EncryptedReason, EnvelopeBinding::Reason { .. })
        | (EnvelopePurpose::GrantPayload, EnvelopeBinding::Grant { .. }) => {
            actual_scope == entry_scope | SCOPE_GRANT_OR_REQUEST | SCOPE_AGENT
        }
        _ => false,
    };
    if !valid {
        return Err(CryptoError::InvalidDescriptor);
    }
    match &descriptor.binding {
        EnvelopeBinding::MemberSecret { operation } if *operation == 0 => {
            return Err(CryptoError::InvalidDescriptor);
        }
        EnvelopeBinding::VaultKey {
            wrapping_vault_key_version,
        } if *wrapping_vault_key_version == 0 => return Err(CryptoError::InvalidDescriptor),
        EnvelopeBinding::Reason {
            wrapper_suite_id,
            agent_message_key_version,
            recipient_vault_message_key_fingerprint,
            ..
        } if wrapper_suite_id != X25519_WRAPPER_V1
            || *agent_message_key_version == 0
            || *recipient_vault_message_key_fingerprint == [0; 32] =>
        {
            return Err(CryptoError::InvalidDescriptor);
        }
        EnvelopeBinding::Grant {
            wrapper_suite_id,
            recipient_agent_key_version,
            recipient_agent_key_fingerprint,
            ..
        } if wrapper_suite_id != X25519_WRAPPER_V1
            || *recipient_agent_key_version == 0
            || *recipient_agent_key_fingerprint == [0; 32] =>
        {
            return Err(CryptoError::InvalidDescriptor);
        }
        _ => {}
    }
    if let EnvelopeBinding::Grant {
        expires_at: Some(instant),
        ..
    } = descriptor.binding
        && instant.nanosecond >= 1_000_000_000
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(())
}

fn scope_bitmap(scope: &EnvelopeScope) -> u16 {
    SCOPE_ORGANIZATION
        | SCOPE_VAULT
        | scope.entry_id.map_or(0, |_| SCOPE_ENTRY)
        | scope
            .grant_or_request_id
            .map_or(0, |_| SCOPE_GRANT_OR_REQUEST)
        | scope.agent_id.map_or(0, |_| SCOPE_AGENT)
        | scope.member_id.map_or(0, |_| SCOPE_MEMBER)
}

fn push_scope_id(output: &mut Vec<u8>, bitmap: u16, bit: u16, id: [u8; 16]) {
    if bitmap & bit != 0 {
        output.extend_from_slice(&id);
    }
}

fn push_optional_scope_id(output: &mut Vec<u8>, bitmap: u16, bit: u16, id: Option<[u8; 16]>) {
    if bitmap & bit != 0 {
        output.extend_from_slice(&id.expect("scope bitmap and value are derived together"));
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_optional_u32(output: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            output.push(1);
            push_u32(output, value);
        }
        None => output.push(0),
    }
}

fn encode_binding(output: &mut Vec<u8>, binding: &EnvelopeBinding) {
    match binding {
        EnvelopeBinding::None => {}
        EnvelopeBinding::MemberSecret { operation } => push_u16(output, *operation),
        EnvelopeBinding::VaultKey {
            wrapping_vault_key_version,
        } => push_u32(output, *wrapping_vault_key_version),
        EnvelopeBinding::Reason {
            wrapper_suite_id,
            agent_message_key_version,
            recipient_vault_message_key_fingerprint,
            requested_methods,
        } => {
            push_ascii(output, wrapper_suite_id).expect("validated wrapper suite identifier");
            push_u32(output, *agent_message_key_version);
            output.extend_from_slice(recipient_vault_message_key_fingerprint);
            push_u16(output, *requested_methods);
        }
        EnvelopeBinding::Grant {
            entry_revision,
            wrapper_suite_id,
            recipient_agent_key_version,
            recipient_agent_key_fingerprint,
            approved_methods,
            field_set_commitment,
            expires_at,
            remaining_uses,
        } => {
            push_u64(output, *entry_revision);
            push_ascii(output, wrapper_suite_id).expect("validated wrapper suite identifier");
            push_u32(output, *recipient_agent_key_version);
            output.extend_from_slice(recipient_agent_key_fingerprint);
            push_u16(output, *approved_methods);
            output.extend_from_slice(field_set_commitment);
            match expires_at {
                Some(instant) => {
                    output.push(1);
                    output.extend_from_slice(&instant.unix_seconds.to_be_bytes());
                    push_u32(output, instant.nanosecond);
                }
                None => output.push(0),
            }
            push_optional_u32(output, *remaining_uses);
        }
    }
}

fn push_ascii(output: &mut Vec<u8>, value: &str) -> Result<(), CryptoError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.is_ascii() {
        return Err(CryptoError::InvalidDescriptor);
    }
    push_u16(
        output,
        u16::try_from(bytes.len()).map_err(|_| CryptoError::InvalidLength)?,
    );
    output.extend_from_slice(bytes);
    Ok(())
}

pub fn compute_field_set_commitment<'a>(
    field_ids: impl IntoIterator<Item = &'a str>,
) -> Result<[u8; 32], CryptoError> {
    let mut canonical: Vec<&str> = field_ids.into_iter().collect();
    if canonical.is_empty() || canonical.iter().any(|value| !is_canonical_field_id(value)) {
        return Err(CryptoError::InvalidDescriptor);
    }
    canonical.sort_unstable();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CryptoError::InvalidDescriptor);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PLDNV2FS");
    push_u32(
        &mut bytes,
        u32::try_from(canonical.len()).map_err(|_| CryptoError::InvalidLength)?,
    );
    for field_id in canonical {
        push_ascii(&mut bytes, field_id)?;
    }
    Ok(Sha256::digest(bytes).into())
}

fn is_canonical_field_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn secrets_equal(left: &[u8], right: &[u8]) -> bool {
        left.len() == right.len() && bool::from(left.ct_eq(right))
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        input_key_material_hex: String,
        nonce_hex: String,
        plaintext_hex: String,
        expected: VectorExpected,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VectorExpected {
        descriptor_aad_hex: String,
        kdf_context_hex: String,
        derived_key_hex: String,
        encoded_suite_payload_hex: String,
    }

    fn descriptor(suite: &str) -> EnvelopeDescriptor {
        EnvelopeDescriptor {
            protocol_version: 2,
            crypto_suite_id: suite.to_owned(),
            purpose: EnvelopePurpose::GrantPayload,
            scope: EnvelopeScope {
                organization_id: hex::decode("00112233445566778899aabbccddeeff")
                    .expect("UUID")
                    .try_into()
                    .expect("UUID length"),
                vault_id: hex::decode("11112222333344448555666677778888")
                    .expect("UUID")
                    .try_into()
                    .expect("UUID length"),
                entry_id: Some(
                    hex::decode("aaaaaaaabbbb4ccc8dddeeeeeeeeeeee")
                        .expect("UUID")
                        .try_into()
                        .expect("UUID length"),
                ),
                grant_or_request_id: Some(
                    hex::decode("123456781234423482341234567890ab")
                        .expect("UUID")
                        .try_into()
                        .expect("UUID length"),
                ),
                agent_id: Some(
                    hex::decode("fedcba98765443218765abcdefabcdef")
                        .expect("UUID")
                        .try_into()
                        .expect("UUID length"),
                ),
                member_id: None,
            },
            resource_revision: 7,
            key_version: 3,
            member_key_generation: Some(9),
            binding: EnvelopeBinding::Grant {
                entry_revision: 6,
                wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                recipient_agent_key_version: 4,
                recipient_agent_key_fingerprint: [0x5a; 32],
                approved_methods: 3,
                field_set_commitment: [0xa5; 32],
                expires_at: Some(InstantBinding {
                    unix_seconds: 1_700_000_000,
                    nanosecond: 123_456_789,
                }),
                remaining_uses: Some(5),
            },
        }
    }

    #[test]
    fn registry_rejects_unknown_suites_without_fallback() {
        let payload = EncodedSuitePayload::from_bytes(vec![0; 40]).expect("bounded payload");
        assert_eq!(
            CryptoSuiteRegistry::validate_envelope(&descriptor("unknown"), &payload),
            Err(CryptoError::UnsupportedSuite)
        );
    }

    #[test]
    fn suite_payload_debug_never_contains_payload_bytes() {
        let payload = EncodedSuitePayload::from_bytes(
            [vec![0; 24], b"confidential-canary".to_vec(), vec![0; 16]].concat(),
        )
        .expect("bounded payload");
        let debug = format!("{payload:?}");
        assert!(!debug.contains("confidential-canary"));
    }

    #[test]
    fn xchacha_authenticates_canonical_aad() {
        let key = SecretBox::new(Box::new([7; KEY_BYTES]));
        let payload = XChaChaVaultSuite::seal_with_nonce(
            &key,
            b"synthetic-secret",
            b"canonical-aad",
            [9; XCHACHA_NONCE_BYTES],
        )
        .expect("seal");

        let opened = XChaChaVaultSuite::open(&key, &payload, b"canonical-aad").expect("open");
        assert!(secrets_equal(opened.expose_secret(), b"synthetic-secret"));
        assert_eq!(
            XChaChaVaultSuite::open(&key, &payload, b"changed-aad").expect_err("AAD tamper"),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn hkdf_is_deterministic_and_context_separated() {
        let first_descriptor = descriptor(VAULT_XCHACHA_V1);
        let first = XChaChaVaultSuite::derive_key(&[3; 32], &first_descriptor).expect("derive");
        let again = XChaChaVaultSuite::derive_key(&[3; 32], &first_descriptor).expect("derive");
        let mut separated_descriptor = first_descriptor;
        separated_descriptor.key_version += 1;
        let separated =
            XChaChaVaultSuite::derive_key(&[3; 32], &separated_descriptor).expect("derive");
        assert!(secrets_equal(first.expose_secret(), again.expose_secret()));
        assert!(!secrets_equal(
            first.expose_secret(),
            separated.expose_secret()
        ));

        let mut next_revision = descriptor(VAULT_XCHACHA_V1);
        next_revision.resource_revision += 1;
        let same_version = XChaChaVaultSuite::derive_key(&[3; 32], &next_revision).expect("derive");
        assert!(secrets_equal(
            first.expose_secret(),
            same_version.expose_secret()
        ));
    }

    #[test]
    fn field_set_commitment_matches_cross_client_vector_and_rejects_duplicates() {
        assert_eq!(
            hex::encode(
                compute_field_set_commitment(["password", "username"]).expect("commitment")
            ),
            "f4efe1b64791880d2f2bcd96905ae75bb39a8c5212a9b77831e9376699372708"
        );
        assert_eq!(
            compute_field_set_commitment(["username", "username"]),
            Err(CryptoError::InvalidDescriptor)
        );
    }

    #[test]
    fn sealed_box_wrapper_binds_recipient_and_parent_descriptor() {
        let recipient = X25519Identity::from_private_bytes(vec![0x44; 32]).expect("identity");
        let descriptor = descriptor(VAULT_XCHACHA_V1);
        let parent_hash: [u8; 32] =
            Sha256::digest(descriptor.canonical_aad().expect("parent descriptor")).into();
        let context = WrapperContext {
            protocol_version: 2,
            wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
            purpose: WrapperPurpose::GrantDek,
            scope: descriptor.scope.clone(),
            resource_revision: 7,
            wrapped_key_version: 3,
            member_key_generation: Some(9),
            recipient_key_kind: RecipientKeyKind::AgentX25519,
            recipient_key_version: 4,
            recipient_fingerprint: compute_key_fingerprint(
                recipient.public_key(),
                RecipientKeyKind::AgentX25519,
            ),
            parent_descriptor_hash: Some(parent_hash),
        };
        let key = SecretBox::new(Box::new([0x77; 32]));
        let wrapped =
            X25519SealedBoxSuite::wrap(&key, *recipient.public_key(), &context).expect("wrap");
        assert_eq!(wrapped.as_bytes().len(), 120);
        let opened = X25519SealedBoxSuite::unwrap(&wrapped, &recipient, &context).expect("unwrap");
        assert!(secrets_equal(opened.expose_secret(), key.expose_secret()));

        let mut changed = context;
        changed.parent_descriptor_hash = Some([0x99; 32]);
        assert_eq!(
            X25519SealedBoxSuite::unwrap(&wrapped, &recipient, &changed)
                .expect_err("changed parent must fail"),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn opens_frozen_libsodium_sealed_box_vector() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/v2/x25519-sealed-box.json"))
                .expect("wrapper fixture");
        let private = hex::decode(
            fixture["recipientPrivateKeyHex"]
                .as_str()
                .expect("private key"),
        )
        .expect("private key hex");
        let recipient = X25519Identity::from_private_bytes(private).expect("identity");
        assert_eq!(
            hex::encode(recipient.public_key()),
            fixture["recipientPublicKeyHex"]
                .as_str()
                .expect("public key")
        );
        let descriptor = descriptor(VAULT_XCHACHA_V1);
        let context = WrapperContext {
            protocol_version: 2,
            wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
            purpose: WrapperPurpose::GrantDek,
            scope: descriptor.scope,
            resource_revision: 7,
            wrapped_key_version: 3,
            member_key_generation: Some(9),
            recipient_key_kind: RecipientKeyKind::AgentX25519,
            recipient_key_version: 4,
            recipient_fingerprint: compute_key_fingerprint(
                recipient.public_key(),
                RecipientKeyKind::AgentX25519,
            ),
            parent_descriptor_hash: Some(
                hex::decode(
                    fixture["context"]["parentDescriptorHashHex"]
                        .as_str()
                        .expect("parent hash"),
                )
                .expect("parent hash hex")
                .try_into()
                .expect("parent hash length"),
            ),
        };
        assert_eq!(
            hex::encode(context.canonical_bytes().expect("context")),
            fixture["expectedContextHex"].as_str().expect("context hex")
        );
        let package = SealedWrappedKey::from_bytes(
            hex::decode(fixture["sealedPackageHex"].as_str().expect("package"))
                .expect("package hex"),
        )
        .expect("package");
        let opened = X25519SealedBoxSuite::unwrap(&package, &recipient, &context).expect("unwrap");
        let expected_wrapped_key =
            hex::decode(fixture["wrappedKeyHex"].as_str().expect("wrapped key"))
                .expect("wrapped key hex");
        assert!(secrets_equal(opened.expose_secret(), &expected_wrapped_key));
    }

    #[test]
    fn shared_v2_vector_is_byte_exact() {
        let vector: Vector = serde_json::from_str(include_str!(
            "../../../contracts/v2/envelope-xchacha-hkdf.json"
        ))
        .expect("vector JSON");
        let descriptor = descriptor(VAULT_XCHACHA_V1);
        let aad = descriptor.canonical_aad().expect("AAD");
        let kdf_context = encode_kdf_context(&descriptor).expect("KDF context");
        let ikm = hex::decode(vector.input_key_material_hex).expect("IKM");
        let key = XChaChaVaultSuite::derive_key(&ikm, &descriptor).expect("derive");
        let nonce: [u8; XCHACHA_NONCE_BYTES] = hex::decode(vector.nonce_hex)
            .expect("nonce")
            .try_into()
            .expect("nonce length");
        let plaintext = hex::decode(vector.plaintext_hex).expect("plaintext");
        let payload =
            XChaChaVaultSuite::seal_with_nonce(&key, &plaintext, &aad, nonce).expect("seal vector");

        assert_eq!(hex::encode(aad), vector.expected.descriptor_aad_hex);
        assert_eq!(hex::encode(kdf_context), vector.expected.kdf_context_hex);
        let expected_derived_key =
            hex::decode(vector.expected.derived_key_hex).expect("expected derived key hex");
        assert!(secrets_equal(key.expose_secret(), &expected_derived_key));
        assert_eq!(
            hex::encode(payload.as_bytes()),
            vector.expected.encoded_suite_payload_hex
        );
    }
}
