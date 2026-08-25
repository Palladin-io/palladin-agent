use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CryptoError, EncodedSuitePayload, EnvelopeBinding, EnvelopeDescriptor, EnvelopePurpose,
    EnvelopeScope, InstantBinding, RecipientKeyKind, SealedWrappedKey, VAULT_XCHACHA_V1,
    WrapperContext, WrapperPurpose, X25519_WRAPPER_V1, X25519Identity, X25519SealedBoxSuite,
    XChaChaVaultSuite, compute_field_set_commitment,
};

const GRANT_PAYLOAD_PURPOSE: u16 = 10;
const MEMBER_SECRET_PURPOSE: u16 = 6;
const ENTRY_DEK_BY_VAULT_KEY_PURPOSE: u16 = 8;

#[derive(Deserialize)]
#[serde(untagged)]
enum ProtocolCodeWire {
    Numeric(u16),
    Named(String),
}

fn deserialize_protocol_code<'de, D>(
    deserializer: D,
    expected_name: &str,
    expected_code: u16,
) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    match ProtocolCodeWire::deserialize(deserializer)? {
        ProtocolCodeWire::Numeric(value) => Ok(value),
        ProtocolCodeWire::Named(value) if value == expected_name => Ok(expected_code),
        ProtocolCodeWire::Named(_) => Err(de::Error::custom("unsupported protocol enum value")),
    }
}

fn deserialize_grant_payload_purpose<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protocol_code(deserializer, "grantPayload", GRANT_PAYLOAD_PURPOSE)
}

fn deserialize_grant_dek_purpose<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protocol_code(deserializer, "grantDek", WrapperPurpose::GrantDek as u16)
}

fn deserialize_agent_vault_key_purpose<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protocol_code(
        deserializer,
        "agentVaultKey",
        WrapperPurpose::AgentVaultKey as u16,
    )
}

fn deserialize_entry_dek_purpose<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protocol_code(
        deserializer,
        "entryDekByVaultKey",
        ENTRY_DEK_BY_VAULT_KEY_PURPOSE,
    )
}

fn deserialize_member_secret_purpose<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protocol_code(deserializer, "memberSecret", MEMBER_SECRET_PURPOSE)
}

fn deserialize_entry_operation<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let operation = match ProtocolCodeWire::deserialize(deserializer)? {
        ProtocolCodeWire::Numeric(value) => value,
        ProtocolCodeWire::Named(value) => match value.as_str() {
            "created" => 1,
            "updated" => 2,
            "archived" => 3,
            "restored" => 4,
            "deleted" => 5,
            _ => return Err(de::Error::custom("unsupported entry operation")),
        },
    };

    (1..=5)
        .contains(&operation)
        .then_some(operation)
        .ok_or_else(|| de::Error::custom("unsupported entry operation"))
}

fn deserialize_agent_recipient_kind<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protocol_code(
        deserializer,
        "agentX25519",
        RecipientKeyKind::AgentX25519 as u16,
    )
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedCredential {
    pub descriptor: GrantEnvelopeDescriptor,
    pub encoded_suite_payload: String,
    pub wrapped_grant_dek: WrappedGrantDek,
    pub field_ids: Vec<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentWrappedVaultKey {
    pub wrapped_vault_key: AgentVaultKeyWrapper,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentVaultKeyWrapper {
    pub descriptor: AgentVaultKeyWrapperDescriptor,
    pub encoded_sealed_key_package: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentVaultKeyWrapperDescriptor {
    pub protocol_version: u16,
    pub wrapper_suite_id: String,
    #[serde(deserialize_with = "deserialize_agent_vault_key_purpose")]
    pub purpose: u16,
    pub scope: GrantEnvelopeScope,
    pub resource_revision: String,
    pub wrapped_key_version: u32,
    pub member_key_generation: Option<u32>,
    #[serde(deserialize_with = "deserialize_agent_recipient_kind")]
    pub recipient_key_kind: u16,
    pub recipient_key_version: u32,
    pub recipient_fingerprint: String,
    pub parent_descriptor_hash: Option<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultEntryKeyEnvelope {
    pub descriptor: VaultEntryKeyDescriptor,
    pub encoded_suite_payload: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultEntryKeyDescriptor {
    pub protocol_version: u16,
    pub crypto_suite_id: String,
    #[serde(deserialize_with = "deserialize_entry_dek_purpose")]
    pub purpose: u16,
    pub scope: GrantEnvelopeScope,
    pub resource_revision: String,
    pub key_version: u32,
    pub member_key_generation: Option<u32>,
    pub binding: VaultKeyBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultKeyBinding {
    pub wrapping_vault_key_version: u32,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberSecretEnvelope {
    pub descriptor: MemberSecretDescriptor,
    pub encoded_suite_payload: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberSecretDescriptor {
    pub protocol_version: u16,
    pub crypto_suite_id: String,
    #[serde(deserialize_with = "deserialize_member_secret_purpose")]
    pub purpose: u16,
    pub scope: GrantEnvelopeScope,
    pub resource_revision: String,
    pub key_version: u32,
    pub member_key_generation: Option<u32>,
    pub binding: MemberSecretBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberSecretBinding {
    #[serde(deserialize_with = "deserialize_entry_operation")]
    pub operation: u16,
}

impl std::fmt::Debug for AgentWrappedVaultKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AgentWrappedVaultKey([REDACTED])")
    }
}

impl std::fmt::Debug for AgentVaultKeyWrapper {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AgentVaultKeyWrapper([REDACTED])")
    }
}

impl std::fmt::Debug for VaultEntryKeyEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VaultEntryKeyEnvelope([REDACTED])")
    }
}

impl std::fmt::Debug for MemberSecretEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MemberSecretEnvelope([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WrappedGrantDek {
    pub descriptor: WrappedGrantDekDescriptor,
    pub encoded_sealed_key_package: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WrappedGrantDekDescriptor {
    pub protocol_version: u16,
    pub wrapper_suite_id: String,
    #[serde(deserialize_with = "deserialize_grant_dek_purpose")]
    pub purpose: u16,
    pub scope: GrantEnvelopeScope,
    pub resource_revision: String,
    pub wrapped_key_version: u32,
    pub member_key_generation: Option<u32>,
    #[serde(deserialize_with = "deserialize_agent_recipient_kind")]
    pub recipient_key_kind: u16,
    pub recipient_key_version: u32,
    pub recipient_fingerprint: String,
    pub parent_descriptor_hash: Option<String>,
}

impl WrappedGrantDek {
    pub fn from_context(context: &WrapperContext, wrapped: &SealedWrappedKey) -> Self {
        Self {
            descriptor: WrappedGrantDekDescriptor {
                protocol_version: context.protocol_version,
                wrapper_suite_id: context.wrapper_suite_id.clone(),
                purpose: context.purpose as u16,
                scope: GrantEnvelopeScope {
                    organization_id: format_uuid(context.scope.organization_id),
                    vault_id: format_uuid(context.scope.vault_id),
                    entry_id: context.scope.entry_id.map(format_uuid),
                    grant_or_request_id: context.scope.grant_or_request_id.map(format_uuid),
                    agent_id: context.scope.agent_id.map(format_uuid),
                    member_id: context.scope.member_id.map(format_uuid),
                },
                resource_revision: context.resource_revision.to_string(),
                wrapped_key_version: context.wrapped_key_version,
                member_key_generation: context.member_key_generation,
                recipient_key_kind: context.recipient_key_kind as u16,
                recipient_key_version: context.recipient_key_version,
                recipient_fingerprint: URL_SAFE_NO_PAD.encode(context.recipient_fingerprint),
                parent_descriptor_hash: context
                    .parent_descriptor_hash
                    .map(|hash| URL_SAFE_NO_PAD.encode(hash)),
            },
            encoded_sealed_key_package: URL_SAFE_NO_PAD.encode(wrapped.as_bytes()),
        }
    }
}

impl std::fmt::Debug for EncryptedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EncryptedCredential([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantEnvelopeDescriptor {
    pub protocol_version: u16,
    pub crypto_suite_id: String,
    #[serde(deserialize_with = "deserialize_grant_payload_purpose")]
    pub purpose: u16,
    pub scope: GrantEnvelopeScope,
    pub resource_revision: String,
    pub key_version: u32,
    pub member_key_generation: Option<u32>,
    pub binding: GrantEnvelopeBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantEnvelopeScope {
    pub organization_id: String,
    pub vault_id: String,
    pub entry_id: Option<String>,
    pub grant_or_request_id: Option<String>,
    pub agent_id: Option<String>,
    pub member_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantEnvelopeBinding {
    pub entry_revision: String,
    pub wrapper_suite_id: String,
    pub recipient_key_version: u32,
    pub recipient_key_fingerprint: String,
    pub approved_methods: u16,
    pub delivery_policy: u16,
    pub field_set_commitment: String,
    pub expires_at: Option<String>,
    pub remaining_uses: Option<u32>,
}

pub struct CredentialEnvelopeContext<'a> {
    pub organization_id: &'a str,
    pub vault_id: &'a str,
    pub grant_id: &'a str,
    pub agent_id: &'a str,
    pub entry_id: &'a str,
    pub approved_methods: u16,
    pub requested_vault_id: &'a str,
    pub requested_entry_id: &'a str,
    pub requested_method: u16,
}

pub struct FullCredentialEnvelopeContext<'a> {
    pub organization_id: &'a str,
    pub vault_id: &'a str,
    pub grant_id: &'a str,
    pub agent_id: &'a str,
    pub agent_access_epoch: u32,
    pub trusted_agent_access_epoch: u32,
    pub entry_id: &'a str,
    pub approved_methods: u16,
    pub delivery_policy: u16,
    pub expires_at: Option<&'a str>,
    pub requested_vault_id: &'a str,
    pub requested_entry_id: &'a str,
    pub requested_method: u16,
}

pub struct DecryptedCredential {
    plaintext: SecretSlice<u8>,
    grant_expires_at: Option<InstantBinding>,
}

impl DecryptedCredential {
    #[must_use]
    pub fn expose_for_authorized_operation(&self) -> &[u8] {
        self.plaintext.expose_secret()
    }

    /// Remaining authenticated grant lifetime at the point of use. A lifetime grant returns
    /// `None`; an expired bounded grant always fails closed even if it decrypted earlier.
    pub fn remaining_validity_at(
        &self,
        now: OffsetDateTime,
    ) -> Result<Option<std::time::Duration>, CryptoError> {
        let Some(expires_at) = self.grant_expires_at else {
            return Ok(None);
        };
        let expires_at = OffsetDateTime::from_unix_timestamp(expires_at.unix_seconds)
            .and_then(|value| value.replace_nanosecond(expires_at.nanosecond))
            .map_err(|_| CryptoError::InvalidDescriptor)?;
        if expires_at <= now {
            return Err(CryptoError::StaleInput);
        }
        std::time::Duration::try_from(expires_at - now)
            .map(Some)
            .map_err(|_| CryptoError::StaleInput)
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
    outer: &CredentialEnvelopeContext<'_>,
) -> Result<DecryptedCredential, CryptoError> {
    decrypt_credential_at(envelope, identity, outer, OffsetDateTime::now_utc())
}

pub fn decrypt_full_credential(
    wrapped_vault_key: &AgentWrappedVaultKey,
    entry_key: &VaultEntryKeyEnvelope,
    member_secret: &MemberSecretEnvelope,
    identity: &X25519Identity,
    outer: &FullCredentialEnvelopeContext<'_>,
) -> Result<DecryptedCredential, CryptoError> {
    decrypt_full_credential_at(
        wrapped_vault_key,
        entry_key,
        member_secret,
        identity,
        outer,
        OffsetDateTime::now_utc(),
    )
}

pub fn decrypt_full_credential_at(
    wrapped_vault_key: &AgentWrappedVaultKey,
    entry_key: &VaultEntryKeyEnvelope,
    member_secret: &MemberSecretEnvelope,
    identity: &X25519Identity,
    outer: &FullCredentialEnvelopeContext<'_>,
    now: OffsetDateTime,
) -> Result<DecryptedCredential, CryptoError> {
    validate_full_delivery_policy(outer)?;
    let grant_expires_at = outer.expires_at.map(parse_instant).transpose()?;
    if grant_expires_at.is_some_and(|expires_at| {
        (expires_at.unix_seconds, expires_at.nanosecond) <= (now.unix_timestamp(), now.nanosecond())
    }) {
        return Err(CryptoError::StaleInput);
    }

    let organization_id = parse_uuid(outer.organization_id)?;
    let vault_id = parse_uuid(outer.vault_id)?;
    let grant_id = parse_uuid(outer.grant_id)?;
    let agent_id = parse_uuid(outer.agent_id)?;
    let entry_id = parse_uuid(outer.entry_id)?;
    if vault_id != parse_uuid(outer.requested_vault_id)?
        || entry_id != parse_uuid(outer.requested_entry_id)?
        || outer.agent_access_epoch == 0
        || outer.agent_access_epoch != outer.trusted_agent_access_epoch
    {
        return Err(CryptoError::InvalidDescriptor);
    }

    let wrapper = &wrapped_vault_key.wrapped_vault_key;
    let wire_wrapper = &wrapper.descriptor;
    let wrapper_scope = parse_scope(&wire_wrapper.scope)?;
    let expected_wrapper_scope = EnvelopeScope {
        organization_id,
        vault_id,
        entry_id: None,
        grant_or_request_id: Some(grant_id),
        agent_id: Some(agent_id),
        member_id: None,
    };
    let recipient_fingerprint = decode_fixed::<32>(&wire_wrapper.recipient_fingerprint)?;
    if wire_wrapper.protocol_version != 2
        || wire_wrapper.wrapper_suite_id != X25519_WRAPPER_V1
        || wire_wrapper.purpose != WrapperPurpose::AgentVaultKey as u16
        || wrapper_scope != expected_wrapper_scope
        || parse_nonzero_u64(&wire_wrapper.resource_revision)?
            != u64::from(outer.agent_access_epoch)
        || wire_wrapper.wrapped_key_version == 0
        || wire_wrapper.member_key_generation.is_some()
        || wire_wrapper.recipient_key_kind != RecipientKeyKind::AgentX25519 as u16
        || wire_wrapper.recipient_key_version == 0
        || recipient_fingerprint
            != crate::compute_key_fingerprint(identity.public_key(), RecipientKeyKind::AgentX25519)
        || wire_wrapper.parent_descriptor_hash.is_some()
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    let wrapper_context = WrapperContext {
        protocol_version: wire_wrapper.protocol_version,
        wrapper_suite_id: wire_wrapper.wrapper_suite_id.clone(),
        purpose: WrapperPurpose::AgentVaultKey,
        scope: expected_wrapper_scope,
        resource_revision: u64::from(outer.agent_access_epoch),
        wrapped_key_version: wire_wrapper.wrapped_key_version,
        member_key_generation: None,
        recipient_key_kind: RecipientKeyKind::AgentX25519,
        recipient_key_version: wire_wrapper.recipient_key_version,
        recipient_fingerprint,
        parent_descriptor_hash: None,
    };
    let sealed_vault_key =
        SealedWrappedKey::from_bytes(decode_base64url(&wrapper.encoded_sealed_key_package)?)?;
    let vault_key = X25519SealedBoxSuite::unwrap(&sealed_vault_key, identity, &wrapper_context)?;

    let entry_descriptor =
        vault_entry_key_descriptor(entry_key, organization_id, vault_id, entry_id)?;
    let EnvelopeBinding::VaultKey {
        wrapping_vault_key_version,
    } = &entry_descriptor.binding
    else {
        return Err(CryptoError::InvalidDescriptor);
    };
    if *wrapping_vault_key_version != wire_wrapper.wrapped_key_version {
        return Err(CryptoError::StaleInput);
    }
    let entry_aad = entry_descriptor.canonical_aad()?;
    let entry_payload =
        EncodedSuitePayload::from_bytes(decode_base64url(&entry_key.encoded_suite_payload)?)?;
    let entry_wrapper_key =
        XChaChaVaultSuite::derive_key(vault_key.expose_secret(), &entry_descriptor)?;
    let entry_dek = XChaChaVaultSuite::open(&entry_wrapper_key, &entry_payload, &entry_aad)?;
    if entry_dek.expose_secret().len() != 32 {
        return Err(CryptoError::InvalidLength);
    }

    let secret_descriptor =
        member_secret_descriptor(member_secret, organization_id, vault_id, entry_id)?;
    if secret_descriptor.key_version != entry_descriptor.key_version
        || secret_descriptor.member_key_generation != entry_descriptor.member_key_generation
    {
        return Err(CryptoError::StaleInput);
    }
    let secret_aad = secret_descriptor.canonical_aad()?;
    let secret_payload =
        EncodedSuitePayload::from_bytes(decode_base64url(&member_secret.encoded_suite_payload)?)?;
    let secret_key = XChaChaVaultSuite::derive_key(entry_dek.expose_secret(), &secret_descriptor)?;
    let plaintext = XChaChaVaultSuite::open(&secret_key, &secret_payload, &secret_aad)?;
    let normalized = normalize_full_member_secret(
        plaintext.expose_secret(),
        outer.requested_method,
        outer.delivery_policy,
    )?;
    Ok(DecryptedCredential {
        plaintext: normalized.plaintext.into(),
        grant_expires_at,
    })
}

fn validate_full_delivery_policy(
    outer: &FullCredentialEnvelopeContext<'_>,
) -> Result<(), CryptoError> {
    if !matches!(outer.requested_method, 1 | 2 | 4)
        || outer.approved_methods == 0
        || outer.approved_methods & !0b111 != 0
        || outer.approved_methods & outer.requested_method != outer.requested_method
        || outer.delivery_policy > 2
        || (outer.delivery_policy == 1 && outer.requested_method != 2)
        || (outer.delivery_policy == 2 && outer.requested_method != 4)
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(())
}

fn vault_entry_key_descriptor(
    envelope: &VaultEntryKeyEnvelope,
    organization_id: [u8; 16],
    vault_id: [u8; 16],
    entry_id: [u8; 16],
) -> Result<EnvelopeDescriptor, CryptoError> {
    let wire = &envelope.descriptor;
    let scope = parse_scope(&wire.scope)?;
    if wire.protocol_version != 2
        || wire.crypto_suite_id != VAULT_XCHACHA_V1
        || wire.purpose != ENTRY_DEK_BY_VAULT_KEY_PURPOSE
        || scope.organization_id != organization_id
        || scope.vault_id != vault_id
        || scope.entry_id != Some(entry_id)
        || scope.grant_or_request_id.is_some()
        || scope.agent_id.is_some()
        || scope.member_id.is_some()
        || wire.member_key_generation.is_none()
        || wire.binding.wrapping_vault_key_version == 0
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(EnvelopeDescriptor {
        protocol_version: wire.protocol_version,
        crypto_suite_id: wire.crypto_suite_id.clone(),
        purpose: EnvelopePurpose::EntryDekByVaultKey,
        scope,
        resource_revision: parse_nonzero_u64(&wire.resource_revision)?,
        key_version: wire.key_version,
        member_key_generation: wire.member_key_generation,
        binding: EnvelopeBinding::VaultKey {
            wrapping_vault_key_version: wire.binding.wrapping_vault_key_version,
        },
    })
}

fn member_secret_descriptor(
    envelope: &MemberSecretEnvelope,
    organization_id: [u8; 16],
    vault_id: [u8; 16],
    entry_id: [u8; 16],
) -> Result<EnvelopeDescriptor, CryptoError> {
    let wire = &envelope.descriptor;
    let scope = parse_scope(&wire.scope)?;
    if wire.protocol_version != 2
        || wire.crypto_suite_id != VAULT_XCHACHA_V1
        || wire.purpose != MEMBER_SECRET_PURPOSE
        || scope.organization_id != organization_id
        || scope.vault_id != vault_id
        || scope.entry_id != Some(entry_id)
        || scope.grant_or_request_id.is_some()
        || scope.agent_id.is_some()
        || scope.member_id.is_some()
        || wire.member_key_generation.is_none()
        || !matches!(wire.binding.operation, 1..=5)
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(EnvelopeDescriptor {
        protocol_version: wire.protocol_version,
        crypto_suite_id: wire.crypto_suite_id.clone(),
        purpose: EnvelopePurpose::MemberSecret,
        scope,
        resource_revision: parse_nonzero_u64(&wire.resource_revision)?,
        key_version: wire.key_version,
        member_key_generation: wire.member_key_generation,
        binding: EnvelopeBinding::MemberSecret {
            operation: wire.binding.operation,
        },
    })
}

pub fn decrypt_credential_at(
    envelope: &EncryptedCredential,
    identity: &X25519Identity,
    outer: &CredentialEnvelopeContext<'_>,
    now: OffsetDateTime,
) -> Result<DecryptedCredential, CryptoError> {
    let descriptor = to_descriptor(envelope, outer, now)?;
    let aad = descriptor.canonical_aad()?;
    let parent_descriptor_hash: [u8; 32] = Sha256::digest(&aad).into();
    let fingerprint = decode_fixed::<32>(&envelope.descriptor.binding.recipient_key_fingerprint)?;
    let wrapped_descriptor = &envelope.wrapped_grant_dek.descriptor;
    let wrapper_scope = parse_scope(&wrapped_descriptor.scope)?;
    let wrapper_fingerprint = decode_fixed::<32>(&wrapped_descriptor.recipient_fingerprint)?;
    let wrapper_parent_hash = wrapped_descriptor
        .parent_descriptor_hash
        .as_deref()
        .map(decode_fixed::<32>)
        .transpose()?;
    if wrapped_descriptor.protocol_version != descriptor.protocol_version
        || wrapped_descriptor.wrapper_suite_id != X25519_WRAPPER_V1
        || wrapped_descriptor.purpose != WrapperPurpose::GrantDek as u16
        || wrapper_scope != descriptor.scope
        || parse_nonzero_u64(&wrapped_descriptor.resource_revision)? != descriptor.resource_revision
        || wrapped_descriptor.wrapped_key_version != descriptor.key_version
        || wrapped_descriptor.member_key_generation != descriptor.member_key_generation
        || wrapped_descriptor.recipient_key_kind != RecipientKeyKind::AgentX25519 as u16
        || wrapped_descriptor.recipient_key_version
            != envelope.descriptor.binding.recipient_key_version
        || wrapper_fingerprint != fingerprint
        || wrapper_parent_hash != Some(parent_descriptor_hash)
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    let wrapped = SealedWrappedKey::from_bytes(decode_base64url(
        &envelope.wrapped_grant_dek.encoded_sealed_key_package,
    )?)?;
    let wrapper_context = WrapperContext {
        protocol_version: descriptor.protocol_version,
        wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
        purpose: WrapperPurpose::GrantDek,
        scope: descriptor.scope.clone(),
        resource_revision: descriptor.resource_revision,
        wrapped_key_version: descriptor.key_version,
        member_key_generation: descriptor.member_key_generation,
        recipient_key_kind: RecipientKeyKind::AgentX25519,
        recipient_key_version: envelope.descriptor.binding.recipient_key_version,
        recipient_fingerprint: fingerprint,
        parent_descriptor_hash: Some(parent_descriptor_hash),
    };
    let grant_dek = X25519SealedBoxSuite::unwrap(&wrapped, identity, &wrapper_context)?;
    let payload =
        EncodedSuitePayload::from_bytes(decode_base64url(&envelope.encoded_suite_payload)?)?;
    let payload_key = XChaChaVaultSuite::derive_key(grant_dek.expose_secret(), &descriptor)?;
    let plaintext = XChaChaVaultSuite::open(&payload_key, &payload, &aad)?;
    let normalized = normalize_grant_payload(
        plaintext.expose_secret(),
        &envelope.field_ids,
        outer.requested_method,
    )
    .map_err(|error| match error {
        CryptoError::InvalidEncoding => CryptoError::InvalidGrantPayloadEncoding,
        error => error,
    })?;
    let grant_expires_at = match &descriptor.binding {
        EnvelopeBinding::Grant { expires_at, .. } => *expires_at,
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    Ok(DecryptedCredential {
        plaintext: normalized.plaintext.into(),
        grant_expires_at,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantPayload {
    schema: String,
    entry_type: String,
    fields: Vec<GrantField>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantField {
    id: String,
    kind: String,
    mode: String,
    value: Value,
}

impl Drop for GrantPayload {
    fn drop(&mut self) {
        self.schema.zeroize();
        self.entry_type.zeroize();
    }
}

impl Drop for GrantField {
    fn drop(&mut self) {
        self.id.zeroize();
        self.kind.zeroize();
        self.mode.zeroize();
        zeroize_json(&mut self.value);
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TotpValue {
    secret: String,
    algorithm: String,
    digits: u8,
    period: u16,
    issuer: Option<String>,
    account: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScriptReference {
    env: String,
    vault_id: String,
    entry_id: String,
    field_id: String,
}

impl Drop for TotpValue {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.algorithm.zeroize();
        self.issuer.zeroize();
        self.account.zeroize();
    }
}

impl Drop for ScriptReference {
    fn drop(&mut self) {
        self.env.zeroize();
        self.vault_id.zeroize();
        self.entry_id.zeroize();
        self.field_id.zeroize();
    }
}

struct NormalizedGrant {
    plaintext: Vec<u8>,
}

fn normalize_full_member_secret(
    plaintext: &[u8],
    requested_method: u16,
    delivery_policy: u16,
) -> Result<NormalizedGrant, CryptoError> {
    let text = std::str::from_utf8(plaintext).map_err(|_| CryptoError::InvalidEncoding)?;
    let secret =
        SensitiveJson(serde_json::from_str(text).map_err(|_| CryptoError::InvalidEncoding)?);
    let mut canonical =
        serde_json::to_string(&secret.0).map_err(|_| CryptoError::InvalidEncoding)?;
    let is_canonical = canonical == text;
    canonical.zeroize();
    if !is_canonical {
        return Err(CryptoError::InvalidEncoding);
    }
    let projected = canonical_member_secret_projection(&secret.0)?;
    normalize_projected_member_secret(&projected, requested_method, delivery_policy)
}

fn canonical_member_secret_projection(value: &Value) -> Result<SensitiveJson, CryptoError> {
    let object = value.as_object().ok_or(CryptoError::InvalidEncoding)?;
    require_allowed_keys(
        object,
        &[
            "agentVisibilityPolicy",
            "content",
            "entryType",
            "memberLabel",
        ],
        &[
            "agentLabel",
            "agentVisibilityPolicy",
            "content",
            "description",
            "entryType",
            "memberLabel",
        ],
    )?;
    let entry_type_code = object
        .get("entryType")
        .and_then(Value::as_u64)
        .ok_or(CryptoError::InvalidEncoding)?;
    let entry_type = match entry_type_code {
        0 => "key",
        1 => "credential",
        2 => "script",
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    if object.get("memberLabel").and_then(Value::as_str).is_none()
        || !is_optional_string_or_absent(object.get("agentLabel"))
        || !is_optional_string_or_absent(object.get("description"))
    {
        return Err(CryptoError::InvalidEncoding);
    }

    let content = object
        .get("content")
        .and_then(Value::as_object)
        .ok_or(CryptoError::InvalidEncoding)?;
    let (required_content, allowed_content): (&[&str], &[&str]) = match entry_type {
        "key" => (
            &["fields", "v", "value"],
            &["fields", "notes", "url", "v", "value"],
        ),
        "credential" => (
            &["fields", "password", "username", "v"],
            &[
                "fields", "notes", "password", "totp", "url", "username", "v",
            ],
        ),
        "script" => (
            &["fields", "interpreter", "refs", "script", "v"],
            &["fields", "interpreter", "notes", "refs", "script", "v"],
        ),
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    require_allowed_keys(content, required_content, allowed_content)?;
    if content.get("v").and_then(Value::as_u64) != Some(2) {
        return Err(CryptoError::InvalidDescriptor);
    }

    let custom_fields = content
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(CryptoError::InvalidEncoding)?;
    let mut legacy_custom_fields = Vec::with_capacity(custom_fields.len());
    let mut custom_policy_ids = Vec::with_capacity(custom_fields.len());
    for field in custom_fields {
        let field = field.as_object().ok_or(CryptoError::InvalidEncoding)?;
        require_exact_keys(field, &["id", "label", "type", "value"])?;
        let id = field
            .get("id")
            .and_then(Value::as_str)
            .ok_or(CryptoError::InvalidEncoding)?;
        let parsed_id = uuid::Uuid::parse_str(id).map_err(|_| CryptoError::InvalidDescriptor)?;
        if parsed_id.to_string() != id || custom_policy_ids.iter().any(|existing| existing == id) {
            return Err(CryptoError::InvalidDescriptor);
        }
        let field_type = field
            .get("type")
            .and_then(Value::as_str)
            .ok_or(CryptoError::InvalidEncoding)?;
        if !matches!(
            field_type,
            "text" | "multiline" | "concealed" | "totp" | "unknown"
        ) || field.get("label").and_then(Value::as_str).is_none()
        {
            return Err(CryptoError::InvalidDescriptor);
        }
        let policy_id = format!("custom:{id}");
        custom_policy_ids.push(policy_id.clone());
        legacy_custom_fields.push(serde_json::json!({
            "id": policy_id,
            "label": field["label"].clone(),
            "type": field_type,
            "value": field["value"].clone(),
        }));
    }

    let policy = object
        .get("agentVisibilityPolicy")
        .and_then(Value::as_object)
        .ok_or(CryptoError::InvalidEncoding)?;
    require_exact_keys(policy, &["discoveryEnabled", "fields", "schemaVersion"])?;
    if policy.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CryptoError::InvalidDescriptor);
    }
    let discovery_enabled = policy
        .get("discoveryEnabled")
        .and_then(Value::as_bool)
        .ok_or(CryptoError::InvalidEncoding)?;
    if discovery_enabled
        && object
            .get("agentLabel")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    let fields = policy
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(CryptoError::InvalidEncoding)?;
    let expected_builtins: &[&str] = match entry_type {
        "key" => &[
            "common.agent-label",
            "common.capabilities",
            "common.description",
            "common.entry-type",
            "common.icon-reference",
            "common.member-label",
            "common.search-fields",
            "key.notes",
            "key.url",
            "key.value",
        ],
        "credential" => &[
            "common.agent-label",
            "common.capabilities",
            "common.description",
            "common.entry-type",
            "common.icon-reference",
            "common.member-label",
            "common.search-fields",
            "credential.notes",
            "credential.password",
            "credential.totp",
            "credential.url",
            "credential.url-domain",
            "credential.username",
        ],
        "script" => &[
            "common.agent-label",
            "common.capabilities",
            "common.description",
            "common.entry-type",
            "common.icon-reference",
            "common.member-label",
            "common.search-fields",
            "script.interpreter",
            "script.notes",
            "script.refs",
            "script.source",
        ],
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    let mut canonical_access = Map::new();
    let mut previous_id: Option<String> = None;
    for field in fields {
        let field = field.as_object().ok_or(CryptoError::InvalidEncoding)?;
        require_exact_keys(field, &["access", "fieldId"])?;
        let field_id = field
            .get("fieldId")
            .and_then(Value::as_str)
            .ok_or(CryptoError::InvalidEncoding)?;
        if previous_id
            .as_deref()
            .is_some_and(|previous| previous >= field_id)
            || canonical_access.contains_key(field_id)
        {
            return Err(CryptoError::InvalidDescriptor);
        }
        let access = field
            .get("access")
            .and_then(Value::as_u64)
            .filter(|access| *access <= 4)
            .ok_or(CryptoError::InvalidDescriptor)?;
        let is_builtin = expected_builtins.contains(&field_id);
        let is_known_custom = custom_policy_ids.iter().any(|id| id == field_id);
        if !is_builtin && !is_known_custom {
            return Err(CryptoError::InvalidDescriptor);
        }
        canonical_access.insert(field_id.to_owned(), Value::from(access));
        previous_id = Some(field_id.to_owned());
    }
    if expected_builtins
        .iter()
        .any(|field_id| !canonical_access.contains_key(*field_id))
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    for custom_id in &custom_policy_ids {
        canonical_access
            .entry(custom_id.clone())
            .or_insert_with(|| Value::from(0));
    }
    for (field_id, expected) in [
        ("common.member-label", 0),
        ("common.agent-label", 1),
        ("common.entry-type", 1),
        ("common.capabilities", 1),
        ("common.icon-reference", 0),
        ("common.search-fields", 0),
    ] {
        if canonical_access.get(field_id).and_then(Value::as_u64) != Some(expected) {
            return Err(CryptoError::InvalidDescriptor);
        }
    }
    if !matches!(
        canonical_access
            .get("common.description")
            .and_then(Value::as_u64),
        Some(0 | 1)
    ) {
        return Err(CryptoError::InvalidDescriptor);
    }

    let mut legacy_access = Map::new();
    for (field_id, access) in &canonical_access {
        let mut access = access.as_u64().ok_or(CryptoError::InvalidDescriptor)?;
        let legacy_id = match field_id.as_str() {
            "common.member-label" => Some("memberLabel"),
            "common.agent-label" => Some("agentLabel"),
            "common.description" => Some("description"),
            "common.entry-type" => Some("entryType"),
            "common.icon-reference" => Some("icon"),
            "common.capabilities" | "common.search-fields" => None,
            "credential.url-domain" => Some("credential.urlDomain"),
            "key.notes" | "credential.notes" | "script.notes" => Some("notes"),
            "key.url" => Some("key.url"),
            other => Some(other),
        };
        let Some(legacy_id) = legacy_id else { continue };
        if !discovery_enabled && matches!(legacy_id, "agentLabel" | "entryType") {
            access = 0;
        }
        let mode = match access {
            0 => "never",
            1 => "discovery",
            2 => "onGrantValue",
            3 => "onGrantDerived",
            4 => "onGrantRuntime",
            _ => return Err(CryptoError::InvalidDescriptor),
        };
        legacy_access.insert(legacy_id.to_owned(), Value::String(mode.to_owned()));
    }
    legacy_access.insert("color".to_owned(), Value::String("never".to_owned()));

    let optional = |name: &str| content.get(name).cloned().unwrap_or(Value::Null);
    let mut legacy_content = Map::new();
    legacy_content.insert(
        "customFields".to_owned(),
        Value::Array(legacy_custom_fields),
    );
    match entry_type {
        "key" => {
            legacy_content.insert("value".to_owned(), content["value"].clone());
            legacy_content.insert("url".to_owned(), optional("url"));
            legacy_content.insert("notes".to_owned(), optional("notes"));
        }
        "credential" => {
            legacy_content.insert("username".to_owned(), content["username"].clone());
            legacy_content.insert("password".to_owned(), content["password"].clone());
            legacy_content.insert("url".to_owned(), optional("url"));
            legacy_content.insert("urlDomain".to_owned(), Value::Null);
            legacy_content.insert("totp".to_owned(), optional("totp"));
            legacy_content.insert("notes".to_owned(), optional("notes"));
        }
        "script" => {
            legacy_content.insert("source".to_owned(), content["script"].clone());
            legacy_content.insert("interpreter".to_owned(), content["interpreter"].clone());
            legacy_content.insert("refs".to_owned(), content["refs"].clone());
            legacy_content.insert("notes".to_owned(), optional("notes"));
        }
        _ => return Err(CryptoError::InvalidDescriptor),
    }

    let mut projected = Map::new();
    projected.insert(
        "schema".to_owned(),
        Value::String("palladin.member-secret.v1".to_owned()),
    );
    projected.insert("memberLabel".to_owned(), object["memberLabel"].clone());
    projected.insert(
        "agentLabel".to_owned(),
        if discovery_enabled {
            object.get("agentLabel").cloned().unwrap_or(Value::Null)
        } else {
            Value::Null
        },
    );
    projected.insert("discoverable".to_owned(), Value::Bool(discovery_enabled));
    projected.insert(
        "description".to_owned(),
        object.get("description").cloned().unwrap_or(Value::Null),
    );
    projected.insert("icon".to_owned(), Value::Null);
    projected.insert("color".to_owned(), Value::Null);
    projected.insert("agentFieldAccess".to_owned(), Value::Object(legacy_access));
    projected.insert("entryType".to_owned(), Value::String(entry_type.to_owned()));
    projected.insert("content".to_owned(), Value::Object(legacy_content));
    Ok(SensitiveJson(Value::Object(projected)))
}

fn normalize_projected_member_secret(
    projected: &SensitiveJson,
    requested_method: u16,
    _delivery_policy: u16,
) -> Result<NormalizedGrant, CryptoError> {
    let object = projected
        .0
        .as_object()
        .ok_or(CryptoError::InvalidEncoding)?;
    require_exact_keys(
        object,
        &[
            "agentFieldAccess",
            "agentLabel",
            "color",
            "content",
            "description",
            "discoverable",
            "entryType",
            "icon",
            "memberLabel",
            "schema",
        ],
    )?;
    if object.get("schema").and_then(Value::as_str) != Some("palladin.member-secret.v1")
        || object.get("memberLabel").and_then(Value::as_str).is_none()
        || !is_optional_string(object.get("agentLabel"))
        || !is_optional_string(object.get("description"))
        || !is_optional_string(object.get("color"))
    {
        return Err(CryptoError::InvalidEncoding);
    }
    let discoverable = object
        .get("discoverable")
        .and_then(Value::as_bool)
        .ok_or(CryptoError::InvalidEncoding)?;
    let entry_type = object
        .get("entryType")
        .and_then(Value::as_str)
        .ok_or(CryptoError::InvalidEncoding)?;
    if !matches!(entry_type, "key" | "credential" | "script" | "creditCard") {
        return Err(CryptoError::InvalidDescriptor);
    }
    let content = object
        .get("content")
        .and_then(Value::as_object)
        .ok_or(CryptoError::InvalidEncoding)?;
    validate_member_content(entry_type, content)?;
    let custom_fields = content
        .get("customFields")
        .and_then(Value::as_array)
        .ok_or(CryptoError::InvalidEncoding)?;
    let custom_ids = validate_custom_fields(custom_fields)?;
    let access = object
        .get("agentFieldAccess")
        .and_then(Value::as_object)
        .ok_or(CryptoError::InvalidEncoding)?;
    validate_agent_field_access(
        entry_type,
        access,
        custom_fields,
        &custom_ids,
        discoverable,
        object.get("agentLabel"),
    )?;

    let mut field_ids: Vec<&str> = access
        .iter()
        .filter_map(|(field_id, mode)| match mode.as_str() {
            Some("onGrantValue" | "onGrantDerived" | "onGrantRuntime") => Some(field_id.as_str()),
            _ => None,
        })
        .collect();
    field_ids.sort_unstable();
    if field_ids.is_empty() {
        return Err(CryptoError::InvalidDescriptor);
    }
    let fields = field_ids
        .into_iter()
        .map(|field_id| {
            let mode = match access.get(field_id).and_then(Value::as_str) {
                Some("onGrantValue") => "value",
                Some("onGrantDerived") => "derived",
                Some("onGrantRuntime") => "runtime",
                _ => return Err(CryptoError::InvalidDescriptor),
            };
            let (kind, value) =
                member_secret_field(entry_type, object, content, custom_fields, field_id)?;
            Ok(serde_json::json!({
                "id": field_id,
                "kind": kind,
                "mode": mode,
                "value": value,
            }))
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;
    let projected = SensitiveJson(serde_json::json!({
        "schema": "palladin.grant-payload.v1",
        "entryType": entry_type,
        "fields": fields,
    }));
    let projected_bytes =
        Zeroizing::new(serde_json::to_vec(&projected.0).map_err(|_| CryptoError::InvalidEncoding)?);
    normalize_grant_payload(
        &projected_bytes,
        &projected_field_ids(&projected.0)?,
        requested_method,
    )
}

fn require_allowed_keys(
    object: &Map<String, Value>,
    required: &[&str],
    allowed: &[&str],
) -> Result<(), CryptoError> {
    if required.iter().any(|key| !object.contains_key(*key))
        || object.keys().any(|key| !allowed.contains(&key.as_str()))
    {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(())
}

fn is_optional_string_or_absent(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null | Value::String(_)))
}

fn require_exact_keys(object: &Map<String, Value>, expected: &[&str]) -> Result<(), CryptoError> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(())
}

fn is_optional_string(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Null | Value::String(_)))
}

fn validate_member_content(
    entry_type: &str,
    content: &Map<String, Value>,
) -> Result<(), CryptoError> {
    let expected = match entry_type {
        "key" => &["customFields", "notes", "url", "value"][..],
        "credential" => &[
            "customFields",
            "notes",
            "password",
            "totp",
            "url",
            "urlDomain",
            "username",
        ][..],
        "script" => &["customFields", "interpreter", "notes", "refs", "source"][..],
        "creditCard" => &[
            "billingAddress",
            "cardNumber",
            "cardholderName",
            "customFields",
            "expiryMonth",
            "expiryYear",
            "notes",
        ][..],
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    require_exact_keys(content, expected)?;
    let required_strings: &[&str] = match entry_type {
        "key" => &["value"],
        "credential" => &["username", "password"],
        "script" => &["source", "interpreter"],
        "creditCard" => &["cardholderName", "cardNumber", "expiryMonth", "expiryYear"],
        _ => &[],
    };
    if required_strings
        .iter()
        .any(|key| content.get(*key).and_then(Value::as_str).is_none())
        || content
            .get("customFields")
            .and_then(Value::as_array)
            .is_none()
        || !is_optional_string(content.get("notes"))
        || (entry_type == "key" && !is_optional_string(content.get("url")))
        || (entry_type == "credential"
            && (!is_optional_string(content.get("url"))
                || !is_optional_string(content.get("urlDomain"))))
        || (entry_type == "script" && content.get("refs").and_then(Value::as_array).is_none())
        || (entry_type == "creditCard" && !is_optional_string(content.get("billingAddress")))
    {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(())
}

fn validate_custom_fields(fields: &[Value]) -> Result<Vec<String>, CryptoError> {
    let mut ids = Vec::with_capacity(fields.len());
    for field in fields {
        let object = field.as_object().ok_or(CryptoError::InvalidEncoding)?;
        require_exact_keys(object, &["id", "label", "type", "value"])?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or(CryptoError::InvalidEncoding)?;
        let Some(uuid) = id.strip_prefix("custom:") else {
            return Err(CryptoError::InvalidDescriptor);
        };
        parse_uuid(uuid)?;
        if object.get("label").and_then(Value::as_str).is_none()
            || object.get("type").and_then(Value::as_str).is_none()
            || ids.iter().any(|existing| existing == id)
        {
            return Err(CryptoError::InvalidEncoding);
        }
        ids.push(id.to_owned());
    }
    Ok(ids)
}

fn validate_agent_field_access(
    entry_type: &str,
    access: &Map<String, Value>,
    custom_fields: &[Value],
    custom_ids: &[String],
    discoverable: bool,
    agent_label: Option<&Value>,
) -> Result<(), CryptoError> {
    let builtins: &[&str] = match entry_type {
        "key" => &[
            "memberLabel",
            "agentLabel",
            "description",
            "icon",
            "color",
            "entryType",
            "key.value",
            "key.url",
            "notes",
        ],
        "credential" => &[
            "memberLabel",
            "agentLabel",
            "description",
            "icon",
            "color",
            "entryType",
            "credential.username",
            "credential.password",
            "credential.url",
            "credential.urlDomain",
            "credential.totp",
            "notes",
        ],
        "script" => &[
            "memberLabel",
            "agentLabel",
            "description",
            "icon",
            "color",
            "entryType",
            "script.source",
            "script.interpreter",
            "script.refs",
            "notes",
        ],
        "creditCard" => &[
            "memberLabel",
            "agentLabel",
            "description",
            "icon",
            "color",
            "entryType",
            "creditCard.cardholderName",
            "creditCard.cardNumber",
            "creditCard.expiryMonth",
            "creditCard.expiryYear",
            "creditCard.billingAddress",
            "notes",
        ],
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    if access.len() != builtins.len() + custom_ids.len()
        || builtins.iter().any(|field| !access.contains_key(*field))
        || custom_ids.iter().any(|field| !access.contains_key(field))
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    let agent_label_access = access.get("agentLabel").and_then(Value::as_str);
    let entry_type_access = access.get("entryType").and_then(Value::as_str);
    if (!discoverable
        && (!matches!(agent_label, Some(Value::Null))
            || agent_label_access != Some("never")
            || entry_type_access != Some("never")))
        || (discoverable
            && (agent_label
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
                || agent_label_access != Some("discovery")
                || entry_type_access != Some("discovery")))
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    for (field_id, value) in access {
        let mode = value.as_str().ok_or(CryptoError::InvalidEncoding)?;
        let allowed = allowed_access_modes(entry_type, custom_fields, field_id)?;
        if !allowed.contains(&mode) {
            return Err(CryptoError::InvalidDescriptor);
        }
    }
    Ok(())
}

fn allowed_access_modes(
    entry_type: &str,
    custom_fields: &[Value],
    field_id: &str,
) -> Result<&'static [&'static str], CryptoError> {
    let allowed = match field_id {
        "memberLabel" | "icon" | "color" => &["never"][..],
        "agentLabel" | "entryType" | "description" => &["never", "discovery"][..],
        "key.value" | "key.url" | "credential.password" | "credential.url" => {
            &["never", "onGrantValue"][..]
        }
        "credential.username" | "credential.urlDomain" => {
            &["never", "discovery", "onGrantValue"][..]
        }
        "credential.totp" => &["never", "onGrantDerived"][..],
        "script.source" | "script.refs" => &["never", "onGrantRuntime"][..],
        "script.interpreter" => &["never", "discovery", "onGrantRuntime"][..],
        "creditCard.cardholderName"
        | "creditCard.cardNumber"
        | "creditCard.expiryMonth"
        | "creditCard.expiryYear"
        | "creditCard.billingAddress" => &["never", "onGrantRuntime"][..],
        "notes" if matches!(entry_type, "script" | "creditCard") => {
            &["never", "onGrantRuntime"][..]
        }
        "notes" => &["never", "onGrantValue", "onGrantRuntime"][..],
        custom if custom.starts_with("custom:") => {
            let field_type = custom_fields
                .iter()
                .find_map(|field| {
                    let object = field.as_object()?;
                    (object.get("id")?.as_str()? == custom)
                        .then(|| object.get("type")?.as_str())
                        .flatten()
                })
                .ok_or(CryptoError::InvalidDescriptor)?;
            match field_type {
                "totp" => &["never", "onGrantDerived"][..],
                "text" | "multiline" | "concealed"
                    if matches!(entry_type, "script" | "creditCard") =>
                {
                    &["never", "onGrantRuntime"][..]
                }
                "text" | "multiline" | "concealed" => &["never", "discovery", "onGrantValue"][..],
                _ => &["never"][..],
            }
        }
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    Ok(allowed)
}

fn member_secret_field(
    entry_type: &str,
    root: &Map<String, Value>,
    content: &Map<String, Value>,
    custom_fields: &[Value],
    field_id: &str,
) -> Result<(&'static str, Value), CryptoError> {
    let value = match field_id {
        "notes" => content.get("notes"),
        "key.value" => content.get("value"),
        "key.url" => content.get("url"),
        "credential.username" => content.get("username"),
        "credential.password" => content.get("password"),
        "credential.url" => content.get("url"),
        "credential.urlDomain" => content.get("urlDomain"),
        "credential.totp" => content.get("totp"),
        "script.source" => content.get("source"),
        "script.interpreter" => content.get("interpreter"),
        "script.refs" => content.get("refs"),
        "creditCard.cardholderName" => content.get("cardholderName"),
        "creditCard.cardNumber" => content.get("cardNumber"),
        "creditCard.expiryMonth" => content.get("expiryMonth"),
        "creditCard.expiryYear" => content.get("expiryYear"),
        "creditCard.billingAddress" => content.get("billingAddress"),
        custom if custom.starts_with("custom:") => custom_fields.iter().find_map(|field| {
            let object = field.as_object()?;
            (object.get("id")?.as_str()? == custom)
                .then(|| object.get("value"))
                .flatten()
        }),
        "memberLabel" | "agentLabel" | "description" | "icon" | "color" | "entryType" => {
            root.get(field_id)
        }
        _ => None,
    }
    .ok_or(CryptoError::InvalidDescriptor)?
    .clone();
    let custom_kind = custom_fields.iter().find_map(|field| {
        let object = field.as_object()?;
        (object.get("id")?.as_str()? == field_id)
            .then(|| object.get("type")?.as_str())
            .flatten()
    });
    let kind = match (field_id, custom_kind) {
        (_, Some("text")) => "text",
        (_, Some("multiline")) => "multiline",
        (_, Some("concealed")) => "concealed",
        (_, Some("totp")) => "totp",
        ("key.value" | "credential.password" | "creditCard.cardNumber", None) => "concealed",
        ("key.url" | "credential.url", None) => "url",
        ("credential.totp", None) => "totp",
        ("notes", None) => "multiline",
        ("script.source", None) => "script",
        ("script.interpreter", None) => "interpreter",
        ("script.refs", None) => "refs",
        (_, None) if matches!(entry_type, "key" | "credential" | "creditCard") => "text",
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    Ok((kind, value))
}

fn projected_field_ids(projected: &Value) -> Result<Vec<String>, CryptoError> {
    projected
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(CryptoError::InvalidEncoding)?
        .iter()
        .map(|field| {
            field
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(CryptoError::InvalidEncoding)
        })
        .collect()
}

struct SensitiveJson(Value);

impl Drop for SensitiveJson {
    fn drop(&mut self) {
        zeroize_json(&mut self.0);
    }
}

struct SensitiveValues(Vec<Value>);

impl Drop for SensitiveValues {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(zeroize_json);
    }
}

fn normalize_grant_payload(
    plaintext: &[u8],
    envelope_field_ids: &[String],
    requested_method: u16,
) -> Result<NormalizedGrant, CryptoError> {
    let text = std::str::from_utf8(plaintext).map_err(|_| CryptoError::InvalidEncoding)?;
    let mut payload: GrantPayload =
        serde_json::from_str(text).map_err(|_| CryptoError::InvalidEncoding)?;
    if payload.schema != "palladin.grant-payload.v1"
        || !matches!(
            payload.entry_type.as_str(),
            "key" | "credential" | "script" | "creditCard"
        )
        || payload.fields.is_empty()
        || !matches!(requested_method, 1 | 2 | 4)
        || (payload.entry_type == "script" && requested_method != 2)
        || (payload.entry_type == "creditCard" && requested_method != 4)
        || (requested_method == 4
            && !matches!(payload.entry_type.as_str(), "credential" | "creditCard"))
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    let canonical_value =
        SensitiveJson(serde_json::from_str(text).map_err(|_| CryptoError::InvalidEncoding)?);
    let mut canonical =
        serde_json::to_string(&canonical_value.0).map_err(|_| CryptoError::InvalidEncoding)?;
    let is_canonical = canonical == text;
    canonical.zeroize();
    if !is_canonical {
        return Err(CryptoError::InvalidEncoding);
    }
    let payload_ids: Vec<&str> = payload
        .fields
        .iter()
        .map(|field| field.id.as_str())
        .collect();
    if payload_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || envelope_field_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != payload_ids
    {
        return Err(CryptoError::InvalidDescriptor);
    }

    let mut normalized = SensitiveJson(Value::Object(Map::new()));
    let normalized_object = normalized
        .0
        .as_object_mut()
        .ok_or(CryptoError::InvalidEncoding)?;
    let mut custom_fields = SensitiveValues(Vec::new());
    let mut has_encrypted_url_domain = false;
    for mut field in payload.fields.drain(..) {
        let expected = expected_field(&payload.entry_type, &field.id, &field.kind)?;
        if field.mode != expected {
            return Err(CryptoError::InvalidDescriptor);
        }
        if field.mode == "runtime"
            && !((payload.entry_type == "script" && requested_method == 2)
                || (payload.entry_type == "creditCard" && requested_method == 4))
        {
            return Err(CryptoError::InvalidDescriptor);
        }
        match field.kind.as_str() {
            "text" | "multiline" | "concealed" | "url" | "script" | "interpreter" => {
                let value = match std::mem::take(&mut field.value) {
                    Value::String(value) => value,
                    Value::Null
                        if matches!(
                            field.id.as_str(),
                            "credential.url"
                                | "credential.urlDomain"
                                | "creditCard.billingAddress"
                                | "notes"
                        ) =>
                    {
                        continue;
                    }
                    _ => return Err(CryptoError::InvalidEncoding),
                };
                let value = Zeroizing::new(value);
                if field.kind == "interpreter"
                    && !matches!(value.as_str(), "bash" | "sh" | "node" | "python")
                {
                    return Err(CryptoError::InvalidDescriptor);
                }
                if field.id == "credential.urlDomain" {
                    has_encrypted_url_domain = !value.is_empty();
                }
                insert_scalar_field(normalized_object, &mut custom_fields.0, &field, &value)?;
            }
            "totp" => {
                let raw_value = std::mem::take(&mut field.value);
                if raw_value.is_null() && field.id == "credential.totp" {
                    continue;
                }
                let value: TotpValue =
                    serde_json::from_value(raw_value).map_err(|_| CryptoError::InvalidEncoding)?;
                validate_totp(&value)?;
                let value =
                    serde_json::to_value(&value).map_err(|_| CryptoError::InvalidEncoding)?;
                custom_fields.0.push(custom_field(&field, value));
            }
            "refs" => {
                let references: Vec<ScriptReference> =
                    serde_json::from_value(std::mem::take(&mut field.value))
                        .map_err(|_| CryptoError::InvalidEncoding)?;
                let mut converted = Vec::with_capacity(references.len());
                for reference in references {
                    validate_reference(&reference)?;
                    let mut converted_reference = serde_json::json!({
                        "env": reference.env,
                        "vaultId": reference.vault_id,
                        "entryId": reference.entry_id,
                    });
                    let object = converted_reference
                        .as_object_mut()
                        .ok_or(CryptoError::InvalidEncoding)?;
                    if reference.field_id == "credential.totp" {
                        object.insert(
                            "fieldId".to_owned(),
                            Value::String(reference.field_id.clone()),
                        );
                    } else if let Some(custom_id) = reference.field_id.strip_prefix("custom:") {
                        object.insert("fieldId".to_owned(), Value::String(custom_id.to_owned()));
                    } else {
                        let alias = match reference.field_id.as_str() {
                            "key.value" => "value",
                            "credential.username" => "username",
                            "credential.password" => "password",
                            "credential.url" => "url",
                            "notes" => "notes",
                            _ => return Err(CryptoError::InvalidDescriptor),
                        };
                        object.insert("field".to_owned(), Value::String(alias.to_owned()));
                    }
                    converted.push(converted_reference);
                }
                normalized_object.insert("refs".to_owned(), Value::Array(converted));
            }
            _ => return Err(CryptoError::InvalidDescriptor),
        }
    }
    if !custom_fields.0.is_empty() {
        normalized_object.insert(
            "fields".to_owned(),
            Value::Array(std::mem::take(&mut custom_fields.0)),
        );
    }
    if payload.entry_type == "creditCard" {
        normalized_object.insert("type".to_owned(), Value::String("creditCard".to_owned()));
    }
    if requested_method == 4 && payload.entry_type == "credential" && !has_encrypted_url_domain {
        let origin_present = normalized_object
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty());
        if !origin_present {
            return Err(CryptoError::InvalidDescriptor);
        }
    }
    let plaintext = serde_json::to_vec(&normalized.0).map_err(|_| CryptoError::InvalidEncoding)?;
    Ok(NormalizedGrant { plaintext })
}

fn expected_field(entry_type: &str, id: &str, kind: &str) -> Result<&'static str, CryptoError> {
    let mapping = match (entry_type, id) {
        ("key", "key.value") => ("concealed", "value"),
        ("key", "key.url") => ("url", "value"),
        ("credential", "credential.username") => ("text", "value"),
        ("credential", "credential.password") => ("concealed", "value"),
        ("credential", "credential.url") => ("url", "value"),
        ("credential", "credential.urlDomain") => ("text", "value"),
        ("credential", "credential.totp") => ("totp", "derived"),
        ("credential" | "key", "notes") => ("multiline", "value"),
        ("script", "script.source") => ("script", "runtime"),
        ("script", "script.interpreter") => ("interpreter", "runtime"),
        ("script", "script.refs") => ("refs", "runtime"),
        ("creditCard", "creditCard.cardholderName") => ("text", "runtime"),
        ("creditCard", "creditCard.cardNumber") => ("concealed", "runtime"),
        ("creditCard", "creditCard.expiryMonth") => ("text", "runtime"),
        ("creditCard", "creditCard.expiryYear") => ("text", "runtime"),
        ("creditCard", "creditCard.billingAddress") => ("text", "runtime"),
        ("script" | "creditCard", "notes") => ("multiline", "runtime"),
        (_, custom) if is_custom_field_id(custom) => {
            return match kind {
                "text" | "multiline" | "concealed"
                    if matches!(entry_type, "script" | "creditCard") =>
                {
                    Ok("runtime")
                }
                "text" | "multiline" | "concealed" => Ok("value"),
                "totp" => Ok("derived"),
                _ => Err(CryptoError::InvalidDescriptor),
            };
        }
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    if mapping.0 != kind {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(mapping.1)
}

fn insert_scalar_field(
    normalized: &mut Map<String, Value>,
    custom_fields: &mut Vec<Value>,
    field: &GrantField,
    value: &str,
) -> Result<(), CryptoError> {
    let target = match field.id.as_str() {
        "key.value" => "value",
        "key.url" => "url",
        "credential.username" => "username",
        "credential.password" => "password",
        "credential.url" => "url",
        "credential.urlDomain" => "urlDomain",
        "notes" => "notes",
        "script.source" => "script",
        "script.interpreter" => "interpreter",
        "creditCard.cardholderName" => "cardholderName",
        "creditCard.cardNumber" => "cardNumber",
        "creditCard.expiryMonth" => "expiryMonth",
        "creditCard.expiryYear" => "expiryYear",
        "creditCard.billingAddress" => "billingAddress",
        custom if is_custom_field_id(custom) => {
            custom_fields.push(custom_field(field, Value::String(value.to_owned())));
            return Ok(());
        }
        _ => return Err(CryptoError::InvalidDescriptor),
    };
    normalized.insert(target.to_owned(), Value::String(value.to_owned()));
    Ok(())
}

fn custom_field(field: &GrantField, value: Value) -> Value {
    serde_json::json!({
        "id": field.id.strip_prefix("custom:").unwrap_or(&field.id),
        "label": field.id,
        "type": field.kind,
        "value": value,
        "agentVisible": true,
    })
}

fn validate_totp(value: &TotpValue) -> Result<(), CryptoError> {
    if !matches!(value.algorithm.as_str(), "SHA1" | "SHA256" | "SHA512")
        || !matches!(value.digits, 6 | 8)
        || !(15..=120).contains(&value.period)
        || value.secret.is_empty()
        || value.secret.ends_with('=')
        || !value
            .secret
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || matches!(byte, b'2'..=b'7'))
        || !is_canonical_base32(&value.secret)
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(())
}

fn is_canonical_base32(value: &str) -> bool {
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    let mut output_bytes = 0_usize;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'2'..=b'7' => u32::from(byte - b'2' + 26),
            _ => return false,
        };
        accumulator = (accumulator << 5) | digit;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            output_bytes += 1;
            accumulator &= (1_u32 << bits).wrapping_sub(1);
        }
    }
    output_bytes > 0 && (bits == 0 || accumulator == 0)
}

fn validate_reference(reference: &ScriptReference) -> Result<(), CryptoError> {
    if reference.env.is_empty()
        || reference.env.len() > 128
        || !reference.env.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_uppercase() || (index > 0 && byte.is_ascii_digit())
        })
        || parse_uuid(&reference.vault_id).is_err()
        || parse_uuid(&reference.entry_id).is_err()
        || !is_field_id(&reference.field_id)
    {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(())
}

fn is_custom_field_id(value: &str) -> bool {
    value
        .strip_prefix("custom:")
        .is_some_and(|uuid| parse_uuid(uuid).is_ok())
}

fn is_field_id(value: &str) -> bool {
    matches!(
        value,
        "key.value"
            | "key.url"
            | "credential.username"
            | "credential.password"
            | "credential.url"
            | "credential.urlDomain"
            | "credential.totp"
            | "notes"
            | "script.source"
            | "script.interpreter"
            | "script.refs"
            | "creditCard.cardholderName"
            | "creditCard.cardNumber"
            | "creditCard.expiryMonth"
            | "creditCard.expiryYear"
            | "creditCard.billingAddress"
    ) || is_custom_field_id(value)
}

fn to_descriptor(
    envelope: &EncryptedCredential,
    outer: &CredentialEnvelopeContext<'_>,
    now: OffsetDateTime,
) -> Result<EnvelopeDescriptor, CryptoError> {
    let wire = &envelope.descriptor;
    let binding = &wire.binding;
    if wire.protocol_version != 2
        || wire.crypto_suite_id != VAULT_XCHACHA_V1
        || wire.purpose != GRANT_PAYLOAD_PURPOSE
        || binding.wrapper_suite_id != X25519_WRAPPER_V1
        || binding.approved_methods != outer.approved_methods
        || outer.requested_method == 0
        || binding.approved_methods & outer.requested_method != outer.requested_method
        || binding.approved_methods & !0b111 != 0
        || binding.delivery_policy > 2
        || (binding.delivery_policy == 1 && outer.requested_method != 2)
        || (binding.delivery_policy == 2 && outer.requested_method != 4)
        || wire.member_key_generation.is_none()
        || envelope.field_ids.is_empty()
    {
        return Err(CryptoError::InvalidDescriptor);
    }

    let organization_id = parse_uuid(&wire.scope.organization_id)?;
    let vault_id = parse_uuid(&wire.scope.vault_id)?;
    let entry_id = parse_required_uuid(wire.scope.entry_id.as_deref())?;
    let grant_id = parse_required_uuid(wire.scope.grant_or_request_id.as_deref())?;
    let agent_id = parse_required_uuid(wire.scope.agent_id.as_deref())?;
    if wire.scope.member_id.is_some()
        || organization_id != parse_uuid(outer.organization_id)?
        || vault_id != parse_uuid(outer.vault_id)?
        || entry_id != parse_uuid(outer.entry_id)?
        || vault_id != parse_uuid(outer.requested_vault_id)?
        || entry_id != parse_uuid(outer.requested_entry_id)?
        || grant_id != parse_uuid(outer.grant_id)?
        || agent_id != parse_uuid(outer.agent_id)?
    {
        return Err(CryptoError::InvalidDescriptor);
    }

    let field_ids: Vec<&str> = envelope.field_ids.iter().map(String::as_str).collect();
    let expected_commitment = compute_field_set_commitment(field_ids)?;
    if expected_commitment != decode_fixed::<32>(&binding.field_set_commitment)? {
        return Err(CryptoError::AuthenticationFailed);
    }
    let expires_at = binding
        .expires_at
        .as_deref()
        .map(parse_instant)
        .transpose()?;
    if binding.remaining_uses == Some(0) {
        return Err(CryptoError::InvalidDescriptor);
    }
    if expires_at.is_some_and(|expires_at| {
        (expires_at.unix_seconds, expires_at.nanosecond) <= (now.unix_timestamp(), now.nanosecond())
    }) {
        return Err(CryptoError::InvalidDescriptor);
    }
    let resource_revision = parse_nonzero_u64(&wire.resource_revision)?;
    let entry_revision = parse_nonzero_u64(&binding.entry_revision)?;
    let fingerprint = decode_fixed::<32>(&binding.recipient_key_fingerprint)?;
    if binding.recipient_key_version == 0 || fingerprint == [0; 32] {
        return Err(CryptoError::InvalidDescriptor);
    }

    Ok(EnvelopeDescriptor {
        protocol_version: wire.protocol_version,
        crypto_suite_id: wire.crypto_suite_id.clone(),
        purpose: EnvelopePurpose::GrantPayload,
        scope: EnvelopeScope {
            organization_id,
            vault_id,
            entry_id: Some(entry_id),
            grant_or_request_id: Some(grant_id),
            agent_id: Some(agent_id),
            member_id: None,
        },
        resource_revision,
        key_version: wire.key_version,
        member_key_generation: wire.member_key_generation,
        binding: EnvelopeBinding::Grant {
            entry_revision,
            wrapper_suite_id: binding.wrapper_suite_id.clone(),
            recipient_agent_key_version: binding.recipient_key_version,
            recipient_agent_key_fingerprint: fingerprint,
            approved_methods: binding.approved_methods,
            delivery_policy: binding.delivery_policy,
            field_set_commitment: expected_commitment,
            expires_at,
            remaining_uses: binding.remaining_uses,
        },
    })
}

fn parse_instant(value: &str) -> Result<InstantBinding, CryptoError> {
    let instant =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| CryptoError::InvalidEncoding)?;
    Ok(InstantBinding {
        unix_seconds: instant.unix_timestamp(),
        nanosecond: instant.nanosecond(),
    })
}

fn parse_nonzero_u64(value: &str) -> Result<u64, CryptoError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| CryptoError::InvalidEncoding)?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(CryptoError::InvalidDescriptor);
    }
    Ok(parsed)
}

fn parse_required_uuid(value: Option<&str>) -> Result<[u8; 16], CryptoError> {
    parse_uuid(value.ok_or(CryptoError::InvalidDescriptor)?)
}

fn parse_scope(scope: &GrantEnvelopeScope) -> Result<EnvelopeScope, CryptoError> {
    Ok(EnvelopeScope {
        organization_id: parse_uuid(&scope.organization_id)?,
        vault_id: parse_uuid(&scope.vault_id)?,
        entry_id: scope.entry_id.as_deref().map(parse_uuid).transpose()?,
        grant_or_request_id: scope
            .grant_or_request_id
            .as_deref()
            .map(parse_uuid)
            .transpose()?,
        agent_id: scope.agent_id.as_deref().map(parse_uuid).transpose()?,
        member_id: scope.member_id.as_deref().map(parse_uuid).transpose()?,
    })
}

fn parse_uuid(value: &str) -> Result<[u8; 16], CryptoError> {
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return Err(CryptoError::InvalidEncoding);
    }
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    let decoded = hex::decode(compact).map_err(|_| CryptoError::InvalidEncoding)?;
    decoded.try_into().map_err(|_| CryptoError::InvalidLength)
}

fn format_uuid(value: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
        value[6],
        value[7],
        value[8],
        value[9],
        value[10],
        value[11],
        value[12],
        value[13],
        value[14],
        value[15]
    )
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, CryptoError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(decoded)
}

fn decode_fixed<const SIZE: usize>(value: &str) -> Result<[u8; SIZE], CryptoError> {
    decode_base64url(value)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                zeroize_json(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use secrecy::{ExposeSecret, SecretBox};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

    use super::{
        AgentVaultKeyWrapper, AgentVaultKeyWrapperDescriptor, AgentWrappedVaultKey,
        CredentialEnvelopeContext, CryptoError, DecryptedCredential, EncryptedCredential,
        FullCredentialEnvelopeContext, GrantEnvelopeBinding, GrantEnvelopeDescriptor,
        GrantEnvelopeScope, MemberSecretBinding, MemberSecretDescriptor, MemberSecretEnvelope,
        VaultEntryKeyDescriptor, VaultEntryKeyEnvelope, VaultKeyBinding, WrappedGrantDek,
        WrappedGrantDekDescriptor, decrypt_full_credential_at, normalize_full_member_secret,
        normalize_grant_payload, parse_nonzero_u64, parse_uuid, to_descriptor,
    };
    use crate::{
        EnvelopeBinding, EnvelopeDescriptor, EnvelopePurpose, EnvelopeScope, RecipientKeyKind,
        VAULT_XCHACHA_V1, WrapperContext, WrapperPurpose, X25519_WRAPPER_V1, X25519Identity,
        X25519SealedBoxSuite, XChaChaVaultSuite, compute_field_set_commitment,
        compute_key_fingerprint,
    };

    #[test]
    fn full_grant_unwraps_vault_key_only_inside_native_crypto_and_projects_member_policy() {
        const ORGANIZATION_ID: &str = "00112233-4455-4677-8899-aabbccddeeff";
        const VAULT_ID: &str = "11112222-3333-4444-8555-666677778888";
        const GRANT_ID: &str = "12345678-1234-4234-8234-1234567890ab";
        const AGENT_ID: &str = "fedcba98-7654-4321-8765-abcdefabcdef";
        const ENTRY_ID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

        let identity = X25519Identity::from_private_bytes(vec![0x41; 32]).expect("identity");
        let organization_id = parse_uuid(ORGANIZATION_ID).expect("organization");
        let vault_id = parse_uuid(VAULT_ID).expect("vault");
        let grant_id = parse_uuid(GRANT_ID).expect("grant");
        let agent_id = parse_uuid(AGENT_ID).expect("agent");
        let entry_id = parse_uuid(ENTRY_ID).expect("entry");
        let fingerprint =
            compute_key_fingerprint(identity.public_key(), RecipientKeyKind::AgentX25519);
        let vault_key = SecretBox::new(Box::new([0x21; 32]));
        let wrapper_scope = EnvelopeScope {
            organization_id,
            vault_id,
            entry_id: None,
            grant_or_request_id: Some(grant_id),
            agent_id: Some(agent_id),
            member_id: None,
        };
        let wrapper_context = WrapperContext {
            protocol_version: 2,
            wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
            purpose: WrapperPurpose::AgentVaultKey,
            scope: wrapper_scope,
            resource_revision: 7,
            wrapped_key_version: 3,
            member_key_generation: None,
            recipient_key_kind: RecipientKeyKind::AgentX25519,
            recipient_key_version: 2,
            recipient_fingerprint: fingerprint,
            parent_descriptor_hash: None,
        };
        let sealed_vault_key =
            X25519SealedBoxSuite::wrap(&vault_key, *identity.public_key(), &wrapper_context)
                .expect("wrapped vault key");
        let wire_scope = GrantEnvelopeScope {
            organization_id: ORGANIZATION_ID.to_owned(),
            vault_id: VAULT_ID.to_owned(),
            entry_id: None,
            grant_or_request_id: Some(GRANT_ID.to_owned()),
            agent_id: Some(AGENT_ID.to_owned()),
            member_id: None,
        };
        let wrapped_vault_key = AgentWrappedVaultKey {
            wrapped_vault_key: AgentVaultKeyWrapper {
                descriptor: AgentVaultKeyWrapperDescriptor {
                    protocol_version: 2,
                    wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                    purpose: 5,
                    scope: wire_scope,
                    resource_revision: "7".to_owned(),
                    wrapped_key_version: 3,
                    member_key_generation: None,
                    recipient_key_kind: 1,
                    recipient_key_version: 2,
                    recipient_fingerprint: URL_SAFE_NO_PAD.encode(fingerprint),
                    parent_descriptor_hash: None,
                },
                encoded_sealed_key_package: URL_SAFE_NO_PAD.encode(sealed_vault_key.as_bytes()),
            },
        };

        let entry_scope = EnvelopeScope {
            organization_id,
            vault_id,
            entry_id: Some(entry_id),
            grant_or_request_id: None,
            agent_id: None,
            member_id: None,
        };
        let entry_descriptor = EnvelopeDescriptor {
            protocol_version: 2,
            crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
            purpose: EnvelopePurpose::EntryDekByVaultKey,
            scope: entry_scope.clone(),
            resource_revision: 1,
            key_version: 4,
            member_key_generation: Some(5),
            binding: EnvelopeBinding::VaultKey {
                wrapping_vault_key_version: 3,
            },
        };
        let entry_dek = [0x31; 32];
        let entry_key = XChaChaVaultSuite::derive_key(vault_key.expose_secret(), &entry_descriptor)
            .expect("entry wrapper key");
        let entry_payload = XChaChaVaultSuite::seal(
            &entry_key,
            &entry_dek,
            &entry_descriptor.canonical_aad().expect("entry AAD"),
        )
        .expect("entry payload");
        let entry_wire_scope = GrantEnvelopeScope {
            organization_id: ORGANIZATION_ID.to_owned(),
            vault_id: VAULT_ID.to_owned(),
            entry_id: Some(ENTRY_ID.to_owned()),
            grant_or_request_id: None,
            agent_id: None,
            member_id: None,
        };
        let entry_envelope = VaultEntryKeyEnvelope {
            descriptor: VaultEntryKeyDescriptor {
                protocol_version: 2,
                crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
                purpose: 8,
                scope: entry_wire_scope.clone(),
                resource_revision: "1".to_owned(),
                key_version: 4,
                member_key_generation: Some(5),
                binding: VaultKeyBinding {
                    wrapping_vault_key_version: 3,
                },
            },
            encoded_suite_payload: URL_SAFE_NO_PAD.encode(entry_payload.as_bytes()),
        };

        let secret_descriptor = EnvelopeDescriptor {
            protocol_version: 2,
            crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
            purpose: EnvelopePurpose::MemberSecret,
            scope: entry_scope,
            resource_revision: 9,
            key_version: 4,
            member_key_generation: Some(5),
            binding: EnvelopeBinding::MemberSecret { operation: 2 },
        };
        let member_plaintext = serde_json::to_vec(&serde_json::json!({
            "agentLabel": null,
            "agentVisibilityPolicy": {
                "discoveryEnabled": false,
                "fields": [
                    { "access": 1, "fieldId": "common.agent-label" },
                    { "access": 1, "fieldId": "common.capabilities" },
                    { "access": 0, "fieldId": "common.description" },
                    { "access": 1, "fieldId": "common.entry-type" },
                    { "access": 0, "fieldId": "common.icon-reference" },
                    { "access": 0, "fieldId": "common.member-label" },
                    { "access": 0, "fieldId": "common.search-fields" },
                    { "access": 0, "fieldId": "key.notes" },
                    { "access": 0, "fieldId": "key.url" },
                    { "access": 2, "fieldId": "key.value" }
                ],
                "schemaVersion": 1
            },
            "content": {
                "fields": [],
                "v": 2,
                "value": "fixture-sensitive-value"
            },
            "description": null,
            "entryType": 0,
            "memberLabel": "Member-only label"
        }))
        .expect("canonical member secret");
        let secret_key = XChaChaVaultSuite::derive_key(&entry_dek, &secret_descriptor)
            .expect("member secret key");
        let secret_payload = XChaChaVaultSuite::seal(
            &secret_key,
            &member_plaintext,
            &secret_descriptor.canonical_aad().expect("secret AAD"),
        )
        .expect("secret payload");
        let secret_envelope = MemberSecretEnvelope {
            descriptor: MemberSecretDescriptor {
                protocol_version: 2,
                crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
                purpose: 6,
                scope: entry_wire_scope,
                resource_revision: "9".to_owned(),
                key_version: 4,
                member_key_generation: Some(5),
                binding: MemberSecretBinding { operation: 2 },
            },
            encoded_suite_payload: URL_SAFE_NO_PAD.encode(secret_payload.as_bytes()),
        };

        let credential = decrypt_full_credential_at(
            &wrapped_vault_key,
            &entry_envelope,
            &secret_envelope,
            &identity,
            &FullCredentialEnvelopeContext {
                organization_id: ORGANIZATION_ID,
                vault_id: VAULT_ID,
                grant_id: GRANT_ID,
                agent_id: AGENT_ID,
                agent_access_epoch: 7,
                trusted_agent_access_epoch: 7,
                entry_id: ENTRY_ID,
                approved_methods: 1,
                delivery_policy: 0,
                expires_at: None,
                requested_vault_id: VAULT_ID,
                requested_entry_id: ENTRY_ID,
                requested_method: 1,
            },
            OffsetDateTime::now_utc(),
        )
        .expect("full credential");
        let credential_digest = Sha256::digest(credential.expose_for_authorized_operation());
        let expected_plaintext = serde_json::to_vec(&serde_json::json!({
            "value": "fixture-sensitive-value"
        }))
        .expect("projected credential");
        let expected_digest = Sha256::digest(expected_plaintext);
        assert_eq!(credential_digest, expected_digest);

        let context = FullCredentialEnvelopeContext {
            organization_id: ORGANIZATION_ID,
            vault_id: VAULT_ID,
            grant_id: GRANT_ID,
            agent_id: AGENT_ID,
            agent_access_epoch: 7,
            trusted_agent_access_epoch: 7,
            entry_id: ENTRY_ID,
            approved_methods: 1,
            delivery_policy: 0,
            expires_at: None,
            requested_vault_id: VAULT_ID,
            requested_entry_id: ENTRY_ID,
            requested_method: 1,
        };
        let mut wrong_epoch = wrapped_vault_key.clone();
        wrong_epoch.wrapped_vault_key.descriptor.resource_revision = "8".to_owned();
        assert!(matches!(
            decrypt_full_credential_at(
                &wrong_epoch,
                &entry_envelope,
                &secret_envelope,
                &identity,
                &context,
                OffsetDateTime::now_utc(),
            ),
            Err(CryptoError::InvalidDescriptor)
        ));

        let stale_anchor_context = FullCredentialEnvelopeContext {
            organization_id: ORGANIZATION_ID,
            vault_id: VAULT_ID,
            grant_id: GRANT_ID,
            agent_id: AGENT_ID,
            agent_access_epoch: 7,
            trusted_agent_access_epoch: 8,
            entry_id: ENTRY_ID,
            approved_methods: 1,
            delivery_policy: 0,
            expires_at: None,
            requested_vault_id: VAULT_ID,
            requested_entry_id: ENTRY_ID,
            requested_method: 1,
        };
        assert!(matches!(
            decrypt_full_credential_at(
                &wrapped_vault_key,
                &entry_envelope,
                &secret_envelope,
                &identity,
                &stale_anchor_context,
                OffsetDateTime::now_utc(),
            ),
            Err(CryptoError::InvalidDescriptor)
        ));

        let mut wrong_grant = wrapped_vault_key.clone();
        wrong_grant
            .wrapped_vault_key
            .descriptor
            .scope
            .grant_or_request_id = Some("87654321-4321-4321-8321-ba0987654321".to_owned());
        assert!(matches!(
            decrypt_full_credential_at(
                &wrong_grant,
                &entry_envelope,
                &secret_envelope,
                &identity,
                &context,
                OffsetDateTime::now_utc(),
            ),
            Err(CryptoError::InvalidDescriptor)
        ));
    }

    #[test]
    fn full_projection_accepts_the_pinned_member_secret_payload() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../contracts/vault-v2/fixtures/v2/vectors/envelopes.json"
        ))
        .expect("pinned envelope fixture");
        let plaintext = fixture["aeadVectors"]
            .as_array()
            .expect("fixture vectors")
            .iter()
            .find(|vector| vector["id"] == "member-secret")
            .and_then(|vector| vector["plaintextCanonical"].as_str())
            .expect("pinned MemberSecret plaintext");

        let normalized = normalize_full_member_secret(plaintext.as_bytes(), 1, 0)
            .expect("canonical MemberSecret projection");

        assert_eq!(
            normalized.plaintext,
            br#"{"password":"not-a-real-password","url":"postgresql://fixture.invalid"}"#
        );
    }

    #[test]
    fn plaintext_debug_is_redacted() {
        let plaintext = DecryptedCredential {
            plaintext: br#"{"urlDomain":"sensitive.example","password":"synthetic-plaintext"}"#
                .to_vec()
                .into(),
            grant_expires_at: None,
        };
        let debug = format!("{plaintext:?}");
        assert_eq!(debug, "DecryptedCredential([REDACTED])");
        assert!(!debug.contains("synthetic-plaintext"));
        assert!(!debug.contains("sensitive.example"));
    }

    #[test]
    fn decrypted_grant_is_rechecked_at_final_use_time() {
        let expires_at = OffsetDateTime::from_unix_timestamp(1_800_000_001).expect("expiry");
        let credential = DecryptedCredential {
            plaintext: b"fixture-sensitive-value".to_vec().into(),
            grant_expires_at: Some(crate::InstantBinding {
                unix_seconds: expires_at.unix_timestamp(),
                nanosecond: expires_at.nanosecond(),
            }),
        };
        assert_eq!(
            credential
                .remaining_validity_at(expires_at - Duration::SECOND)
                .expect("fresh grant"),
            Some(std::time::Duration::from_secs(1))
        );
        assert_eq!(
            credential.remaining_validity_at(expires_at),
            Err(CryptoError::StaleInput)
        );
    }

    #[test]
    fn grant_payload_is_strict_jcs_and_bound_to_field_ids() {
        let payload = br#"{"entryType":"key","fields":[{"id":"key.value","kind":"concealed","mode":"value","value":"fixture"}],"schema":"palladin.grant-payload.v1"}"#;
        let normalized = normalize_grant_payload(payload, &["key.value".to_owned()], 1)
            .expect("canonical payload");
        assert_eq!(normalized.plaintext, br#"{"value":"fixture"}"#);

        let non_canonical = br#"{ "entryType":"key","fields":[{"id":"key.value","kind":"concealed","mode":"value","value":"fixture"}],"schema":"palladin.grant-payload.v1"}"#;
        assert!(matches!(
            normalize_grant_payload(non_canonical, &["key.value".to_owned()], 1),
            Err(CryptoError::InvalidEncoding)
        ));
        assert!(matches!(
            normalize_grant_payload(payload, &["notes".to_owned()], 1),
            Err(CryptoError::InvalidDescriptor)
        ));
    }

    #[test]
    fn duplicate_keys_and_runtime_fields_on_get_fail_closed() {
        let duplicate = br#"{"entryType":"key","entryType":"key","fields":[{"id":"key.value","kind":"concealed","mode":"value","value":"fixture"}],"schema":"palladin.grant-payload.v1"}"#;
        assert!(matches!(
            normalize_grant_payload(duplicate, &["key.value".to_owned()], 1),
            Err(CryptoError::InvalidEncoding)
        ));
        let script = br#"{"entryType":"script","fields":[{"id":"script.source","kind":"script","mode":"runtime","value":"echo safe"}],"schema":"palladin.grant-payload.v1"}"#;
        assert!(matches!(
            normalize_grant_payload(script, &["script.source".to_owned()], 1),
            Err(CryptoError::InvalidDescriptor)
        ));
    }

    #[test]
    fn inject_accepts_encrypted_origin_and_rejects_missing_origin_or_runtime_fields() {
        let inject = br#"{"entryType":"credential","fields":[{"id":"credential.password","kind":"concealed","mode":"value","value":"fixture"},{"id":"credential.urlDomain","kind":"text","mode":"value","value":"example.test"}],"schema":"palladin.grant-payload.v1"}"#;
        let normalized = normalize_grant_payload(
            inject,
            &[
                "credential.password".to_owned(),
                "credential.urlDomain".to_owned(),
            ],
            4,
        )
        .expect("inject payload with encrypted origin");
        assert_eq!(
            normalized.plaintext,
            br#"{"password":"fixture","urlDomain":"example.test"}"#
        );

        let missing_origin = br#"{"entryType":"credential","fields":[{"id":"credential.password","kind":"concealed","mode":"value","value":"fixture"}],"schema":"palladin.grant-payload.v1"}"#;
        assert!(matches!(
            normalize_grant_payload(missing_origin, &["credential.password".to_owned()], 4),
            Err(CryptoError::InvalidDescriptor)
        ));

        let script = br#"{"entryType":"script","fields":[{"id":"script.source","kind":"script","mode":"runtime","value":"echo safe"}],"schema":"palladin.grant-payload.v1"}"#;
        assert!(matches!(
            normalize_grant_payload(script, &["script.source".to_owned()], 4),
            Err(CryptoError::InvalidDescriptor)
        ));

        let fails_after_sensitive_domain = br#"{"entryType":"credential","fields":[{"id":"credential.urlDomain","kind":"text","mode":"value","value":"drop-canary.example"},{"id":"notes","kind":"text","mode":"value","value":"invalid-kind"}],"schema":"palladin.grant-payload.v1"}"#;
        assert!(matches!(
            normalize_grant_payload(
                fails_after_sensitive_domain,
                &["credential.urlDomain".to_owned(), "notes".to_owned()],
                4
            ),
            Err(CryptoError::InvalidDescriptor)
        ));
    }

    #[test]
    fn nullable_builtin_fields_are_authenticated_as_absent_without_weakening_types() {
        let payload = br#"{"entryType":"credential","fields":[{"id":"credential.password","kind":"concealed","mode":"value","value":"fixture"},{"id":"credential.totp","kind":"totp","mode":"derived","value":null},{"id":"credential.url","kind":"url","mode":"value","value":null},{"id":"credential.urlDomain","kind":"text","mode":"value","value":"example.test"},{"id":"notes","kind":"multiline","mode":"value","value":null}],"schema":"palladin.grant-payload.v1"}"#;
        let field_ids = [
            "credential.password",
            "credential.totp",
            "credential.url",
            "credential.urlDomain",
            "notes",
        ]
        .map(str::to_owned);
        let normalized =
            normalize_grant_payload(payload, &field_ids, 4).expect("nullable built-ins");
        assert_eq!(
            normalized.plaintext,
            br#"{"password":"fixture","urlDomain":"example.test"}"#
        );

        let wrong_type = br#"{"entryType":"credential","fields":[{"id":"credential.password","kind":"concealed","mode":"value","value":7},{"id":"credential.urlDomain","kind":"text","mode":"value","value":"example.test"}],"schema":"palladin.grant-payload.v1"}"#;
        assert!(matches!(
            normalize_grant_payload(
                wrong_type,
                &[
                    "credential.password".to_owned(),
                    "credential.urlDomain".to_owned()
                ],
                4
            ),
            Err(CryptoError::InvalidEncoding)
        ));
    }

    #[test]
    fn canonical_totp_script_reference_preserves_its_field_id() {
        let payload = br#"{"entryType":"script","fields":[{"id":"script.refs","kind":"refs","mode":"runtime","value":[{"entryId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","env":"TOTP_CODE","fieldId":"credential.totp","vaultId":"11112222-3333-4444-8555-666677778888"}]}],"schema":"palladin.grant-payload.v1"}"#;
        let normalized = normalize_grant_payload(payload, &["script.refs".to_owned()], 2)
            .expect("canonical TOTP reference");
        assert_eq!(
            normalized.plaintext,
            br#"{"refs":[{"entryId":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","env":"TOTP_CODE","fieldId":"credential.totp","vaultId":"11112222-3333-4444-8555-666677778888"}]}"#
        );
    }

    #[test]
    fn expiry_is_checked_at_use_time_while_positive_server_use_count_is_not_mutated_locally() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time");
        let lifetime = wire_envelope(None, None);
        assert!(to_descriptor(&lifetime, &outer_context(), now).is_ok());

        let expired = wire_envelope(Some(now - Duration::SECOND), None);
        assert!(matches!(
            to_descriptor(&expired, &outer_context(), now),
            Err(CryptoError::InvalidDescriptor)
        ));

        let future = wire_envelope(Some(now + Duration::SECOND), None);
        assert!(to_descriptor(&future, &outer_context(), now).is_ok());

        let counted = wire_envelope(None, Some(1));
        assert!(to_descriptor(&counted, &outer_context(), now).is_ok());
        assert!(to_descriptor(&counted, &outer_context(), now).is_ok());

        let bounded_by_time_and_use_count = wire_envelope(Some(now + Duration::SECOND), Some(1));
        assert!(to_descriptor(&bounded_by_time_and_use_count, &outer_context(), now).is_ok());

        let exhausted = wire_envelope(Some(now + Duration::SECOND), Some(0));
        assert!(matches!(
            to_descriptor(&exhausted, &outer_context(), now),
            Err(CryptoError::InvalidDescriptor)
        ));
    }

    #[test]
    fn revision_strings_are_positive_canonical_decimals() {
        assert_eq!(parse_nonzero_u64("1"), Ok(1));
        for invalid in ["0", "01", "+1", " 1"] {
            assert!(parse_nonzero_u64(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn backend_named_protocol_enums_decode_to_authenticated_numeric_codes() {
        let mut value = serde_json::to_value(wire_envelope(None, Some(1))).expect("wire JSON");
        value["descriptor"]["purpose"] = serde_json::Value::String("grantPayload".to_owned());
        value["wrappedGrantDek"]["descriptor"]["purpose"] =
            serde_json::Value::String("grantDek".to_owned());
        value["wrappedGrantDek"]["descriptor"]["recipientKeyKind"] =
            serde_json::Value::String("agentX25519".to_owned());

        let decoded: EncryptedCredential =
            serde_json::from_value(value.clone()).expect("current backend contract");
        assert_eq!(decoded.descriptor.purpose, 10);
        assert_eq!(
            decoded.wrapped_grant_dek.descriptor.purpose,
            WrapperPurpose::GrantDek as u16
        );
        assert_eq!(
            decoded.wrapped_grant_dek.descriptor.recipient_key_kind,
            RecipientKeyKind::AgentX25519 as u16
        );

        value["descriptor"]["purpose"] = serde_json::Value::String("unknown".to_owned());
        assert!(serde_json::from_value::<EncryptedCredential>(value).is_err());
    }

    fn wire_envelope(
        expires_at: Option<OffsetDateTime>,
        remaining_uses: Option<u32>,
    ) -> EncryptedCredential {
        let field_ids = vec!["key.value".to_owned()];
        let commitment = compute_field_set_commitment(["key.value"]).expect("commitment");
        EncryptedCredential {
            descriptor: GrantEnvelopeDescriptor {
                protocol_version: 2,
                crypto_suite_id: VAULT_XCHACHA_V1.to_owned(),
                purpose: 10,
                scope: GrantEnvelopeScope {
                    organization_id: "00112233-4455-4677-8899-aabbccddeeff".to_owned(),
                    vault_id: "11112222-3333-4444-8555-666677778888".to_owned(),
                    entry_id: Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_owned()),
                    grant_or_request_id: Some("12345678-1234-4234-8234-1234567890ab".to_owned()),
                    agent_id: Some("fedcba98-7654-4321-8765-abcdefabcdef".to_owned()),
                    member_id: None,
                },
                resource_revision: "1".to_owned(),
                key_version: 1,
                member_key_generation: Some(1),
                binding: GrantEnvelopeBinding {
                    entry_revision: "1".to_owned(),
                    wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                    recipient_key_version: 1,
                    recipient_key_fingerprint: URL_SAFE_NO_PAD.encode([7_u8; 32]),
                    approved_methods: 1,
                    delivery_policy: 0,
                    field_set_commitment: URL_SAFE_NO_PAD.encode(commitment),
                    expires_at: expires_at.map(|value| value.format(&Rfc3339).expect("RFC3339")),
                    remaining_uses,
                },
            },
            encoded_suite_payload: String::new(),
            wrapped_grant_dek: WrappedGrantDek {
                descriptor: WrappedGrantDekDescriptor {
                    protocol_version: 2,
                    wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                    purpose: WrapperPurpose::GrantDek as u16,
                    scope: GrantEnvelopeScope {
                        organization_id: "00112233-4455-4677-8899-aabbccddeeff".to_owned(),
                        vault_id: "11112222-3333-4444-8555-666677778888".to_owned(),
                        entry_id: Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_owned()),
                        grant_or_request_id: Some(
                            "12345678-1234-4234-8234-1234567890ab".to_owned(),
                        ),
                        agent_id: Some("fedcba98-7654-4321-8765-abcdefabcdef".to_owned()),
                        member_id: None,
                    },
                    resource_revision: "1".to_owned(),
                    wrapped_key_version: 1,
                    member_key_generation: Some(1),
                    recipient_key_kind: RecipientKeyKind::AgentX25519 as u16,
                    recipient_key_version: 1,
                    recipient_fingerprint: URL_SAFE_NO_PAD.encode([7_u8; 32]),
                    parent_descriptor_hash: Some(URL_SAFE_NO_PAD.encode([0_u8; 32])),
                },
                encoded_sealed_key_package: String::new(),
            },
            field_ids,
        }
    }

    fn outer_context() -> CredentialEnvelopeContext<'static> {
        CredentialEnvelopeContext {
            organization_id: "00112233-4455-4677-8899-aabbccddeeff",
            vault_id: "11112222-3333-4444-8555-666677778888",
            grant_id: "12345678-1234-4234-8234-1234567890ab",
            agent_id: "fedcba98-7654-4321-8765-abcdefabcdef",
            entry_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            approved_methods: 1,
            requested_vault_id: "11112222-3333-4444-8555-666677778888",
            requested_entry_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            requested_method: 1,
        }
    }
}
