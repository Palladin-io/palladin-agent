use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedCredential {
    pub descriptor: GrantEnvelopeDescriptor,
    pub encoded_suite_payload: String,
    pub wrapped_grant_dek: WrappedGrantDek,
    pub field_ids: Vec<String>,
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
    pub purpose: u16,
    pub scope: GrantEnvelopeScope,
    pub resource_revision: String,
    pub wrapped_key_version: u32,
    pub member_key_generation: Option<u32>,
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

pub struct DecryptedCredential {
    plaintext: SecretSlice<u8>,
}

impl DecryptedCredential {
    #[must_use]
    pub fn expose_for_authorized_operation(&self) -> &[u8] {
        self.plaintext.expose_secret()
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
    )?;
    Ok(DecryptedCredential {
        plaintext: normalized.plaintext.into(),
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
        || !matches!(payload.entry_type.as_str(), "key" | "credential" | "script")
        || payload.fields.is_empty()
        || !matches!(requested_method, 1 | 2 | 4)
        || (payload.entry_type == "script" && requested_method != 2)
        || (requested_method == 4 && payload.entry_type != "credential")
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
        if requested_method != 2 && field.mode == "runtime" {
            return Err(CryptoError::InvalidDescriptor);
        }
        match field.kind.as_str() {
            "text" | "multiline" | "concealed" | "url" | "script" | "interpreter" => {
                let Value::String(value) = std::mem::take(&mut field.value) else {
                    return Err(CryptoError::InvalidEncoding);
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
                let value: TotpValue = serde_json::from_value(std::mem::take(&mut field.value))
                    .map_err(|_| CryptoError::InvalidEncoding)?;
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
    if requested_method == 4 && !has_encrypted_url_domain {
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
        ("credential", "credential.username") => ("text", "value"),
        ("credential", "credential.password") => ("concealed", "value"),
        ("credential", "credential.url") => ("url", "value"),
        ("credential", "credential.urlDomain") => ("text", "value"),
        ("credential", "credential.totp") => ("totp", "derived"),
        ("credential" | "key", "notes") => ("multiline", "value"),
        ("script", "script.source") => ("script", "runtime"),
        ("script", "script.interpreter") => ("interpreter", "runtime"),
        ("script", "script.refs") => ("refs", "runtime"),
        (_, custom) if is_custom_field_id(custom) => {
            return match kind {
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
        "credential.username" => "username",
        "credential.password" => "password",
        "credential.url" => "url",
        "credential.urlDomain" => "urlDomain",
        "notes" => "notes",
        "script.source" => "script",
        "script.interpreter" => "interpreter",
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
            | "credential.username"
            | "credential.password"
            | "credential.url"
            | "credential.urlDomain"
            | "credential.totp"
            | "notes"
            | "script.source"
            | "script.interpreter"
            | "script.refs"
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
    use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

    use super::{
        CredentialEnvelopeContext, CryptoError, DecryptedCredential, EncryptedCredential,
        GrantEnvelopeBinding, GrantEnvelopeDescriptor, GrantEnvelopeScope, WrappedGrantDek,
        WrappedGrantDekDescriptor, normalize_grant_payload, parse_nonzero_u64, to_descriptor,
    };
    use crate::{
        RecipientKeyKind, VAULT_XCHACHA_V1, WrapperPurpose, X25519_WRAPPER_V1,
        compute_field_set_commitment,
    };

    #[test]
    fn plaintext_debug_is_redacted() {
        let plaintext = DecryptedCredential {
            plaintext: br#"{"urlDomain":"sensitive.example","password":"synthetic-plaintext"}"#
                .to_vec()
                .into(),
        };
        let debug = format!("{plaintext:?}");
        assert_eq!(debug, "DecryptedCredential([REDACTED])");
        assert!(!debug.contains("synthetic-plaintext"));
        assert!(!debug.contains("sensitive.example"));
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
