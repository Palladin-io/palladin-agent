use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::ExposeSecret;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CryptoError, EncodedSuitePayload, EnvelopeScope, RecipientKeyKind, SealedWrappedKey,
    SecretBytes, SignatureProfile, WrapperContext, WrapperPurpose, X25519_WRAPPER_V1,
    X25519Identity, X25519SealedBoxSuite, XChaChaVaultSuite, compute_key_fingerprint,
    decode_base64url, verify_domain_signature,
};

const CONTRACT_VERSION: u16 = 1;
const PROTOCOL_VERSION: u16 = 2;
const MAX_PACKAGE_BYTES: usize = 2_097_152;
const MAX_PARAMETERS_BYTES: usize = 32_768;
const MAX_PARAMETER_COUNT: usize = 32;
const MAX_REFERENCE_COUNT: usize = 64;
const MANIFEST_DOMAIN: &[u8] = b"PLDNSCRIPT1";
const TRANSPORT_AAD_DOMAIN: &[u8] = b"PLDNSCRIPTAAD1";

const RESERVED_ENV_NAMES: &[&str] = &[
    "BASHOPTS",
    "BASH_ENV",
    "CDPATH",
    "ENV",
    "GCONV_PATH",
    "GLOBIGNORE",
    "HOME",
    "HOSTALIASES",
    "IFS",
    "LD_PRELOAD",
    "LOCPATH",
    "LOGNAME",
    "NLSPATH",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PATH",
    "PERL5LIB",
    "PERL5OPT",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYOPT",
    "SHELL",
    "SHELLOPTS",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USER",
];
const RESERVED_ENV_PREFIXES: &[&str] = &["CLAW_", "DYLD_", "LD_", "PALLADIN_"];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptExecutionParameterType {
    String,
    Integer,
    Number,
    Boolean,
}

pub struct ScriptExecutionParameters(Value);

impl ScriptExecutionParameters {
    pub fn from_value(value: Value) -> Result<Self, CryptoError> {
        if !value.is_object() || canonical_json(&value)?.len() > MAX_PARAMETERS_BYTES {
            return Err(CryptoError::InvalidProfile);
        }
        Ok(Self(value))
    }

    pub fn from_json_slice(value: &[u8]) -> Result<Self, CryptoError> {
        if value.len() > MAX_PARAMETERS_BYTES {
            return Err(CryptoError::InvalidLength);
        }
        let value = serde_json::from_slice(value).map_err(|_| CryptoError::InvalidEncoding)?;
        Self::from_value(value)
    }

    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    pub fn canonical_bytes(&self) -> Result<SecretBytes, CryptoError> {
        Ok(SecretBytes::new(canonical_json(&self.0)?))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.as_object().is_some_and(serde_json::Map::is_empty)
    }
}

impl Default for ScriptExecutionParameters {
    fn default() -> Self {
        Self(Value::Object(serde_json::Map::new()))
    }
}

impl<'de> Deserialize<'de> for ScriptExecutionParameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_value(Value::deserialize(deserializer)?)
            .map_err(|_| de::Error::custom("invalid Script execution parameters"))
    }
}

impl std::fmt::Debug for ScriptExecutionParameters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScriptExecutionParameters([REDACTED])")
    }
}

impl Drop for ScriptExecutionParameters {
    fn drop(&mut self) {
        zeroize_json(&mut self.0);
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionParameter {
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub parameter_type: ScriptExecutionParameterType,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<Number>,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub allowed_values: Option<Vec<Value>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionMetadata {
    pub contract_version: u16,
    pub description: String,
    pub parameters: Vec<ScriptExecutionParameter>,
    #[serde(default)]
    pub return_result_to_agent: Option<bool>,
}

impl ScriptExecutionMetadata {
    #[must_use]
    pub fn effective_return_result_to_agent(&self) -> bool {
        self.return_result_to_agent == Some(true)
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.contract_version != CONTRACT_VERSION
            || self.description.trim().is_empty()
            || self.description != self.description.trim()
            || self.description.len() > 4_096
            || !is_nfc(&self.description)
        {
            return Err(CryptoError::InvalidProfile);
        }
        validate_parameter_definitions(&self.parameters)
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionReference {
    pub env: String,
    pub vault_id: String,
    pub entry_id: String,
    pub field_id: String,
    pub entry_revision: String,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionManifest {
    pub schema: String,
    pub contract_version: u16,
    pub organization_id: String,
    pub agent_id: String,
    pub agent_access_epoch: u32,
    pub vault_id: String,
    pub script_entry_id: String,
    pub script_revision: String,
    pub description: String,
    pub parameters: Vec<ScriptExecutionParameter>,
    pub return_result_to_agent: bool,
    pub interpreter: String,
    pub script_source: String,
    pub references: Vec<ScriptExecutionReference>,
}

impl Drop for ScriptExecutionManifest {
    fn drop(&mut self) {
        self.script_source.zeroize();
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "source", rename_all = "camelCase", deny_unknown_fields)]
pub enum ScriptExecutionAuthorization {
    ScriptExecution {
        #[serde(rename = "grantId")]
        grant_id: String,
    },
    Full {
        #[serde(rename = "grantId")]
        grant_id: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionScope {
    pub vault_id: String,
    pub entry_id: String,
    pub field_id: String,
    pub entry_revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionTransportScope {
    pub entry_id: String,
    pub entry_revision: String,
    pub is_script: bool,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionBinding {
    pub schema: String,
    pub contract_version: u16,
    pub organization_id: String,
    pub agent_id: String,
    pub agent_access_epoch: u32,
    pub vault_id: String,
    pub script_entry_id: String,
    pub script_revision: String,
    pub manifest_digest: String,
    pub authorization: ScriptExecutionAuthorization,
    pub scopes: Vec<ScriptExecutionScope>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionEncryptedPackage {
    pub contract_version: u16,
    pub organization_id: String,
    pub vault_id: String,
    pub grant_id: String,
    pub agent_id: String,
    pub agent_access_epoch: u32,
    pub script_entry_id: String,
    pub script_revision: String,
    pub package_revision: String,
    pub recipient_agent_key_version: u32,
    pub recipient_agent_key_fingerprint: String,
    pub vault_signing_key_version: u32,
    pub vault_signing_key_fingerprint: String,
    pub manifest_digest: String,
    pub scopes: Vec<ScriptExecutionTransportScope>,
    pub encoded_package_ciphertext: String,
    pub producer_signature: String,
}

impl std::fmt::Debug for ScriptExecutionEncryptedPackage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptExecutionEncryptedPackage")
            .field("script_entry_id", &self.script_entry_id)
            .field("script_revision", &self.script_revision)
            .field("package_revision", &self.package_revision)
            .field("ciphertext", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedScriptExecutionPackageContext {
    pub organization_id: String,
    pub vault_id: String,
    pub grant_id: String,
    pub agent_id: String,
    pub agent_access_epoch: u32,
    pub script_entry_id: String,
    pub script_revision: String,
    pub package_revision: String,
    pub recipient_agent_key_version: u32,
    pub vault_signing_key_version: u32,
    pub vault_signing_key_fingerprint: String,
    pub vault_signing_public_key: [u8; 32],
}

pub struct OpenedScriptExecutionReference {
    pub entry_id: String,
    pub entry_revision: String,
    pub encoded_grant_payload: SecretBytes,
}

pub struct OpenedScriptExecutionPackage {
    pub binding: ScriptExecutionBinding,
    pub manifest: ScriptExecutionManifest,
    pub entries: Vec<OpenedScriptExecutionReference>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScriptExecutionCiphertextContainer {
    schema: String,
    contract_version: u16,
    package_revision: String,
    encoded_sealed_package_dek: String,
    encoded_suite_payload: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScriptExecutionPayload {
    schema: String,
    binding: ScriptExecutionBinding,
    manifest: ScriptExecutionManifest,
    entries: Vec<ScriptExecutionEntry>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScriptExecutionEntry {
    entry_id: String,
    entry_revision: String,
    encoded_grant_payload: String,
}

impl Drop for ScriptExecutionEntry {
    fn drop(&mut self) {
        self.encoded_grant_payload.zeroize();
    }
}

struct ScriptExecutionSensitiveJson(Value);

impl Drop for ScriptExecutionSensitiveJson {
    fn drop(&mut self) {
        zeroize_json(&mut self.0);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScriptExecutionTransportBinding<'a> {
    contract_version: u16,
    organization_id: &'a str,
    vault_id: &'a str,
    grant_id: &'a str,
    agent_id: &'a str,
    agent_access_epoch: u32,
    script_entry_id: &'a str,
    script_revision: &'a str,
    package_revision: &'a str,
    recipient_agent_key_version: u32,
    recipient_agent_key_fingerprint: &'a str,
    vault_signing_key_version: u32,
    vault_signing_key_fingerprint: &'a str,
    manifest_digest: &'a str,
    scopes: &'a [ScriptExecutionTransportScope],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScriptExecutionUnsignedPackage<'a> {
    contract_version: u16,
    organization_id: &'a str,
    vault_id: &'a str,
    grant_id: &'a str,
    agent_id: &'a str,
    agent_access_epoch: u32,
    script_entry_id: &'a str,
    script_revision: &'a str,
    package_revision: &'a str,
    recipient_agent_key_version: u32,
    recipient_agent_key_fingerprint: &'a str,
    vault_signing_key_version: u32,
    vault_signing_key_fingerprint: &'a str,
    manifest_digest: &'a str,
    scopes: &'a [ScriptExecutionTransportScope],
    encoded_package_ciphertext: &'a str,
}

pub fn validate_script_execution_parameters(
    definitions: &[ScriptExecutionParameter],
    values: &Value,
) -> Result<BTreeMap<String, Value>, CryptoError> {
    validate_parameter_definitions(definitions)?;
    let object = values.as_object().ok_or(CryptoError::InvalidProfile)?;
    let known = definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();
    if object.keys().any(|name| !known.contains(name.as_str())) {
        return Err(CryptoError::InvalidProfile);
    }
    let mut validated = BTreeMap::new();
    for definition in definitions {
        let Some(value) = object.get(&definition.name) else {
            if definition.required {
                return Err(CryptoError::InvalidProfile);
            }
            continue;
        };
        validate_parameter_value(definition, value)?;
        validated.insert(definition.name.clone(), value.clone());
    }
    if canonical_json(&validated)?.len() > MAX_PARAMETERS_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    Ok(validated)
}

pub fn encode_script_execution_parameters(
    definitions: &[ScriptExecutionParameter],
    values: &Value,
) -> Result<SecretBytes, CryptoError> {
    let values = validate_script_execution_parameters(definitions, values)?;
    Ok(SecretBytes::new(canonical_json(&values)?))
}

pub fn open_script_execution_package(
    package: ScriptExecutionEncryptedPackage,
    recipient: &X25519Identity,
    expected: &ExpectedScriptExecutionPackageContext,
) -> Result<OpenedScriptExecutionPackage, CryptoError> {
    validate_transport(&package, expected)?;
    verify_package_producer(&package, expected)?;
    let public_key = recipient.public_key();
    let recipient_fingerprint = compute_key_fingerprint(public_key, RecipientKeyKind::AgentX25519);
    let encoded_fingerprint = URL_SAFE_NO_PAD.encode(recipient_fingerprint);
    if encoded_fingerprint != package.recipient_agent_key_fingerprint {
        return Err(CryptoError::AuthenticationFailed);
    }
    let aad = transport_aad(&package)?;
    let mut hash = Sha256::new();
    hash.update(TRANSPORT_AAD_DOMAIN);
    hash.update(&aad);
    let parent_descriptor_hash: [u8; 32] = hash.finalize().into();
    let context = WrapperContext {
        protocol_version: PROTOCOL_VERSION,
        wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
        purpose: WrapperPurpose::ScriptExecutionDek,
        scope: EnvelopeScope {
            organization_id: uuid_bytes(&package.organization_id)?,
            vault_id: uuid_bytes(&package.vault_id)?,
            entry_id: Some(uuid_bytes(&package.script_entry_id)?),
            grant_or_request_id: Some(uuid_bytes(&package.grant_id)?),
            agent_id: Some(uuid_bytes(&package.agent_id)?),
            member_id: None,
        },
        resource_revision: revision(&package.package_revision)?,
        wrapped_key_version: 1,
        member_key_generation: None,
        recipient_key_kind: RecipientKeyKind::AgentX25519,
        recipient_key_version: package.recipient_agent_key_version,
        recipient_fingerprint,
        parent_descriptor_hash: Some(parent_descriptor_hash),
    };

    let mut container_bytes =
        Zeroizing::new(decode_base64url(&package.encoded_package_ciphertext)?);
    if container_bytes.is_empty() || container_bytes.len() > MAX_PACKAGE_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    let container: ScriptExecutionCiphertextContainer = parse_canonical(&container_bytes)?;
    if container.schema != "palladin.script-execution-package-ciphertext.v1"
        || container.contract_version != CONTRACT_VERSION
        || container.package_revision != package.package_revision
    {
        return Err(CryptoError::InvalidProfile);
    }
    let sealed =
        SealedWrappedKey::from_bytes(decode_base64url(&container.encoded_sealed_package_dek)?)?;
    let package_dek = X25519SealedBoxSuite::unwrap(&sealed, recipient, &context)?;
    let suite_payload =
        EncodedSuitePayload::from_bytes(decode_base64url(&container.encoded_suite_payload)?)?;
    let plaintext = XChaChaVaultSuite::open(&package_dek, &suite_payload, &aad)?;
    container_bytes.zeroize();
    let payload: ScriptExecutionPayload = parse_canonical(plaintext.expose_secret())?;
    validate_opened(&package, &payload)?;

    let entries = payload
        .entries
        .iter()
        .map(|entry| {
            let encoded = decode_base64url(&entry.encoded_grant_payload)?;
            grant_payload_field_ids(&encoded)?;
            Ok(OpenedScriptExecutionReference {
                entry_id: entry.entry_id.clone(),
                entry_revision: entry.entry_revision.clone(),
                encoded_grant_payload: SecretBytes::new(encoded),
            })
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;
    Ok(OpenedScriptExecutionPackage {
        binding: payload.binding,
        manifest: payload.manifest,
        entries,
    })
}

fn validate_transport(
    package: &ScriptExecutionEncryptedPackage,
    expected: &ExpectedScriptExecutionPackageContext,
) -> Result<(), CryptoError> {
    if package.contract_version != CONTRACT_VERSION
        || package.organization_id != expected.organization_id
        || package.vault_id != expected.vault_id
        || package.grant_id != expected.grant_id
        || package.agent_id != expected.agent_id
        || package.agent_access_epoch != expected.agent_access_epoch
        || package.script_entry_id != expected.script_entry_id
        || package.script_revision != expected.script_revision
        || package.package_revision != expected.package_revision
        || package.recipient_agent_key_version != expected.recipient_agent_key_version
        || package.vault_signing_key_version != expected.vault_signing_key_version
        || package.vault_signing_key_fingerprint != expected.vault_signing_key_fingerprint
        || package.agent_access_epoch == 0
        || package.recipient_agent_key_version == 0
        || package.vault_signing_key_version == 0
        || revision(&package.script_revision).is_err()
        || revision(&package.package_revision).is_err()
        || uuid_bytes(&package.organization_id).is_err()
        || uuid_bytes(&package.vault_id).is_err()
        || uuid_bytes(&package.grant_id).is_err()
        || uuid_bytes(&package.agent_id).is_err()
        || uuid_bytes(&package.script_entry_id).is_err()
        || decode_digest(&package.recipient_agent_key_fingerprint).is_err()
        || decode_digest(&package.vault_signing_key_fingerprint).is_err()
        || decode_digest(&package.manifest_digest).is_err()
        || !matches!(
            decode_base64url(&package.producer_signature),
            Ok(signature) if signature.len() == 64
        )
        || package.scopes.is_empty()
        || package.scopes.len() > MAX_REFERENCE_COUNT + 1
    {
        return Err(CryptoError::InvalidProfile);
    }
    let mut scopes = BTreeSet::new();
    let mut script_count = 0;
    for scope in &package.scopes {
        if !scopes.insert(&scope.entry_id)
            || uuid_bytes(&scope.entry_id).is_err()
            || revision(&scope.entry_revision).is_err()
        {
            return Err(CryptoError::InvalidProfile);
        }
        if scope.is_script {
            script_count += 1;
            if scope.entry_id != package.script_entry_id
                || scope.entry_revision != package.script_revision
            {
                return Err(CryptoError::InvalidProfile);
            }
        }
    }
    if script_count != 1 {
        return Err(CryptoError::InvalidProfile);
    }
    Ok(())
}

fn verify_package_producer(
    package: &ScriptExecutionEncryptedPackage,
    expected: &ExpectedScriptExecutionPackageContext,
) -> Result<(), CryptoError> {
    let fingerprint = compute_key_fingerprint(
        &expected.vault_signing_public_key,
        RecipientKeyKind::VaultSigningEd25519,
    );
    if URL_SAFE_NO_PAD.encode(fingerprint) != expected.vault_signing_key_fingerprint {
        return Err(CryptoError::AuthenticationFailed);
    }
    let unsigned = canonical_json(&ScriptExecutionUnsignedPackage {
        contract_version: package.contract_version,
        organization_id: &package.organization_id,
        vault_id: &package.vault_id,
        grant_id: &package.grant_id,
        agent_id: &package.agent_id,
        agent_access_epoch: package.agent_access_epoch,
        script_entry_id: &package.script_entry_id,
        script_revision: &package.script_revision,
        package_revision: &package.package_revision,
        recipient_agent_key_version: package.recipient_agent_key_version,
        recipient_agent_key_fingerprint: &package.recipient_agent_key_fingerprint,
        vault_signing_key_version: package.vault_signing_key_version,
        vault_signing_key_fingerprint: &package.vault_signing_key_fingerprint,
        manifest_digest: &package.manifest_digest,
        scopes: &package.scopes,
        encoded_package_ciphertext: &package.encoded_package_ciphertext,
    })?;
    let signature = Zeroizing::new(decode_base64url(&package.producer_signature)?);
    verify_domain_signature(
        SignatureProfile::ScriptExecutionPackage,
        PROTOCOL_VERSION,
        &unsigned,
        &expected.vault_signing_public_key,
        &signature,
    )
}

fn grant_payload_field_ids(encoded: &[u8]) -> Result<BTreeSet<String>, CryptoError> {
    let text = std::str::from_utf8(encoded).map_err(|_| CryptoError::InvalidEncoding)?;
    let value = ScriptExecutionSensitiveJson(
        serde_json::from_str(text).map_err(|_| CryptoError::InvalidEncoding)?,
    );
    let canonical = Zeroizing::new(canonical_json(&value.0)?);
    if canonical.as_slice() != encoded {
        return Err(CryptoError::InvalidEncoding);
    }
    let object = value.0.as_object().ok_or(CryptoError::InvalidEncoding)?;
    let fields = object
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(CryptoError::InvalidEncoding)?;
    if object.len() != 3
        || object.get("schema").and_then(Value::as_str) != Some("palladin.grant-payload.v1")
        || !matches!(
            object.get("entryType").and_then(Value::as_str),
            Some("key" | "credential" | "script" | "creditCard")
        )
        || fields.is_empty()
    {
        return Err(CryptoError::InvalidProfile);
    }
    let mut previous = None::<&str>;
    let mut field_ids = BTreeSet::new();
    for field in fields {
        let field = field.as_object().ok_or(CryptoError::InvalidEncoding)?;
        let id = field
            .get("id")
            .and_then(Value::as_str)
            .ok_or(CryptoError::InvalidEncoding)?;
        if field.len() != 4
            || !field.contains_key("kind")
            || !field.contains_key("mode")
            || !field.contains_key("value")
            || id.is_empty()
            || previous.is_some_and(|current| current >= id)
        {
            return Err(CryptoError::InvalidProfile);
        }
        previous = Some(id);
        field_ids.insert(id.to_owned());
    }
    Ok(field_ids)
}

fn validate_opened(
    transport: &ScriptExecutionEncryptedPackage,
    payload: &ScriptExecutionPayload,
) -> Result<(), CryptoError> {
    let manifest = &payload.manifest;
    let binding = &payload.binding;
    validate_manifest(manifest)?;
    if payload.schema != "palladin.script-execution-package-payload.v1"
        || binding.schema != "palladin.script-execution-package-binding.v1"
        || binding.contract_version != CONTRACT_VERSION
        || binding.organization_id != manifest.organization_id
        || binding.agent_id != manifest.agent_id
        || binding.agent_access_epoch != manifest.agent_access_epoch
        || binding.vault_id != manifest.vault_id
        || binding.script_entry_id != manifest.script_entry_id
        || binding.script_revision != manifest.script_revision
        || transport.organization_id != manifest.organization_id
        || transport.agent_id != manifest.agent_id
        || transport.agent_access_epoch != manifest.agent_access_epoch
        || transport.vault_id != manifest.vault_id
        || transport.script_entry_id != manifest.script_entry_id
        || transport.script_revision != manifest.script_revision
        || transport.manifest_digest != binding.manifest_digest
        || !matches!(
            &binding.authorization,
            ScriptExecutionAuthorization::ScriptExecution { grant_id }
                if grant_id == &transport.grant_id
        )
    {
        return Err(CryptoError::InvalidProfile);
    }
    let digest = manifest_digest(manifest)?;
    if binding.manifest_digest != digest {
        return Err(CryptoError::AuthenticationFailed);
    }

    let mut expected_scopes = vec![ScriptExecutionScope {
        vault_id: manifest.vault_id.clone(),
        entry_id: manifest.script_entry_id.clone(),
        field_id: "script.source".to_owned(),
        entry_revision: manifest.script_revision.clone(),
    }];
    expected_scopes.extend(
        manifest
            .references
            .iter()
            .map(|reference| ScriptExecutionScope {
                vault_id: reference.vault_id.clone(),
                entry_id: reference.entry_id.clone(),
                field_id: reference.field_id.clone(),
                entry_revision: reference.entry_revision.clone(),
            }),
    );
    expected_scopes.sort();
    let mut actual_scopes = binding.scopes.clone();
    actual_scopes.sort();
    if expected_scopes != actual_scopes {
        return Err(CryptoError::AuthenticationFailed);
    }

    let mut expected_entries = BTreeMap::new();
    for reference in &manifest.references {
        if let Some(current) =
            expected_entries.insert(&reference.entry_id, &reference.entry_revision)
            && current != &reference.entry_revision
        {
            return Err(CryptoError::InvalidProfile);
        }
    }
    let actual_entries = payload
        .entries
        .iter()
        .map(|entry| (&entry.entry_id, &entry.entry_revision))
        .collect::<BTreeMap<_, _>>();
    if expected_entries.len() != payload.entries.len() || expected_entries != actual_entries {
        return Err(CryptoError::AuthenticationFailed);
    }
    for entry in &payload.entries {
        let encoded = Zeroizing::new(decode_base64url(&entry.encoded_grant_payload)?);
        let actual_fields = grant_payload_field_ids(&encoded)?;
        let expected_fields = manifest
            .references
            .iter()
            .filter(|reference| reference.entry_id == entry.entry_id)
            .map(|reference| reference.field_id.clone())
            .collect::<BTreeSet<_>>();
        if actual_fields != expected_fields {
            return Err(CryptoError::AuthenticationFailed);
        }
    }

    let structural = structural_scopes(&actual_scopes, &manifest.script_entry_id)?;
    let mut transport_scopes = transport.scopes.clone();
    transport_scopes.sort();
    if structural != transport_scopes {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(())
}

fn validate_manifest(manifest: &ScriptExecutionManifest) -> Result<(), CryptoError> {
    if manifest.schema != "palladin.script-execution-manifest.v1"
        || manifest.contract_version != CONTRACT_VERSION
        || manifest.agent_access_epoch == 0
        || revision(&manifest.script_revision).is_err()
        || uuid_bytes(&manifest.organization_id).is_err()
        || uuid_bytes(&manifest.agent_id).is_err()
        || uuid_bytes(&manifest.vault_id).is_err()
        || uuid_bytes(&manifest.script_entry_id).is_err()
        || manifest.description.trim().is_empty()
        || manifest.description != manifest.description.trim()
        || manifest.description.len() > 4_096
        || !is_nfc(&manifest.description)
        || !matches!(
            manifest.interpreter.as_str(),
            "bash" | "sh" | "node" | "python"
        )
        || !is_nfc(&manifest.script_source)
        || manifest.references.len() > MAX_REFERENCE_COUNT
    {
        return Err(CryptoError::InvalidProfile);
    }
    validate_parameter_definitions(&manifest.parameters)?;
    let mut reference_keys = BTreeSet::new();
    let mut environment_names = BTreeSet::new();
    for reference in &manifest.references {
        let environment = reference.env.to_ascii_uppercase();
        if reference.vault_id != manifest.vault_id
            || reference.entry_id == manifest.script_entry_id
            || uuid_bytes(&reference.entry_id).is_err()
            || revision(&reference.entry_revision).is_err()
            || reference.field_id.is_empty()
            || reference.field_id.len() > 128
            || !is_nfc(&reference.field_id)
            || !valid_name(&reference.env)
            || RESERVED_ENV_NAMES.contains(&environment.as_str())
            || RESERVED_ENV_PREFIXES
                .iter()
                .any(|prefix| environment.starts_with(prefix))
            || !environment_names.insert(environment)
            || !reference_keys.insert((&reference.env, &reference.entry_id, &reference.field_id))
        {
            return Err(CryptoError::InvalidProfile);
        }
    }
    Ok(())
}

fn validate_parameter_definitions(
    definitions: &[ScriptExecutionParameter],
) -> Result<(), CryptoError> {
    if definitions.len() > MAX_PARAMETER_COUNT {
        return Err(CryptoError::InvalidProfile);
    }
    let mut names = BTreeSet::new();
    let mut previous_name = None::<&str>;
    for definition in definitions {
        if !valid_name(&definition.name)
            || !is_nfc(&definition.name)
            || previous_name.is_some_and(|previous| previous >= definition.name.as_str())
            || !names.insert(&definition.name)
            || definition.description.is_empty()
            || definition.description.len() > 1_024
            || !is_nfc(&definition.description)
            || definition
                .minimum
                .as_ref()
                .is_some_and(|value| value.as_f64().is_none())
            || definition
                .maximum
                .as_ref()
                .is_some_and(|value| value.as_f64().is_none())
            || definition
                .minimum
                .as_ref()
                .zip(definition.maximum.as_ref())
                .is_some_and(|(minimum, maximum)| minimum.as_f64() > maximum.as_f64())
            || definition
                .min_length
                .zip(definition.max_length)
                .is_some_and(|(minimum, maximum)| minimum > maximum)
            || definition.min_length.is_some_and(|value| value > 8_192)
            || definition.max_length.is_some_and(|value| value > 8_192)
        {
            return Err(CryptoError::InvalidProfile);
        }
        previous_name = Some(&definition.name);
        match definition.parameter_type {
            ScriptExecutionParameterType::String
                if definition.minimum.is_some() || definition.maximum.is_some() =>
            {
                return Err(CryptoError::InvalidProfile);
            }
            ScriptExecutionParameterType::Integer
            | ScriptExecutionParameterType::Number
            | ScriptExecutionParameterType::Boolean
                if definition.min_length.is_some() || definition.max_length.is_some() =>
            {
                return Err(CryptoError::InvalidProfile);
            }
            ScriptExecutionParameterType::Boolean
                if definition.minimum.is_some() || definition.maximum.is_some() =>
            {
                return Err(CryptoError::InvalidProfile);
            }
            _ => {}
        }
        if let Some(values) = &definition.allowed_values {
            if values.is_empty() || values.len() > 128 {
                return Err(CryptoError::InvalidProfile);
            }
            let mut seen = BTreeSet::new();
            for value in values {
                validate_parameter_value_without_enum(definition, value)?;
                if !seen.insert(canonical_json(value)?) {
                    return Err(CryptoError::InvalidProfile);
                }
            }
        }
    }
    Ok(())
}

fn validate_parameter_value(
    definition: &ScriptExecutionParameter,
    value: &Value,
) -> Result<(), CryptoError> {
    validate_parameter_value_without_enum(definition, value)?;
    if let Some(values) = &definition.allowed_values
        && !values.iter().any(|candidate| candidate == value)
    {
        return Err(CryptoError::InvalidProfile);
    }
    Ok(())
}

fn validate_parameter_value_without_enum(
    definition: &ScriptExecutionParameter,
    value: &Value,
) -> Result<(), CryptoError> {
    match definition.parameter_type {
        ScriptExecutionParameterType::String => {
            let value = value.as_str().ok_or(CryptoError::InvalidProfile)?;
            let length = value.chars().count() as u64;
            if !is_nfc(value)
                || value.len() > 8_192
                || definition
                    .min_length
                    .is_some_and(|minimum| length < minimum)
                || definition
                    .max_length
                    .is_some_and(|maximum| length > maximum)
            {
                return Err(CryptoError::InvalidProfile);
            }
        }
        ScriptExecutionParameterType::Integer => {
            let integer = value
                .as_i64()
                .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()));
            let integer = integer.ok_or(CryptoError::InvalidProfile)? as f64;
            if integer.abs() > 9_007_199_254_740_991_f64
                || definition
                    .minimum
                    .as_ref()
                    .and_then(Number::as_f64)
                    .is_some_and(|minimum| integer < minimum)
                || definition
                    .maximum
                    .as_ref()
                    .and_then(Number::as_f64)
                    .is_some_and(|maximum| integer > maximum)
            {
                return Err(CryptoError::InvalidProfile);
            }
        }
        ScriptExecutionParameterType::Number => {
            let number = value.as_f64().ok_or(CryptoError::InvalidProfile)?;
            if !number.is_finite()
                || definition
                    .minimum
                    .as_ref()
                    .and_then(Number::as_f64)
                    .is_some_and(|minimum| number < minimum)
                || definition
                    .maximum
                    .as_ref()
                    .and_then(Number::as_f64)
                    .is_some_and(|maximum| number > maximum)
            {
                return Err(CryptoError::InvalidProfile);
            }
        }
        ScriptExecutionParameterType::Boolean if !value.is_boolean() => {
            return Err(CryptoError::InvalidProfile);
        }
        ScriptExecutionParameterType::Boolean => {}
    }
    Ok(())
}

fn manifest_digest(manifest: &ScriptExecutionManifest) -> Result<String, CryptoError> {
    let encoded = canonical_json(manifest)?;
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(encoded);
    Ok(URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

fn structural_scopes(
    scopes: &[ScriptExecutionScope],
    script_entry_id: &str,
) -> Result<Vec<ScriptExecutionTransportScope>, CryptoError> {
    let mut entries = BTreeMap::<&str, (&str, bool)>::new();
    for scope in scopes {
        let is_script = scope.entry_id == script_entry_id;
        if let Some((revision, current_is_script)) =
            entries.insert(&scope.entry_id, (&scope.entry_revision, is_script))
            && (revision != scope.entry_revision || current_is_script != is_script)
        {
            return Err(CryptoError::InvalidProfile);
        }
    }
    Ok(entries
        .into_iter()
        .map(
            |(entry_id, (entry_revision, is_script))| ScriptExecutionTransportScope {
                entry_id: entry_id.to_owned(),
                entry_revision: entry_revision.to_owned(),
                is_script,
            },
        )
        .collect())
}

fn transport_aad(
    package: &ScriptExecutionEncryptedPackage,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    canonical_json(&ScriptExecutionTransportBinding {
        contract_version: package.contract_version,
        organization_id: &package.organization_id,
        vault_id: &package.vault_id,
        grant_id: &package.grant_id,
        agent_id: &package.agent_id,
        agent_access_epoch: package.agent_access_epoch,
        script_entry_id: &package.script_entry_id,
        script_revision: &package.script_revision,
        package_revision: &package.package_revision,
        recipient_agent_key_version: package.recipient_agent_key_version,
        recipient_agent_key_fingerprint: &package.recipient_agent_key_fingerprint,
        vault_signing_key_version: package.vault_signing_key_version,
        vault_signing_key_fingerprint: &package.vault_signing_key_fingerprint,
        manifest_digest: &package.manifest_digest,
        scopes: &package.scopes,
    })
    .map(Zeroizing::new)
}

fn parse_canonical<T>(bytes: &[u8]) -> Result<T, CryptoError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let text = std::str::from_utf8(bytes).map_err(|_| CryptoError::InvalidEncoding)?;
    let value: T = serde_json::from_str(text).map_err(|_| CryptoError::InvalidEncoding)?;
    let encoded = canonical_json(&value)?;
    if encoded != bytes {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(value)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    serde_jcs::to_vec(value).map_err(|_| CryptoError::InvalidEncoding)
}

fn uuid_bytes(value: &str) -> Result<[u8; 16], CryptoError> {
    let uuid = Uuid::parse_str(value).map_err(|_| CryptoError::InvalidProfile)?;
    Ok(*uuid.as_bytes())
}

fn revision(value: &str) -> Result<u64, CryptoError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(CryptoError::InvalidProfile);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|revision| *revision > 0)
        .ok_or(CryptoError::InvalidProfile)
}

fn decode_digest(value: &str) -> Result<[u8; 32], CryptoError> {
    decode_base64url(value)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)
}

fn valid_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn is_nfc(value: &str) -> bool {
    value.nfc().eq(value.chars())
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
    use secrecy::SecretBox;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::{
        ExpectedScriptExecutionPackageContext, MANIFEST_DOMAIN, ScriptExecutionAuthorization,
        ScriptExecutionBinding, ScriptExecutionCiphertextContainer,
        ScriptExecutionEncryptedPackage, ScriptExecutionEntry, ScriptExecutionManifest,
        ScriptExecutionMetadata, ScriptExecutionParameter, ScriptExecutionPayload,
        ScriptExecutionReference, ScriptExecutionScope, ScriptExecutionTransportScope,
        ScriptExecutionUnsignedPackage, TRANSPORT_AAD_DOMAIN, canonical_json,
        encode_script_execution_parameters, open_script_execution_package, transport_aad,
        validate_script_execution_parameters,
    };
    use crate::{
        Ed25519Identity, EnvelopeScope, RecipientKeyKind, WrapperContext, WrapperPurpose,
        X25519_WRAPPER_V1, X25519Identity, X25519SealedBoxSuite, XChaChaVaultSuite,
        compute_key_fingerprint,
    };
    fn definitions() -> Vec<ScriptExecutionParameter> {
        serde_json::from_value(json!([
            {
                "name": "activeOnly",
                "description": "Return active users only.",
                "type": "boolean",
                "required": true
            },
            {
                "name": "limit",
                "description": "Maximum number of users.",
                "type": "integer",
                "required": true,
                "minimum": 1,
                "maximum": 100
            },
            {
                "name": "role",
                "description": "Optional role filter.",
                "type": "string",
                "required": false,
                "enum": ["admin", "member", "viewer"]
            }
        ]))
        .expect("parameter definitions")
    }

    #[test]
    fn typed_parameters_match_the_typescript_canonical_stdin_frame() {
        let definitions = definitions();
        let encoded = encode_script_execution_parameters(
            &definitions,
            &json!({"role":"member","limit":25,"activeOnly":true}),
        )
        .expect("parameters");
        assert_eq!(
            encoded.expose_for_crypto_operation(),
            br#"{"activeOnly":true,"limit":25,"role":"member"}"#
        );
        assert!(
            validate_script_execution_parameters(
                &definitions,
                &json!({"activeOnly":true,"limit":25,"debug":true})
            )
            .is_err()
        );
        assert!(
            validate_script_execution_parameters(
                &definitions,
                &json!({"activeOnly":true,"limit":"25"})
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_requires_strict_parameter_order_and_preserves_integer_constraints() {
        let definitions = definitions();
        let metadata = ScriptExecutionMetadata {
            contract_version: 1,
            description: "Returns users.".to_owned(),
            parameters: definitions.clone(),
            return_result_to_agent: Some(true),
        };
        metadata.validate().expect("sorted metadata");
        let encoded = canonical_json(&metadata).expect("canonical metadata");
        let text = std::str::from_utf8(&encoded).expect("UTF-8");
        assert!(text.contains(r#""minimum":1"#));
        assert!(!text.contains(r#""minimum":1.0"#));

        let mut unsorted = definitions;
        unsorted.swap(0, 1);
        assert!(
            ScriptExecutionMetadata {
                contract_version: 1,
                description: "Returns users.".to_owned(),
                parameters: unsorted,
                return_result_to_agent: Some(true),
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn jcs_number_rendering_matches_ecmascript_for_large_finite_values() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"magnitude":100000000000000000000}"#).expect("JSON number");
        assert_eq!(
            canonical_json(&value).expect("JCS"),
            br#"{"magnitude":100000000000000000000}"#
        );
    }

    #[test]
    fn direct_package_round_trip_binds_the_complete_script_and_reference_set() {
        const ORGANIZATION_ID: &str = "11111111-1111-4111-8111-111111111111";
        const VAULT_ID: &str = "22222222-2222-4222-8222-222222222222";
        const SCRIPT_ID: &str = "33333333-3333-4333-8333-333333333333";
        const REFERENCE_ID: &str = "44444444-4444-4444-8444-444444444444";
        const GRANT_ID: &str = "55555555-5555-4555-8555-555555555555";
        const AGENT_ID: &str = "66666666-6666-4666-8666-666666666666";

        let recipient = X25519Identity::from_private_bytes(vec![7; 32]).expect("recipient");
        let signer = Ed25519Identity::from_seed(vec![9; 32]).expect("Vault signer");
        let recipient_fingerprint =
            compute_key_fingerprint(recipient.public_key(), RecipientKeyKind::AgentX25519);
        let signer_fingerprint =
            compute_key_fingerprint(signer.public_key(), RecipientKeyKind::VaultSigningEd25519);
        let manifest = ScriptExecutionManifest {
            schema: "palladin.script-execution-manifest.v1".to_owned(),
            contract_version: 1,
            organization_id: ORGANIZATION_ID.to_owned(),
            agent_id: AGENT_ID.to_owned(),
            agent_access_epoch: 3,
            vault_id: VAULT_ID.to_owned(),
            script_entry_id: SCRIPT_ID.to_owned(),
            script_revision: "7".to_owned(),
            description: "Returns a safe aggregate.".to_owned(),
            parameters: Vec::new(),
            return_result_to_agent: true,
            interpreter: "sh".to_owned(),
            script_source: "printf safe".to_owned(),
            references: vec![ScriptExecutionReference {
                env: "API_TOKEN".to_owned(),
                vault_id: VAULT_ID.to_owned(),
                entry_id: REFERENCE_ID.to_owned(),
                field_id: "key.value".to_owned(),
                entry_revision: "4".to_owned(),
            }],
        };
        let manifest_bytes = canonical_json(&manifest).expect("manifest");
        let mut digest = Sha256::new();
        digest.update(MANIFEST_DOMAIN);
        digest.update(&manifest_bytes);
        let manifest_digest = URL_SAFE_NO_PAD.encode(digest.finalize());
        let scopes = vec![
            ScriptExecutionScope {
                vault_id: VAULT_ID.to_owned(),
                entry_id: SCRIPT_ID.to_owned(),
                field_id: "script.source".to_owned(),
                entry_revision: "7".to_owned(),
            },
            ScriptExecutionScope {
                vault_id: VAULT_ID.to_owned(),
                entry_id: REFERENCE_ID.to_owned(),
                field_id: "key.value".to_owned(),
                entry_revision: "4".to_owned(),
            },
        ];
        let binding = ScriptExecutionBinding {
            schema: "palladin.script-execution-package-binding.v1".to_owned(),
            contract_version: 1,
            organization_id: ORGANIZATION_ID.to_owned(),
            agent_id: AGENT_ID.to_owned(),
            agent_access_epoch: 3,
            vault_id: VAULT_ID.to_owned(),
            script_entry_id: SCRIPT_ID.to_owned(),
            script_revision: "7".to_owned(),
            manifest_digest: manifest_digest.clone(),
            authorization: ScriptExecutionAuthorization::ScriptExecution {
                grant_id: GRANT_ID.to_owned(),
            },
            scopes,
        };
        let grant_payload = canonical_json(&json!({
            "schema": "palladin.grant-payload.v1",
            "entryType": "key",
            "fields": [{
                "id": "key.value",
                "kind": "concealed",
                "mode": "value",
                "value": "fixture-secret-never-production"
            }]
        }))
        .expect("GrantPayload");
        let payload = ScriptExecutionPayload {
            schema: "palladin.script-execution-package-payload.v1".to_owned(),
            binding,
            manifest,
            entries: vec![ScriptExecutionEntry {
                entry_id: REFERENCE_ID.to_owned(),
                entry_revision: "4".to_owned(),
                encoded_grant_payload: URL_SAFE_NO_PAD.encode(grant_payload),
            }],
        };
        let plaintext = canonical_json(&payload).expect("package plaintext");
        let package_key = SecretBox::new(Box::new([0x42; 32]));
        let mut package = ScriptExecutionEncryptedPackage {
            contract_version: 1,
            organization_id: ORGANIZATION_ID.to_owned(),
            vault_id: VAULT_ID.to_owned(),
            grant_id: GRANT_ID.to_owned(),
            agent_id: AGENT_ID.to_owned(),
            agent_access_epoch: 3,
            script_entry_id: SCRIPT_ID.to_owned(),
            script_revision: "7".to_owned(),
            package_revision: "8".to_owned(),
            recipient_agent_key_version: 2,
            recipient_agent_key_fingerprint: URL_SAFE_NO_PAD.encode(recipient_fingerprint),
            vault_signing_key_version: 5,
            vault_signing_key_fingerprint: URL_SAFE_NO_PAD.encode(signer_fingerprint),
            manifest_digest,
            scopes: vec![
                ScriptExecutionTransportScope {
                    entry_id: SCRIPT_ID.to_owned(),
                    entry_revision: "7".to_owned(),
                    is_script: true,
                },
                ScriptExecutionTransportScope {
                    entry_id: REFERENCE_ID.to_owned(),
                    entry_revision: "4".to_owned(),
                    is_script: false,
                },
            ],
            encoded_package_ciphertext: String::new(),
            producer_signature: String::new(),
        };
        let aad = transport_aad(&package).expect("transport AAD");
        let suite_payload =
            XChaChaVaultSuite::seal(&package_key, &plaintext, &aad).expect("package payload");
        let mut parent_hash = Sha256::new();
        parent_hash.update(TRANSPORT_AAD_DOMAIN);
        parent_hash.update(&aad);
        let wrapped = X25519SealedBoxSuite::wrap(
            &package_key,
            *recipient.public_key(),
            &WrapperContext {
                protocol_version: 2,
                wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
                purpose: WrapperPurpose::ScriptExecutionDek,
                scope: EnvelopeScope {
                    organization_id: uuid::Uuid::parse_str(ORGANIZATION_ID)
                        .expect("organization")
                        .into_bytes(),
                    vault_id: uuid::Uuid::parse_str(VAULT_ID).expect("vault").into_bytes(),
                    entry_id: Some(
                        uuid::Uuid::parse_str(SCRIPT_ID)
                            .expect("script")
                            .into_bytes(),
                    ),
                    grant_or_request_id: Some(
                        uuid::Uuid::parse_str(GRANT_ID).expect("grant").into_bytes(),
                    ),
                    agent_id: Some(uuid::Uuid::parse_str(AGENT_ID).expect("agent").into_bytes()),
                    member_id: None,
                },
                resource_revision: 8,
                wrapped_key_version: 1,
                member_key_generation: None,
                recipient_key_kind: RecipientKeyKind::AgentX25519,
                recipient_key_version: 2,
                recipient_fingerprint,
                parent_descriptor_hash: Some(parent_hash.finalize().into()),
            },
        )
        .expect("wrapped package key");
        let container = ScriptExecutionCiphertextContainer {
            schema: "palladin.script-execution-package-ciphertext.v1".to_owned(),
            contract_version: 1,
            package_revision: "8".to_owned(),
            encoded_sealed_package_dek: URL_SAFE_NO_PAD.encode(wrapped.as_bytes()),
            encoded_suite_payload: URL_SAFE_NO_PAD.encode(suite_payload.as_bytes()),
        };
        package.encoded_package_ciphertext =
            URL_SAFE_NO_PAD.encode(canonical_json(&container).expect("container"));
        let unsigned = canonical_json(&ScriptExecutionUnsignedPackage {
            contract_version: package.contract_version,
            organization_id: &package.organization_id,
            vault_id: &package.vault_id,
            grant_id: &package.grant_id,
            agent_id: &package.agent_id,
            agent_access_epoch: package.agent_access_epoch,
            script_entry_id: &package.script_entry_id,
            script_revision: &package.script_revision,
            package_revision: &package.package_revision,
            recipient_agent_key_version: package.recipient_agent_key_version,
            recipient_agent_key_fingerprint: &package.recipient_agent_key_fingerprint,
            vault_signing_key_version: package.vault_signing_key_version,
            vault_signing_key_fingerprint: &package.vault_signing_key_fingerprint,
            manifest_digest: &package.manifest_digest,
            scopes: &package.scopes,
            encoded_package_ciphertext: &package.encoded_package_ciphertext,
        })
        .expect("unsigned package");
        let mut signature_input = b"PLDNV2SIG:SCRIPT-EXECUTION-PACKAGE:".to_vec();
        signature_input.extend_from_slice(&2_u16.to_be_bytes());
        signature_input.extend_from_slice(&unsigned);
        package.producer_signature = URL_SAFE_NO_PAD.encode(signer.sign(&signature_input));

        let mut tampered = package.clone();
        tampered.encoded_package_ciphertext.push('A');
        assert!(
            open_script_execution_package(
                tampered,
                &recipient,
                &ExpectedScriptExecutionPackageContext {
                    organization_id: ORGANIZATION_ID.to_owned(),
                    vault_id: VAULT_ID.to_owned(),
                    grant_id: GRANT_ID.to_owned(),
                    agent_id: AGENT_ID.to_owned(),
                    agent_access_epoch: 3,
                    script_entry_id: SCRIPT_ID.to_owned(),
                    script_revision: "7".to_owned(),
                    package_revision: "8".to_owned(),
                    recipient_agent_key_version: 2,
                    vault_signing_key_version: 5,
                    vault_signing_key_fingerprint: URL_SAFE_NO_PAD.encode(signer_fingerprint),
                    vault_signing_public_key: *signer.public_key(),
                },
            )
            .is_err()
        );
        assert!(
            open_script_execution_package(
                package.clone(),
                &recipient,
                &ExpectedScriptExecutionPackageContext {
                    organization_id: ORGANIZATION_ID.to_owned(),
                    vault_id: VAULT_ID.to_owned(),
                    grant_id: GRANT_ID.to_owned(),
                    agent_id: AGENT_ID.to_owned(),
                    agent_access_epoch: 3,
                    script_entry_id: SCRIPT_ID.to_owned(),
                    script_revision: "7".to_owned(),
                    package_revision: "9".to_owned(),
                    recipient_agent_key_version: 2,
                    vault_signing_key_version: 5,
                    vault_signing_key_fingerprint: URL_SAFE_NO_PAD.encode(signer_fingerprint),
                    vault_signing_public_key: *signer.public_key(),
                },
            )
            .is_err(),
            "a package from another expected revision must be rejected before decryption"
        );

        let opened = open_script_execution_package(
            package,
            &recipient,
            &ExpectedScriptExecutionPackageContext {
                organization_id: ORGANIZATION_ID.to_owned(),
                vault_id: VAULT_ID.to_owned(),
                grant_id: GRANT_ID.to_owned(),
                agent_id: AGENT_ID.to_owned(),
                agent_access_epoch: 3,
                script_entry_id: SCRIPT_ID.to_owned(),
                script_revision: "7".to_owned(),
                package_revision: "8".to_owned(),
                recipient_agent_key_version: 2,
                vault_signing_key_version: 5,
                vault_signing_key_fingerprint: URL_SAFE_NO_PAD.encode(signer_fingerprint),
                vault_signing_public_key: *signer.public_key(),
            },
        )
        .expect("opened package");
        assert_eq!(opened.manifest.script_source, "printf safe");
        assert_eq!(opened.entries.len(), 1);
        assert_eq!(opened.entries[0].entry_id, REFERENCE_ID);
        assert_eq!(
            opened.entries[0]
                .encoded_grant_payload
                .expose_for_crypto_operation(),
            br#"{"entryType":"key","fields":[{"id":"key.value","kind":"concealed","mode":"value","value":"fixture-secret-never-production"}],"schema":"palladin.grant-payload.v1"}"#
        );
    }
}
