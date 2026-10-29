//! Agent Entry Submission v1 (`palladin-agent-submission`).
//!
//! An Agent proposes a new Entry, or a new revision of an Entry it is granted, without the
//! backend or the operator seeing the secret. A fresh per-submission DEK encrypts the payload
//! under an identity-bound AAD and is sealed once for the authoring Agent and once for the
//! organization approver group, whose key is pinned through a signed, rotation-continuous
//! manifest chain.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use secrecy::{ExposeSecret, SecretBox, SecretSlice, SecretString};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::suite::WrapperOpenError;
use crate::{
    DecryptedCredential, Ed25519Identity, EnvelopeScope, PROTOCOL_VERSION, RecipientKeyKind,
    SealedWrappedKey, SignatureProfile, WrapperContext, WrapperPurpose, X25519_WRAPPER_V1,
    X25519Identity, X25519SealedBoxSuite, compute_key_fingerprint, verify_domain_signature,
};

const CONTRACT_VERSION: u64 = 1;
const SUBMISSION_SCHEMA: &str = "palladin.agent-entry-submission.v1";
const PAYLOAD_SCHEMA: &str = "palladin.agent-submission-payload.v1";
const MANIFEST_SCHEMA: &str = "palladin.organization-approver-manifest.v1";
const PAYLOAD_AAD_PREFIX: &[u8] = b"PLDNSUB1AAD";
const IDENTITY_HASH_PREFIX: &[u8] = b"PLDNSUB1ID";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;

const LABEL_MAX_BYTES: usize = 256;
const USERNAME_MAX_BYTES: usize = 1024;
const PASSWORD_MAX_BYTES: usize = 4096;
const KEY_VALUE_MAX_BYTES: usize = 16_384;
const URL_MAX_BYTES: usize = 2048;
const NOTES_MAX_BYTES: usize = 8192;
const PAYLOAD_PLAINTEXT_MAX_BYTES: usize = 32_768;
const MAX_ENCODED_PAYLOAD_BYTES: usize = PAYLOAD_PLAINTEXT_MAX_BYTES + NONCE_BYTES + TAG_BYTES;

const TRANSPORT_FIELDS: [&str; 20] = [
    "schema",
    "contractVersion",
    "protocolVersion",
    "organizationId",
    "submissionId",
    "agentId",
    "submissionKind",
    "entryType",
    "target",
    "submissionRevision",
    "agentAccessEpoch",
    "agentKeyVersion",
    "agentKeyFingerprint",
    "approverKeyVersion",
    "approverMessageKeyFingerprint",
    "approverManifestRevision",
    "encodedPayload",
    "encodedAgentWrappedDek",
    "encodedApproverWrappedDek",
    "agentSignature",
];
const MANIFEST_REQUIRED_FIELDS: [&str; 14] = [
    "schema",
    "contractVersion",
    "protocolVersion",
    "organizationId",
    "keyVersion",
    "manifestRevision",
    "approverSetRevision",
    "approverSetDigest",
    "messagePublicKey",
    "messageKeyFingerprint",
    "signingPublicKey",
    "signingKeyFingerprint",
    "issuedAt",
    "signature",
];
const MANIFEST_CONDITIONAL_FIELDS: [&str; 2] =
    ["continuitySignature", "previousSigningKeyFingerprint"];
const SIGNATURE_FIELDS: [&str; 3] = ["signature", "continuitySignature", "agentSignature"];

/// Contract error codes. Every variant is value-free and safe to show to an operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubmissionError {
    #[error("submission has an invalid encoding")]
    InvalidEncoding,
    #[error("submission has an unknown field")]
    UnknownField,
    #[error("submission is missing a required field")]
    MissingField,
    #[error("submission target is invalid")]
    InvalidTarget,
    #[error("submission entry type is not supported")]
    UnsupportedEntryType,
    #[error("submission contract version is not supported")]
    UnsupportedContract,
    #[error("submission input is invalid")]
    InvalidInput,
    #[error("submission Agent signature is invalid")]
    InvalidAgentSignature,
    #[error("submission organization or Agent does not match the authenticated context")]
    ContextMismatch,
    #[error("submission recipient key does not match the trusted key")]
    RecipientKeyMismatch,
    #[error("submission key wrapper could not be opened")]
    WrapperOpenFailed,
    #[error("submission key wrapper context does not match")]
    WrapperContextMismatch,
    #[error("submission payload authentication failed")]
    PayloadAuthFailed,
    #[error("submission inner identity does not match its envelope")]
    IdentityMismatch,
    #[error("approver manifest belongs to another organization")]
    ManifestOrganizationMismatch,
    #[error("approver manifest key fingerprint does not match")]
    ManifestFingerprintMismatch,
    #[error("approver manifest signature is invalid")]
    ManifestSignatureInvalid,
    #[error("approver manifest rotation continuity is invalid")]
    ManifestContinuityInvalid,
    #[error("approver manifest skips a key version")]
    ManifestKeyVersionSkip,
    #[error("approver manifest revision does not advance")]
    ManifestRollback,
    #[error("submission re-wrap does not advance the revision by one")]
    RevisionReplay,
    #[error("submission re-wrap changed the encrypted payload or identity")]
    RewrapChangedPayload,
    #[error("cryptographic random generation failed")]
    RandomGenerationFailed,
}

impl SubmissionError {
    /// The exact error code used by the contract conformance vectors.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncoding => "invalid-encoding",
            Self::UnknownField => "unknown-field",
            Self::MissingField => "missing-field",
            Self::InvalidTarget => "invalid-target",
            Self::UnsupportedEntryType => "unsupported-entry-type",
            Self::UnsupportedContract => "unsupported-contract",
            Self::InvalidInput => "invalid-input",
            Self::InvalidAgentSignature => "invalid-agent-signature",
            Self::ContextMismatch => "context-mismatch",
            Self::RecipientKeyMismatch => "recipient-key-mismatch",
            Self::WrapperOpenFailed => "wrapper-open-failed",
            Self::WrapperContextMismatch => "wrapper-context-mismatch",
            Self::PayloadAuthFailed => "payload-auth-failed",
            Self::IdentityMismatch => "identity-mismatch",
            Self::ManifestOrganizationMismatch => "manifest-organization-mismatch",
            Self::ManifestFingerprintMismatch => "manifest-fingerprint-mismatch",
            Self::ManifestSignatureInvalid => "manifest-signature-invalid",
            Self::ManifestContinuityInvalid => "manifest-continuity-invalid",
            Self::ManifestKeyVersionSkip => "manifest-key-version-skip",
            Self::ManifestRollback => "manifest-rollback",
            Self::RevisionReplay => "revision-replay",
            Self::RewrapChangedPayload => "rewrap-changed-payload",
            Self::RandomGenerationFailed => "random-generation-failed",
        }
    }

    /// Whether the error means the approver key chain cannot be trusted.
    #[must_use]
    pub const fn is_untrusted_approver_key(self) -> bool {
        matches!(
            self,
            Self::ManifestOrganizationMismatch
                | Self::ManifestFingerprintMismatch
                | Self::ManifestSignatureInvalid
                | Self::ManifestContinuityInvalid
                | Self::ManifestKeyVersionSkip
                | Self::ManifestRollback
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionKind {
    New,
    Update,
}

impl SubmissionKind {
    const fn wire(self) -> u64 {
        match self {
            Self::New => 1,
            Self::Update => 2,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Update => "update",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionEntryType {
    Key,
    Credential,
}

impl SubmissionEntryType {
    const fn wire(self) -> u64 {
        match self {
            Self::Key => 0,
            Self::Credential => 1,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Credential => "credential",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionTarget {
    New {
        /// Advisory only; never an authority for recipients or the decision.
        suggested_vault_id: Option<Uuid>,
    },
    Update {
        vault_id: Uuid,
        entry_id: Uuid,
        expected_entry_revision: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionIdentity {
    pub organization_id: Uuid,
    pub submission_id: Uuid,
    pub agent_id: Uuid,
    pub entry_type: SubmissionEntryType,
    pub target: SubmissionTarget,
}

impl SubmissionIdentity {
    #[must_use]
    pub const fn kind(&self) -> SubmissionKind {
        match self.target {
            SubmissionTarget::New { .. } => SubmissionKind::New,
            SubmissionTarget::Update { .. } => SubmissionKind::Update,
        }
    }

    fn to_value(&self) -> Value {
        let target = match &self.target {
            SubmissionTarget::New { suggested_vault_id } => {
                let mut target = Map::new();
                target.insert("kind".into(), json!("new"));
                if let Some(vault_id) = suggested_vault_id {
                    target.insert("suggestedVaultId".into(), json!(vault_id.to_string()));
                }
                Value::Object(target)
            }
            SubmissionTarget::Update {
                vault_id,
                entry_id,
                expected_entry_revision,
            } => json!({
                "kind": "update",
                "vaultId": vault_id.to_string(),
                "entryId": entry_id.to_string(),
                "expectedEntryRevision": expected_entry_revision.to_string(),
            }),
        };
        json!({
            "contractVersion": CONTRACT_VERSION,
            "protocolVersion": PROTOCOL_VERSION,
            "organizationId": self.organization_id.to_string(),
            "submissionId": self.submission_id.to_string(),
            "agentId": self.agent_id.to_string(),
            "submissionKind": self.kind().wire(),
            "entryType": self.entry_type.wire(),
            "target": target,
        })
    }

    /// RFC 8785 bytes of the identity object.
    pub fn canonical(&self) -> Result<Vec<u8>, SubmissionError> {
        canonical_json(&self.to_value())
    }

    pub fn descriptor_hash(&self) -> Result<[u8; 32], SubmissionError> {
        let mut hasher = Sha256::new();
        hasher.update(IDENTITY_HASH_PREFIX);
        hasher.update(self.canonical()?);
        Ok(hasher.finalize().into())
    }

    pub fn payload_aad(&self) -> Result<Vec<u8>, SubmissionError> {
        let mut aad = PAYLOAD_AAD_PREFIX.to_vec();
        aad.extend_from_slice(&self.canonical()?);
        Ok(aad)
    }
}

/// The complete transport object of an `AgentEntrySubmission`.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentEntrySubmission {
    pub identity: SubmissionIdentity,
    pub submission_revision: u64,
    pub agent_access_epoch: u64,
    pub agent_key_version: u32,
    pub agent_key_fingerprint: [u8; 32],
    pub approver_key_version: u32,
    pub approver_message_key_fingerprint: [u8; 32],
    pub approver_manifest_revision: u64,
    encoded_payload: Vec<u8>,
    agent_wrapped_dek: Vec<u8>,
    approver_wrapped_dek: Vec<u8>,
    agent_signature: [u8; 64],
}

impl std::fmt::Debug for AgentEntrySubmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentEntrySubmission")
            .field("submission_id", &self.identity.submission_id)
            .field("kind", &self.identity.kind())
            .field("submission_revision", &self.submission_revision)
            .field("approver_key_version", &self.approver_key_version)
            .finish_non_exhaustive()
    }
}

impl AgentEntrySubmission {
    /// Strictly decodes a transport object: unknown or missing fields, unknown enum values and
    /// non-canonical encodings are rejected before any signature or key is used.
    pub fn from_value(value: &Value) -> Result<Self, SubmissionError> {
        let object = value.as_object().ok_or(SubmissionError::InvalidEncoding)?;
        check_fields(object, &TRANSPORT_FIELDS, &[])?;
        if text(object, "schema")? != SUBMISSION_SCHEMA
            || number(object, "contractVersion")? != CONTRACT_VERSION
            || number(object, "protocolVersion")? != u64::from(PROTOCOL_VERSION)
        {
            return Err(SubmissionError::UnsupportedContract);
        }
        let kind = match number(object, "submissionKind")? {
            1 => SubmissionKind::New,
            2 => SubmissionKind::Update,
            _ => return Err(SubmissionError::InvalidTarget),
        };
        let target_object = object
            .get("target")
            .and_then(Value::as_object)
            .ok_or(SubmissionError::InvalidTarget)?;
        if target_object.get("kind").and_then(Value::as_str) != Some(kind.name()) {
            return Err(SubmissionError::InvalidTarget);
        }
        let entry_type = match number(object, "entryType")? {
            0 => SubmissionEntryType::Key,
            1 => SubmissionEntryType::Credential,
            _ => return Err(SubmissionError::UnsupportedEntryType),
        };
        let target = match kind {
            SubmissionKind::New => {
                check_fields(target_object, &["kind"], &["suggestedVaultId"])?;
                SubmissionTarget::New {
                    suggested_vault_id: target_object
                        .contains_key("suggestedVaultId")
                        .then(|| uuid(target_object, "suggestedVaultId"))
                        .transpose()?,
                }
            }
            SubmissionKind::Update => {
                check_fields(
                    target_object,
                    &["kind", "vaultId", "entryId", "expectedEntryRevision"],
                    &[],
                )?;
                SubmissionTarget::Update {
                    vault_id: uuid(target_object, "vaultId")?,
                    entry_id: uuid(target_object, "entryId")?,
                    expected_entry_revision: decimal(target_object, "expectedEntryRevision")?,
                }
            }
        };
        let submission_revision = decimal(object, "submissionRevision")?;
        if submission_revision == 0 {
            return Err(SubmissionError::InvalidEncoding);
        }
        Ok(Self {
            identity: SubmissionIdentity {
                organization_id: uuid(object, "organizationId")?,
                submission_id: uuid(object, "submissionId")?,
                agent_id: uuid(object, "agentId")?,
                entry_type,
                target,
            },
            submission_revision,
            agent_access_epoch: decimal(object, "agentAccessEpoch")?,
            agent_key_version: number_u32(object, "agentKeyVersion")?,
            agent_key_fingerprint: base64_array(object, "agentKeyFingerprint")?,
            approver_key_version: number_u32(object, "approverKeyVersion")?,
            approver_message_key_fingerprint: base64_array(
                object,
                "approverMessageKeyFingerprint",
            )?,
            approver_manifest_revision: decimal(object, "approverManifestRevision")?,
            encoded_payload: base64_bounded(object, "encodedPayload", MAX_ENCODED_PAYLOAD_BYTES)?,
            agent_wrapped_dek: base64_bounded(object, "encodedAgentWrappedDek", 256)?,
            approver_wrapped_dek: base64_bounded(object, "encodedApproverWrappedDek", 256)?,
            agent_signature: base64_array(object, "agentSignature")?,
        })
    }

    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut value = self.unsigned_value();
        if let Value::Object(object) = &mut value {
            object.insert(
                "agentSignature".into(),
                json!(URL_SAFE_NO_PAD.encode(self.agent_signature)),
            );
        }
        value
    }

    fn unsigned_value(&self) -> Value {
        let mut value = self.identity.to_value();
        let Value::Object(object) = &mut value else {
            unreachable!("identity is always encoded as an object");
        };
        let encode = |bytes: &[u8]| json!(URL_SAFE_NO_PAD.encode(bytes));
        object.insert("schema".into(), json!(SUBMISSION_SCHEMA));
        object.insert(
            "submissionRevision".into(),
            json!(self.submission_revision.to_string()),
        );
        object.insert(
            "agentAccessEpoch".into(),
            json!(self.agent_access_epoch.to_string()),
        );
        object.insert("agentKeyVersion".into(), json!(self.agent_key_version));
        object.insert(
            "agentKeyFingerprint".into(),
            encode(&self.agent_key_fingerprint),
        );
        object.insert(
            "approverKeyVersion".into(),
            json!(self.approver_key_version),
        );
        object.insert(
            "approverMessageKeyFingerprint".into(),
            encode(&self.approver_message_key_fingerprint),
        );
        object.insert(
            "approverManifestRevision".into(),
            json!(self.approver_manifest_revision.to_string()),
        );
        object.insert("encodedPayload".into(), encode(&self.encoded_payload));
        object.insert(
            "encodedAgentWrappedDek".into(),
            encode(&self.agent_wrapped_dek),
        );
        object.insert(
            "encodedApproverWrappedDek".into(),
            encode(&self.approver_wrapped_dek),
        );
        value
    }

    pub fn verify_agent_signature(
        &self,
        agent_signing_public_key: &[u8; 32],
    ) -> Result<(), SubmissionError> {
        let canonical = canonical_json(&self.unsigned_value())?;
        verify_domain_signature(
            SignatureProfile::AgentSubmission,
            PROTOCOL_VERSION,
            &canonical,
            agent_signing_public_key,
            &self.agent_signature,
        )
        .map_err(|_| SubmissionError::InvalidAgentSignature)
    }

    fn wrapper_context(
        &self,
        recipient_key_kind: RecipientKeyKind,
    ) -> Result<WrapperContext, SubmissionError> {
        let (recipient_key_version, recipient_fingerprint) = match recipient_key_kind {
            RecipientKeyKind::AgentX25519 => (self.agent_key_version, self.agent_key_fingerprint),
            _ => (
                self.approver_key_version,
                self.approver_message_key_fingerprint,
            ),
        };
        Ok(WrapperContext {
            protocol_version: PROTOCOL_VERSION,
            wrapper_suite_id: X25519_WRAPPER_V1.to_owned(),
            purpose: WrapperPurpose::SubmissionDek,
            scope: EnvelopeScope {
                organization_id: *self.identity.organization_id.as_bytes(),
                vault_id: [0; 16],
                entry_id: None,
                grant_or_request_id: Some(*self.identity.submission_id.as_bytes()),
                agent_id: Some(*self.identity.agent_id.as_bytes()),
                member_id: None,
            },
            resource_revision: self.submission_revision,
            wrapped_key_version: 1,
            member_key_generation: None,
            recipient_key_kind,
            recipient_key_version,
            recipient_fingerprint,
            parent_descriptor_hash: Some(self.identity.descriptor_hash()?),
        })
    }
}

/// Which recipient opens the submission and with which locally held private key.
pub enum SubmissionRecipient<'a> {
    Agent {
        key_version: u32,
        identity: &'a X25519Identity,
    },
    ApproverGroup {
        key_version: u32,
        identity: &'a X25519Identity,
    },
}

/// Expected values from an authority independent of the submission being opened.
pub struct SubmissionAuthority<'a> {
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    /// The authoring Agent's Ed25519 key from the Agent directory or the Agent's own profile.
    pub agent_signing_public_key: &'a [u8; 32],
    pub recipient: SubmissionRecipient<'a>,
}

#[derive(Clone)]
pub enum SubmissionContent {
    /// For an update only the changed fields are present; the approver merges them into the
    /// target revision. A new credential requires a username.
    Credential {
        username: Option<SecretString>,
        password: SecretString,
        url: Option<String>,
        notes: Option<SecretString>,
    },
    Key {
        value: SecretString,
        url: Option<String>,
        notes: Option<SecretString>,
    },
}

impl std::fmt::Debug for SubmissionContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Credential { .. } => "SubmissionContent::Credential([REDACTED])",
            Self::Key { .. } => "SubmissionContent::Key([REDACTED])",
        })
    }
}

impl SubmissionContent {
    #[must_use]
    pub const fn entry_type(&self) -> SubmissionEntryType {
        match self {
            Self::Credential { .. } => SubmissionEntryType::Credential,
            Self::Key { .. } => SubmissionEntryType::Key,
        }
    }

    #[must_use]
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::Credential { url, .. } | Self::Key { url, .. } => url.as_deref(),
        }
    }

    #[must_use]
    pub fn username(&self) -> Option<&str> {
        match self {
            Self::Credential { username, .. } => username.as_ref().map(ExposeSecret::expose_secret),
            Self::Key { .. } => None,
        }
    }

    fn validate(&self, kind: SubmissionKind) -> Result<(), SubmissionError> {
        let (secret_ok, url, notes) = match self {
            Self::Credential {
                username,
                password,
                url,
                notes,
            } => (
                match username {
                    Some(username) => bounded_text(username.expose_secret(), USERNAME_MAX_BYTES),
                    None => kind == SubmissionKind::Update,
                } && bounded_text(password.expose_secret(), PASSWORD_MAX_BYTES),
                url,
                notes,
            ),
            Self::Key { value, url, notes } => (
                bounded_text(value.expose_secret(), KEY_VALUE_MAX_BYTES),
                url,
                notes,
            ),
        };
        let url_ok = url.as_deref().is_none_or(|url| {
            bounded_text(url, URL_MAX_BYTES)
                && (matches!(self, Self::Key { .. }) || url.starts_with("https://"))
        });
        let notes_ok = notes
            .as_ref()
            .is_none_or(|notes| bounded_text(notes.expose_secret(), NOTES_MAX_BYTES));
        if secret_ok && url_ok && notes_ok {
            Ok(())
        } else {
            Err(SubmissionError::InvalidInput)
        }
    }

    fn to_value(&self) -> Value {
        let mut content = Map::new();
        let (url, notes) = match self {
            Self::Credential {
                username,
                password,
                url,
                notes,
            } => {
                if let Some(username) = username {
                    content.insert("username".into(), json!(username.expose_secret()));
                }
                content.insert("password".into(), json!(password.expose_secret()));
                (url, notes)
            }
            Self::Key { value, url, notes } => {
                content.insert("value".into(), json!(value.expose_secret()));
                (url, notes)
            }
        };
        if let Some(url) = url {
            content.insert("url".into(), json!(url));
        }
        if let Some(notes) = notes {
            content.insert("notes".into(), json!(notes.expose_secret()));
        }
        Value::Object(content)
    }

    fn from_value(
        kind: SubmissionKind,
        entry_type: SubmissionEntryType,
        value: &Value,
    ) -> Result<Self, SubmissionError> {
        let object = value.as_object().ok_or(SubmissionError::MissingField)?;
        let (required, optional): (&[&str], &[&str]) = match (kind, entry_type) {
            (SubmissionKind::New, SubmissionEntryType::Credential) => {
                (&["username", "password"], &["url", "notes"])
            }
            (SubmissionKind::Update, SubmissionEntryType::Credential) => {
                (&["password"], &["username", "url", "notes"])
            }
            (_, SubmissionEntryType::Key) => (&["value"], &["url", "notes"]),
        };
        check_fields(object, required, optional)?;
        let required_text = |key: &str| -> Result<SecretString, SubmissionError> {
            match object.get(key).and_then(Value::as_str) {
                Some(value) if !value.is_empty() => Ok(SecretString::from(value.to_owned())),
                _ => Err(SubmissionError::MissingField),
            }
        };
        let optional_text = |key: &str| -> Result<Option<String>, SubmissionError> {
            match object.get(key) {
                None => Ok(None),
                Some(Value::String(value)) => Ok(Some(value.clone())),
                Some(_) => Err(SubmissionError::InvalidEncoding),
            }
        };
        let url = optional_text("url")?;
        let notes = optional_text("notes")?.map(SecretString::from);
        Ok(match entry_type {
            SubmissionEntryType::Credential => Self::Credential {
                username: object
                    .contains_key("username")
                    .then(|| required_text("username"))
                    .transpose()?,
                password: required_text("password")?,
                url,
                notes,
            },
            SubmissionEntryType::Key => Self::Key {
                value: required_text("value")?,
                url,
                notes,
            },
        })
    }
}

/// A verified and decrypted submission. Only produced by `open_agent_submission`.
pub struct OpenedSubmission {
    pub identity: SubmissionIdentity,
    /// Required for a new Entry; for an update it proposes a rename.
    pub label: Option<String>,
    pub content: SubmissionContent,
}

impl std::fmt::Debug for OpenedSubmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenedSubmission")
            .field("submission_id", &self.identity.submission_id)
            .field("label", &"[REDACTED]")
            .field("content", &self.content)
            .finish()
    }
}

impl OpenedSubmission {
    /// Converts the authenticated payload into the flat credential shape consumed by Inject.
    pub fn into_inject_credential(self) -> Result<DecryptedCredential, SubmissionError> {
        let mut value = self.content.to_value();
        let plaintext = serde_json::to_vec(&value).map_err(|_| SubmissionError::InvalidEncoding);
        zeroize_json(&mut value);
        Ok(DecryptedCredential::from_authenticated_plaintext(
            SecretSlice::from(plaintext?),
        ))
    }
}

/// Approver key state pinned in the Agent's signed profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedApproverTrust {
    pub organization_id: Uuid,
    pub key_version: u32,
    pub manifest_revision: u64,
    pub signing_public_key: [u8; 32],
    pub message_public_key: [u8; 32],
}

impl PinnedApproverTrust {
    #[must_use]
    pub fn signing_key_fingerprint(&self) -> [u8; 32] {
        compute_key_fingerprint(
            &self.signing_public_key,
            RecipientKeyKind::OrganizationApproverEd25519,
        )
    }

    #[must_use]
    pub fn message_key_fingerprint(&self) -> [u8; 32] {
        compute_key_fingerprint(
            &self.message_public_key,
            RecipientKeyKind::OrganizationApproverX25519,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationApproverManifest {
    pub organization_id: Uuid,
    pub key_version: u32,
    pub manifest_revision: u64,
    message_public_key: [u8; 32],
    message_key_fingerprint: [u8; 32],
    signing_public_key: [u8; 32],
    signing_key_fingerprint: [u8; 32],
    previous_signing_key_fingerprint: Option<[u8; 32]>,
    signature: [u8; 64],
    continuity_signature: Option<[u8; 64]>,
    unsigned_canonical: Vec<u8>,
}

impl OrganizationApproverManifest {
    pub fn from_value(value: &Value) -> Result<Self, SubmissionError> {
        let object = value.as_object().ok_or(SubmissionError::InvalidEncoding)?;
        check_fields(
            object,
            &MANIFEST_REQUIRED_FIELDS,
            &MANIFEST_CONDITIONAL_FIELDS,
        )?;
        if text(object, "schema")? != MANIFEST_SCHEMA
            || number(object, "contractVersion")? != CONTRACT_VERSION
            || number(object, "protocolVersion")? != u64::from(PROTOCOL_VERSION)
        {
            return Err(SubmissionError::UnsupportedContract);
        }
        let key_version = number_u32(object, "keyVersion")?;
        let manifest_revision = decimal(object, "manifestRevision")?;
        if key_version == 0
            || manifest_revision == 0
            || decimal(object, "approverSetRevision")? == 0
        {
            return Err(SubmissionError::InvalidEncoding);
        }
        base64_array::<32>(object, "approverSetDigest")?;
        text(object, "issuedAt")?;
        let mut unsigned = object.clone();
        for field in SIGNATURE_FIELDS {
            unsigned.remove(field);
        }
        Ok(Self {
            organization_id: uuid(object, "organizationId")?,
            key_version,
            manifest_revision,
            message_public_key: base64_array(object, "messagePublicKey")?,
            message_key_fingerprint: base64_array(object, "messageKeyFingerprint")?,
            signing_public_key: base64_array(object, "signingPublicKey")?,
            signing_key_fingerprint: base64_array(object, "signingKeyFingerprint")?,
            previous_signing_key_fingerprint: object
                .contains_key("previousSigningKeyFingerprint")
                .then(|| base64_array(object, "previousSigningKeyFingerprint"))
                .transpose()?,
            signature: base64_array(object, "signature")?,
            continuity_signature: object
                .contains_key("continuitySignature")
                .then(|| base64_array(object, "continuitySignature"))
                .transpose()?,
            unsigned_canonical: canonical_json(&Value::Object(unsigned))?,
        })
    }

    fn verify_signature(
        &self,
        profile: SignatureProfile,
        signature: &[u8; 64],
        public_key: &[u8; 32],
        error: SubmissionError,
    ) -> Result<(), SubmissionError> {
        verify_domain_signature(
            profile,
            PROTOCOL_VERSION,
            &self.unsigned_canonical,
            public_key,
            signature,
        )
        .map_err(|_| error)
    }

    fn pin(&self) -> PinnedApproverTrust {
        PinnedApproverTrust {
            organization_id: self.organization_id,
            key_version: self.key_version,
            manifest_revision: self.manifest_revision,
            signing_public_key: self.signing_public_key,
            message_public_key: self.message_public_key,
        }
    }
}

/// Verifies an ascending manifest batch against the current pin and returns the next pin.
///
/// Without a pin the first manifest is a trust-on-first-use introduction from the authenticated
/// backend, the same boundary as a first Vault manifest. Every later manifest must be signed by
/// the pinned key, or be exactly the next key version with a continuity signature by it.
pub fn verify_approver_manifest_chain(
    manifests: &[OrganizationApproverManifest],
    organization_id: Uuid,
    pinned: Option<&PinnedApproverTrust>,
) -> Result<Option<PinnedApproverTrust>, SubmissionError> {
    if pinned.is_some_and(|pin| pin.organization_id != organization_id) {
        return Err(SubmissionError::ManifestOrganizationMismatch);
    }
    let mut current = pinned.cloned();
    for manifest in manifests {
        if manifest.organization_id != organization_id {
            return Err(SubmissionError::ManifestOrganizationMismatch);
        }
        if compute_key_fingerprint(
            &manifest.signing_public_key,
            RecipientKeyKind::OrganizationApproverEd25519,
        ) != manifest.signing_key_fingerprint
            || compute_key_fingerprint(
                &manifest.message_public_key,
                RecipientKeyKind::OrganizationApproverX25519,
            ) != manifest.message_key_fingerprint
        {
            return Err(SubmissionError::ManifestFingerprintMismatch);
        }
        manifest.verify_signature(
            SignatureProfile::ApproverManifest,
            &manifest.signature,
            &manifest.signing_public_key,
            SubmissionError::ManifestSignatureInvalid,
        )?;
        let rotated = manifest.key_version > 1;
        if rotated != manifest.continuity_signature.is_some()
            || rotated != manifest.previous_signing_key_fingerprint.is_some()
        {
            return Err(SubmissionError::ManifestContinuityInvalid);
        }
        let Some(pin) = current.as_ref() else {
            current = Some(manifest.pin());
            continue;
        };
        if manifest.manifest_revision <= pin.manifest_revision {
            return Err(SubmissionError::ManifestRollback);
        }
        if manifest.key_version == pin.key_version {
            if manifest.signing_key_fingerprint != pin.signing_key_fingerprint() {
                return Err(SubmissionError::ManifestSignatureInvalid);
            }
        } else if Some(manifest.key_version) == pin.key_version.checked_add(1) {
            let (Some(previous), Some(continuity)) = (
                manifest.previous_signing_key_fingerprint,
                manifest.continuity_signature.as_ref(),
            ) else {
                return Err(SubmissionError::ManifestContinuityInvalid);
            };
            if previous != pin.signing_key_fingerprint() {
                return Err(SubmissionError::ManifestContinuityInvalid);
            }
            manifest.verify_signature(
                SignatureProfile::ApproverContinuity,
                continuity,
                &pin.signing_public_key,
                SubmissionError::ManifestContinuityInvalid,
            )?;
        } else {
            return Err(SubmissionError::ManifestKeyVersionSkip);
        }
        current = Some(manifest.pin());
    }
    Ok(current)
}

pub struct SubmissionBuildContext<'a> {
    pub identity: SubmissionIdentity,
    pub agent_access_epoch: u64,
    pub agent_key_version: u32,
    pub agent_encryption_public_key: &'a [u8; 32],
    pub agent_signing: &'a Ed25519Identity,
    pub approver: &'a PinnedApproverTrust,
}

/// Encrypts a fresh submission with a new random DEK and nonce, wraps the DEK for the Agent and
/// the pinned approver key, and signs the transport object with the Agent's Ed25519 key.
pub fn build_agent_submission(
    context: &SubmissionBuildContext<'_>,
    label: Option<&str>,
    content: &SubmissionContent,
) -> Result<AgentEntrySubmission, SubmissionError> {
    if context.identity.entry_type != content.entry_type() {
        return Err(SubmissionError::InvalidInput);
    }
    if context.identity.organization_id != context.approver.organization_id {
        return Err(SubmissionError::ContextMismatch);
    }
    let kind = context.identity.kind();
    let label_valid = match label {
        Some(label) => {
            !label.is_empty()
                && label.len() <= LABEL_MAX_BYTES
                && unicode_normalization::is_nfc(label)
                && !label.chars().any(char::is_control)
        }
        None => kind == SubmissionKind::Update,
    };
    if !label_valid {
        return Err(SubmissionError::InvalidInput);
    }
    content.validate(kind)?;
    let mut payload = json!({
        "schema": PAYLOAD_SCHEMA,
        "identity": context.identity.to_value(),
        "content": content.to_value(),
    });
    if let (Some(label), Value::Object(object)) = (label, &mut payload) {
        object.insert("label".into(), json!(label));
    }
    let plaintext = canonical_json(&payload).map(Zeroizing::new);
    zeroize_json(&mut payload);
    let plaintext = plaintext?;
    if plaintext.len() > PAYLOAD_PLAINTEXT_MAX_BYTES {
        return Err(SubmissionError::InvalidInput);
    }
    let mut dek = Zeroizing::new([0_u8; 32]);
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(dek.as_mut()).map_err(|_| SubmissionError::RandomGenerationFailed)?;
    getrandom::fill(&mut nonce).map_err(|_| SubmissionError::RandomGenerationFailed)?;
    let dek = SecretBox::new(Box::new(*dek));
    let encoded_payload = encrypt_payload(&context.identity, &dek, &nonce, plaintext.as_slice())?;
    seal_revision(
        context.identity.clone(),
        encoded_payload,
        &dek,
        1,
        context.agent_access_epoch,
        context.agent_key_version,
        context.agent_encryption_public_key,
        context.agent_signing,
        context.approver,
    )
}

/// Re-wraps the unchanged DEK and payload of a stored submission for a rotated approver key.
///
/// The organization comes from the pinned approver key and `agent_id` from the local profile,
/// never from the stored envelope being re-wrapped.
pub fn rewrap_agent_submission(
    stored: &AgentEntrySubmission,
    agent_id: Uuid,
    agent_encryption: &X25519Identity,
    agent_signing: &Ed25519Identity,
    approver: &PinnedApproverTrust,
) -> Result<AgentEntrySubmission, SubmissionError> {
    if approver.key_version <= stored.approver_key_version {
        return Err(SubmissionError::RecipientKeyMismatch);
    }
    let authority = SubmissionAuthority {
        organization_id: approver.organization_id,
        agent_id,
        agent_signing_public_key: agent_signing.public_key(),
        recipient: SubmissionRecipient::Agent {
            key_version: stored.agent_key_version,
            identity: agent_encryption,
        },
    };
    let dek = open_dek(stored, &authority)?;
    let next_revision = stored
        .submission_revision
        .checked_add(1)
        .ok_or(SubmissionError::RevisionReplay)?;
    let candidate = seal_revision(
        stored.identity.clone(),
        stored.encoded_payload.clone(),
        &dek,
        next_revision,
        stored.agent_access_epoch,
        stored.agent_key_version,
        agent_encryption.public_key(),
        agent_signing,
        approver,
    )?;
    verify_rewrap(stored, &candidate, approver.key_version)?;
    Ok(candidate)
}

/// The re-wrap acceptance rule shared by the backend and approver clients.
pub fn verify_rewrap(
    stored: &AgentEntrySubmission,
    candidate: &AgentEntrySubmission,
    current_approver_key_version: u32,
) -> Result<(), SubmissionError> {
    if Some(candidate.submission_revision) != stored.submission_revision.checked_add(1) {
        return Err(SubmissionError::RevisionReplay);
    }
    if candidate.approver_key_version != current_approver_key_version {
        return Err(SubmissionError::RecipientKeyMismatch);
    }
    if candidate.encoded_payload != stored.encoded_payload || candidate.identity != stored.identity
    {
        return Err(SubmissionError::RewrapChangedPayload);
    }
    Ok(())
}

/// Verifies the Agent signature and every binding against the independent authority, opens the
/// recipient's wrapped DEK and decrypts the identity-bound payload.
pub fn open_agent_submission(
    submission: &AgentEntrySubmission,
    authority: &SubmissionAuthority<'_>,
) -> Result<OpenedSubmission, SubmissionError> {
    let dek = open_dek(submission, authority)?;
    let sealed = &submission.encoded_payload;
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return Err(SubmissionError::PayloadAuthFailed);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(dek.expose_secret()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&sealed[..NONCE_BYTES]),
                Payload {
                    msg: &sealed[NONCE_BYTES..],
                    aad: &submission.identity.payload_aad()?,
                },
            )
            .map_err(|_| SubmissionError::PayloadAuthFailed)?,
    );
    let mut payload: Value =
        serde_json::from_slice(&plaintext).map_err(|_| SubmissionError::InvalidEncoding)?;
    let opened = parse_payload(&payload, &submission.identity);
    zeroize_json(&mut payload);
    opened
}

fn parse_payload(
    payload: &Value,
    identity: &SubmissionIdentity,
) -> Result<OpenedSubmission, SubmissionError> {
    let object = payload
        .as_object()
        .ok_or(SubmissionError::InvalidEncoding)?;
    check_fields(object, &["schema", "identity", "content"], &["label"])?;
    if text(object, "schema")? != PAYLOAD_SCHEMA {
        return Err(SubmissionError::UnsupportedContract);
    }
    let inner_identity = object
        .get("identity")
        .ok_or(SubmissionError::MissingField)?;
    let label = match object.get("label") {
        None if identity.kind() == SubmissionKind::New => {
            return Err(SubmissionError::MissingField);
        }
        None => None,
        Some(Value::String(label)) if !label.is_empty() && label.len() <= LABEL_MAX_BYTES => {
            Some(label.clone())
        }
        Some(_) => return Err(SubmissionError::InvalidEncoding),
    };
    let content = SubmissionContent::from_value(
        identity.kind(),
        identity.entry_type,
        object.get("content").ok_or(SubmissionError::MissingField)?,
    )?;
    if canonical_json(inner_identity)? != identity.canonical()? {
        return Err(SubmissionError::IdentityMismatch);
    }
    Ok(OpenedSubmission {
        identity: identity.clone(),
        label,
        content,
    })
}

fn open_dek(
    submission: &AgentEntrySubmission,
    authority: &SubmissionAuthority<'_>,
) -> Result<SecretBox<[u8; 32]>, SubmissionError> {
    submission.verify_agent_signature(authority.agent_signing_public_key)?;
    if submission.identity.organization_id != authority.organization_id
        || submission.identity.agent_id != authority.agent_id
    {
        return Err(SubmissionError::ContextMismatch);
    }
    let (kind, key_version, identity, declared_version, declared_fingerprint, wrapped) =
        match authority.recipient {
            SubmissionRecipient::Agent {
                key_version,
                identity,
            } => (
                RecipientKeyKind::AgentX25519,
                key_version,
                identity,
                submission.agent_key_version,
                submission.agent_key_fingerprint,
                &submission.agent_wrapped_dek,
            ),
            SubmissionRecipient::ApproverGroup {
                key_version,
                identity,
            } => (
                RecipientKeyKind::OrganizationApproverX25519,
                key_version,
                identity,
                submission.approver_key_version,
                submission.approver_message_key_fingerprint,
                &submission.approver_wrapped_dek,
            ),
        };
    let fingerprint = compute_key_fingerprint(identity.public_key(), kind);
    if declared_version != key_version || declared_fingerprint.ct_eq(&fingerprint).unwrap_u8() != 1
    {
        return Err(SubmissionError::RecipientKeyMismatch);
    }
    let wrapped = SealedWrappedKey::from_bytes(wrapped.clone())
        .map_err(|_| SubmissionError::WrapperOpenFailed)?;
    let context = submission.wrapper_context(kind)?;
    X25519SealedBoxSuite::unwrap_classified(&wrapped, identity, &context).map_err(|error| {
        match error {
            WrapperOpenError::ContextMismatch => SubmissionError::WrapperContextMismatch,
            WrapperOpenError::Open | WrapperOpenError::Descriptor(_) => {
                SubmissionError::WrapperOpenFailed
            }
        }
    })
}

fn encrypt_payload(
    identity: &SubmissionIdentity,
    dek: &SecretBox<[u8; 32]>,
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>, SubmissionError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(dek.expose_secret()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &identity.payload_aad()?,
            },
        )
        .map_err(|_| SubmissionError::InvalidInput)?;
    let mut encoded = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    encoded.extend_from_slice(nonce);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

#[allow(clippy::too_many_arguments)]
fn seal_revision(
    identity: SubmissionIdentity,
    encoded_payload: Vec<u8>,
    dek: &SecretBox<[u8; 32]>,
    submission_revision: u64,
    agent_access_epoch: u64,
    agent_key_version: u32,
    agent_encryption_public_key: &[u8; 32],
    agent_signing: &Ed25519Identity,
    approver: &PinnedApproverTrust,
) -> Result<AgentEntrySubmission, SubmissionError> {
    let mut submission = AgentEntrySubmission {
        identity,
        submission_revision,
        agent_access_epoch,
        agent_key_version,
        agent_key_fingerprint: compute_key_fingerprint(
            agent_encryption_public_key,
            RecipientKeyKind::AgentX25519,
        ),
        approver_key_version: approver.key_version,
        approver_message_key_fingerprint: approver.message_key_fingerprint(),
        approver_manifest_revision: approver.manifest_revision,
        encoded_payload,
        agent_wrapped_dek: Vec::new(),
        approver_wrapped_dek: Vec::new(),
        agent_signature: [0; 64],
    };
    let wrap = |kind, public_key: &[u8; 32], submission: &AgentEntrySubmission| {
        X25519SealedBoxSuite::wrap(dek, *public_key, &submission.wrapper_context(kind)?)
            .map(|sealed| sealed.as_bytes().to_vec())
            .map_err(|_| SubmissionError::InvalidInput)
    };
    submission.agent_wrapped_dek = wrap(
        RecipientKeyKind::AgentX25519,
        agent_encryption_public_key,
        &submission,
    )?;
    submission.approver_wrapped_dek = wrap(
        RecipientKeyKind::OrganizationApproverX25519,
        &approver.message_public_key,
        &submission,
    )?;
    let mut input = SignatureProfile::AgentSubmission.domain_prefix().to_vec();
    input.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    input.extend_from_slice(&canonical_json(&submission.unsigned_value())?);
    submission.agent_signature = agent_signing.sign(&input);
    Ok(submission)
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, SubmissionError> {
    serde_jcs::to_vec(value).map_err(|_| SubmissionError::InvalidEncoding)
}

fn check_fields(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), SubmissionError> {
    if object
        .keys()
        .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(SubmissionError::UnknownField);
    }
    if required.iter().any(|key| !object.contains_key(*key)) {
        return Err(SubmissionError::MissingField);
    }
    Ok(())
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, SubmissionError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(SubmissionError::InvalidEncoding)
}

fn number(object: &Map<String, Value>, key: &str) -> Result<u64, SubmissionError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(SubmissionError::InvalidEncoding)
}

fn number_u32(object: &Map<String, Value>, key: &str) -> Result<u32, SubmissionError> {
    u32::try_from(number(object, key)?).map_err(|_| SubmissionError::InvalidEncoding)
}

fn decimal(object: &Map<String, Value>, key: &str) -> Result<u64, SubmissionError> {
    let value = text(object, key)?;
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(SubmissionError::InvalidEncoding)
}

fn uuid(object: &Map<String, Value>, key: &str) -> Result<Uuid, SubmissionError> {
    let value = text(object, key)?;
    Uuid::parse_str(value)
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(SubmissionError::InvalidEncoding)
}

fn base64_bounded(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, SubmissionError> {
    let value = text(object, key)?;
    if value.len() > max_bytes.div_ceil(3) * 4 {
        return Err(SubmissionError::InvalidEncoding);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .filter(|decoded| decoded.len() <= max_bytes && URL_SAFE_NO_PAD.encode(decoded) == value)
        .ok_or(SubmissionError::InvalidEncoding)
}

fn base64_array<const N: usize>(
    object: &Map<String, Value>,
    key: &str,
) -> Result<[u8; N], SubmissionError> {
    base64_bounded(object, key, N)?
        .try_into()
        .map_err(|_| SubmissionError::InvalidEncoding)
}

fn bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_json),
        Value::Object(object) => object.values_mut().for_each(zeroize_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
