use palladin_crypto::{EncryptedCredential, EncryptedReasonEnvelope};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentVisibleField {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySearchItem {
    pub entry_id: String,
    pub vault_id: String,
    pub label: String,
    pub url_domain: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub agent_fields: Vec<AgentVisibleField>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySearchResult {
    pub items: Vec<EntrySearchItem>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialMethod {
    Get,
    Exec,
    Inject,
}

impl CredentialMethod {
    pub(crate) const fn backend_name(self) -> &'static str {
        match self {
            Self::Get => "Get",
            Self::Exec => "Exec",
            Self::Inject => "Inject",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GetCredentialOptions {
    pub encrypted_reason: Option<EncryptedReasonEnvelope>,
    pub method: Option<CredentialMethod>,
    pub requested_methods: Vec<CredentialMethod>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "access", rename_all = "kebab-case")]
pub enum CredentialAccess {
    Granted {
        #[serde(rename = "entryId")]
        entry_id: String,
        label: String,
        #[serde(rename = "urlDomain")]
        url_domain: Option<String>,
        #[serde(flatten)]
        envelope: EncryptedCredential,
    },
    Pending {
        #[serde(rename = "grantId")]
        grant_id: String,
        created: Option<bool>,
        #[serde(rename = "pollIntervalMs")]
        poll_interval_ms: Option<u64>,
        #[serde(rename = "maxWaitMs")]
        max_wait_ms: Option<u64>,
    },
    Denied,
    Revoked,
    Expired,
    Consumed,
    MethodNotAllowed,
    ScriptExecOnly,
    Unavailable,
    Blocked,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleReasonCode {
    LoginRejected,
    AuthFailed,
    #[default]
    Manual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportCredentialStaleInput {
    pub vault_id: String,
    pub entry_id: String,
    pub code: StaleReasonCode,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InjectFailureUpload {
    pub entry_id: String,
    pub domain: Option<String>,
    pub reason: String,
    pub page_origin: Option<String>,
    pub controls: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentRegistrationResult {
    Pending {
        agent_id: String,
    },
    Active {
        agent_id: String,
        name: Option<String>,
    },
    Deactivated {
        agent_id: String,
    },
    InvalidKey,
    Unreachable {
        error: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegistrationBody {
    pub agent_id: String,
    pub name: Option<String>,
    pub status: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialRequestBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_reason: Option<&'a EncryptedReasonEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_methods: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum GrantStatus {
    Pending,
    Active,
    Denied,
    Revoked,
    Expired,
    Consumed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrantStatusResponse {
    pub grant_id: String,
    pub status: GrantStatus,
    pub expires_at: Option<String>,
    pub query_limit: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentVaultDiscoveryEnvelope {
    pub protocol_version: u16,
    pub organization_id: String,
    pub vault_id: String,
    pub agent_id: String,
    pub vdk_version: u32,
    pub algorithm_suite: u16,
    pub recipient_agent_key_version: u32,
    pub recipient_agent_key_fingerprint: String,
    pub agent_wrapped_vdk: String,
    pub manifest_revision: String,
    pub manifest_signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultManifest {
    pub protocol_version: u16,
    pub algorithm_suite: u16,
    pub organization_id: String,
    pub vault_id: String,
    pub agent_id: String,
    pub agent_x25519_fingerprint: String,
    pub agent_ed25519_fingerprint: String,
    pub vault_signing_public_key: String,
    pub vault_signing_key_fingerprint: String,
    pub manifest_signing_key_version: u32,
    pub vault_agent_message_public_key: String,
    pub vault_agent_message_key_fingerprint: String,
    pub agent_message_key_version: u32,
    pub vdk_version: u32,
    pub agent_wrapped_vdk_digest: String,
    pub manifest_revision: String,
    pub issued_at: String,
    pub minimum_agent_runtime_protocol: u16,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentVaultManifestItem {
    pub envelope: AgentVaultDiscoveryEnvelope,
    pub manifest: VaultManifest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentVaultManifestsResponse {
    pub items: Vec<AgentVaultManifestItem>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDiscoveryEnvelopeHeader {
    pub protocol_version: u16,
    pub algorithm_suite: u16,
    pub resource_kind: u16,
    pub projection_kind: u16,
    pub resource_revision: String,
    pub key_version: u32,
    pub member_key_generation: u32,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDiscoveryEnvelope {
    pub organization_id: String,
    pub vault_id: String,
    pub entry_id: String,
    pub agent_discovery_revision: String,
    pub vdk_version: u32,
    pub header: AgentDiscoveryEnvelopeHeader,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AgentDiscoverySyncItem {
    #[serde(rename = "head")]
    Head {
        entry_id: String,
        agent_discovery_revision: String,
        agent_discovery: AgentDiscoveryEnvelope,
    },
    #[serde(rename = "tombstone")]
    Tombstone {
        entry_id: String,
        agent_discovery_revision: Option<String>,
        agent_discovery: Option<AgentDiscoveryEnvelope>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDiscoverySnapshotResponse {
    pub snapshot_base_sequence: String,
    pub items: Vec<AgentDiscoverySyncItem>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDiscoveryDeltaResponse {
    pub delta_upper_bound: String,
    pub applied_through_sequence: String,
    pub items: Vec<AgentDiscoverySyncItem>,
    pub continuation_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentDiscoverySnapshotBody<'a> {
    pub vault_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentDiscoveryDeltaBody<'a> {
    pub vault_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_sequence: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_cursor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentPairingActivationResponse {
    pub activation_id: String,
    pub organization_id: String,
    pub agent_id: String,
    pub agent_access_epoch: u32,
    pub agent_x25519_fingerprint: String,
    pub agent_ed25519_fingerprint: String,
    pub expires_at: String,
    pub candidate_manifests: Vec<VaultManifest>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AgentPairingStatus {
    Pending,
    Confirmed,
    Expired,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentPairingStatusResponse {
    pub activation_id: String,
    pub status: AgentPairingStatus,
    pub expires_at: String,
    pub confirmed_pairing_digest: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreatePairingActivationBody<'a> {
    pub activation_id: &'a str,
}

#[derive(Serialize)]
pub(crate) struct StaleRequestBody<'a> {
    pub code: StaleReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'a str>,
}
