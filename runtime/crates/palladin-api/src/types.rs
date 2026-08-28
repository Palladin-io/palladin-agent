use palladin_crypto::{
    AgentWrappedVaultKey, EncryptedCredential, EncryptedReasonEnvelope, MemberSecretEnvelope,
    ScriptExecutionEncryptedPackage, ScriptExecutionParameter, VaultEntryKeyEnvelope,
};
use serde::{Deserialize, Deserializer, Serialize, de};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentVisibleField {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySearchItem {
    pub entry_id: String,
    pub vault_id: String,
    pub label: String,
    pub url_domain: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub agent_fields: Vec<AgentVisibleField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_execution: Option<ScriptExecutionDiscovery>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionDiscovery {
    pub contract_version: u16,
    pub script_revision: String,
    pub description: String,
    pub parameters: Vec<ScriptExecutionParameter>,
    pub return_result_to_agent: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySearchResult {
    pub items: Vec<EntrySearchItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionVaultEntry {
    pub entry_id: String,
    pub entry_revision: String,
    #[serde(deserialize_with = "deserialize_delivery_policy")]
    pub delivery_policy: u16,
    pub entry_key: VaultEntryKeyEnvelope,
    pub member_secret: MemberSecretEnvelope,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptExecutionPackageResponse {
    pub status: String,
    pub authorization_source: String,
    pub organization_id: String,
    pub vault_id: String,
    pub agent_id: String,
    pub agent_access_epoch: u32,
    pub script_entry_id: String,
    pub script_revision: String,
    pub grant_id: String,
    pub query_count: u32,
    pub query_limit: Option<u32>,
    pub expires_at: Option<String>,
    pub script_package: Option<ScriptExecutionEncryptedPackage>,
    pub agent_wrapped_vault_key: Option<AgentWrappedVaultKey>,
    pub vault_entries: Option<Vec<ScriptExecutionVaultEntry>>,
}

impl ScriptExecutionPackageResponse {
    pub(crate) fn validate(self) -> Result<Self, de::value::Error> {
        let direct = self.authorization_source == "scriptExecution"
            && self.script_package.is_some()
            && self.agent_wrapped_vault_key.is_none()
            && self.vault_entries.is_none();
        let full = self.authorization_source == "full"
            && self.script_package.is_none()
            && self.agent_wrapped_vault_key.is_some()
            && self.vault_entries.is_some();
        if self.status != "granted"
            || self.agent_access_epoch == 0
            || self.query_count == 0
            || !(direct || full)
        {
            return Err(de::Error::custom(
                "invalid Script execution package response",
            ));
        }
        Ok(self)
    }
}

fn deserialize_delivery_policy<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    GrantDeliveryPolicyWire::deserialize(deserializer)?.into_code()
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum ApprovedCredentialMethods {
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "exec")]
    Exec,
    #[serde(rename = "get, exec")]
    GetExec,
    #[serde(rename = "inject")]
    Inject,
    #[serde(rename = "get, inject")]
    GetInject,
    #[serde(rename = "exec, inject")]
    ExecInject,
    #[serde(rename = "get, exec, inject")]
    GetExecInject,
}

impl ApprovedCredentialMethods {
    const fn bits(self) -> u16 {
        match self {
            Self::Get => 1,
            Self::Exec => 2,
            Self::GetExec => 3,
            Self::Inject => 4,
            Self::GetInject => 5,
            Self::ExecInject => 6,
            Self::GetExecInject => 7,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
enum ApprovedCredentialMethodsWire {
    Named(ApprovedCredentialMethods),
    Numeric(u16),
}

impl ApprovedCredentialMethodsWire {
    fn into_bits<E: de::Error>(self) -> Result<u16, E> {
        let bits = match self {
            Self::Named(methods) => methods.bits(),
            Self::Numeric(bits) => bits,
        };
        (1..=7)
            .contains(&bits)
            .then_some(bits)
            .ok_or_else(|| E::custom("approved methods contain unsupported bits"))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum CredentialAccess {
    Granted {
        organization_id: String,
        vault_id: String,
        grant_id: String,
        agent_id: String,
        agent_access_epoch: u32,
        approved_methods: u16,
        entry_id: String,
        grant_type: CredentialGrantType,
        delivery_policy: u16,
        expires_at: Option<String>,
        material: CredentialCiphertext,
    },
    Pending {
        grant_id: String,
        created: Option<bool>,
        poll_interval_ms: Option<u64>,
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

#[derive(Debug, Eq, PartialEq)]
pub enum CredentialCiphertext {
    Granular(Box<EncryptedCredential>),
    Full {
        agent_wrapped_vault_key: Box<AgentWrappedVaultKey>,
        entry_key: Box<VaultEntryKeyEnvelope>,
        member_secret: Box<MemberSecretEnvelope>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum CredentialGrantType {
    Full,
    Granular,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
enum GrantDeliveryPolicy {
    Standard,
    ExecOnly,
    InjectOnly,
}

impl GrantDeliveryPolicy {
    const fn code(self) -> u16 {
        match self {
            Self::Standard => 0,
            Self::ExecOnly => 1,
            Self::InjectOnly => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
enum GrantDeliveryPolicyWire {
    Named(GrantDeliveryPolicy),
    Numeric(u16),
}

impl GrantDeliveryPolicyWire {
    fn into_code<E: de::Error>(self) -> Result<u16, E> {
        let code = match self {
            Self::Named(policy) => policy.code(),
            Self::Numeric(code) => code,
        };
        (code <= 2)
            .then_some(code)
            .ok_or_else(|| E::custom("delivery policy is unsupported"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialAccessWire {
    access: String,
    organization_id: Option<String>,
    vault_id: Option<String>,
    agent_id: Option<String>,
    agent_access_epoch: Option<u32>,
    approved_methods: Option<ApprovedCredentialMethodsWire>,
    entry_id: Option<String>,
    grant_type: Option<CredentialGrantType>,
    delivery_policy: Option<GrantDeliveryPolicyWire>,
    #[serde(default, deserialize_with = "deserialize_nullable_field")]
    expires_at: NullableField<String>,
    grant_envelope: Option<Box<EncryptedCredential>>,
    agent_wrapped_vault_key: Option<Box<AgentWrappedVaultKey>>,
    entry_key: Option<Box<VaultEntryKeyEnvelope>>,
    member_secret: Option<Box<MemberSecretEnvelope>>,
    grant_id: Option<String>,
    created: Option<bool>,
    poll_interval_ms: Option<u64>,
    max_wait_ms: Option<u64>,
}

#[derive(Debug, Default)]
enum NullableField<T> {
    #[default]
    Missing,
    Present(Option<T>),
}

impl<T> NullableField<T> {
    const fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
}

fn deserialize_nullable_field<'de, D, T>(deserializer: D) -> Result<NullableField<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(NullableField::Present)
}

impl<'de> Deserialize<'de> for CredentialAccess {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CredentialAccessWire::deserialize(deserializer)?;
        let approved_methods = wire
            .approved_methods
            .map(ApprovedCredentialMethodsWire::into_bits)
            .transpose()?;
        let delivery_policy = wire
            .delivery_policy
            .map(GrantDeliveryPolicyWire::into_code)
            .transpose()?;
        let granted_fields_absent = wire.organization_id.is_none()
            && wire.vault_id.is_none()
            && wire.agent_id.is_none()
            && wire.agent_access_epoch.is_none()
            && approved_methods.is_none()
            && wire.entry_id.is_none()
            && wire.grant_type.is_none()
            && delivery_policy.is_none()
            && wire.expires_at.is_missing()
            && wire.grant_envelope.is_none()
            && wire.agent_wrapped_vault_key.is_none()
            && wire.entry_key.is_none()
            && wire.member_secret.is_none();
        let pending_fields_absent = wire.grant_id.is_none()
            && wire.created.is_none()
            && wire.poll_interval_ms.is_none()
            && wire.max_wait_ms.is_none();
        match wire.access.as_str() {
            "granted"
                if wire.created.is_none()
                    && wire.poll_interval_ms.is_none()
                    && wire.max_wait_ms.is_none() =>
            {
                let grant_type = wire
                    .grant_type
                    .ok_or_else(|| de::Error::missing_field("grantType"))?;
                let material = match grant_type {
                    CredentialGrantType::Granular
                        if wire.agent_wrapped_vault_key.is_none()
                            && wire.entry_key.is_none()
                            && wire.member_secret.is_none() =>
                    {
                        CredentialCiphertext::Granular(
                            wire.grant_envelope
                                .ok_or_else(|| de::Error::missing_field("grantEnvelope"))?,
                        )
                    }
                    CredentialGrantType::Full if wire.grant_envelope.is_none() => {
                        CredentialCiphertext::Full {
                            agent_wrapped_vault_key: wire
                                .agent_wrapped_vault_key
                                .ok_or_else(|| de::Error::missing_field("agentWrappedVaultKey"))?,
                            entry_key: wire
                                .entry_key
                                .ok_or_else(|| de::Error::missing_field("entryKey"))?,
                            member_secret: wire
                                .member_secret
                                .ok_or_else(|| de::Error::missing_field("memberSecret"))?,
                        }
                    }
                    _ => return Err(de::Error::custom("invalid credential material set")),
                };
                Ok(Self::Granted {
                    organization_id: wire
                        .organization_id
                        .ok_or_else(|| de::Error::missing_field("organizationId"))?,
                    vault_id: wire
                        .vault_id
                        .ok_or_else(|| de::Error::missing_field("vaultId"))?,
                    grant_id: wire
                        .grant_id
                        .ok_or_else(|| de::Error::missing_field("grantId"))?,
                    agent_id: wire
                        .agent_id
                        .ok_or_else(|| de::Error::missing_field("agentId"))?,
                    agent_access_epoch: wire
                        .agent_access_epoch
                        .ok_or_else(|| de::Error::missing_field("agentAccessEpoch"))?,
                    approved_methods: approved_methods
                        .ok_or_else(|| de::Error::missing_field("approvedMethods"))?,
                    entry_id: wire
                        .entry_id
                        .ok_or_else(|| de::Error::missing_field("entryId"))?,
                    grant_type,
                    delivery_policy: delivery_policy
                        .ok_or_else(|| de::Error::missing_field("deliveryPolicy"))?,
                    expires_at: match wire.expires_at {
                        NullableField::Present(value) => value,
                        NullableField::Missing => {
                            return Err(de::Error::missing_field("expiresAt"));
                        }
                    },
                    material,
                })
            }
            "pending" if granted_fields_absent => Ok(Self::Pending {
                grant_id: wire
                    .grant_id
                    .ok_or_else(|| de::Error::missing_field("grantId"))?,
                created: wire.created,
                poll_interval_ms: wire.poll_interval_ms,
                max_wait_ms: wire.max_wait_ms,
            }),
            "denied" if granted_fields_absent && pending_fields_absent => Ok(Self::Denied),
            "revoked" if granted_fields_absent && pending_fields_absent => Ok(Self::Revoked),
            "expired" if granted_fields_absent && pending_fields_absent => Ok(Self::Expired),
            "consumed" if granted_fields_absent && pending_fields_absent => Ok(Self::Consumed),
            "method-not-allowed" if granted_fields_absent && pending_fields_absent => {
                Ok(Self::MethodNotAllowed)
            }
            "script-exec-only" if granted_fields_absent && pending_fields_absent => {
                Ok(Self::ScriptExecOnly)
            }
            "unavailable" if granted_fields_absent && pending_fields_absent => {
                Ok(Self::Unavailable)
            }
            "blocked" if granted_fields_absent && pending_fields_absent => Ok(Self::Blocked),
            _ => Err(de::Error::custom("invalid credential access response")),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantedCredential {
    pub organization_id: String,
    pub vault_id: String,
    pub grant_id: String,
    pub agent_id: String,
    pub entry_id: String,
    pub approved_methods: ApprovedCredentialMethods,
    pub label: String,
    pub grant_envelope_revision: String,
    pub entry_revision: String,
    pub protocol_version: u16,
    pub algorithm_suite: u16,
    pub grant_key_version: u32,
    pub member_key_generation: u32,
    pub recipient_agent_key_version: u32,
    pub field_ids: Vec<String>,
    pub ciphertext: String,
    pub nonce: String,
    pub agent_wrapped_grant_dek: String,
    pub agent_wrapper_suite: u16,
    pub agent_key_fingerprint: String,
    pub envelope_expires_at: Option<String>,
    pub envelope_remaining_uses: Option<u32>,
    pub url_domain: Option<String>,
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
    pub created: Option<bool>,
    pub poll_interval_ms: Option<u64>,
    pub max_wait_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentVaultDiscoveryEnvelope {
    pub protocol_version: u16,
    pub organization_id: String,
    pub vault_id: String,
    pub agent_id: String,
    pub vdk_version: u32,
    pub wrapped_vdk: X25519WrappedKey,
    pub manifest_revision: String,
    pub manifest_signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct X25519WrappedKey {
    pub descriptor: X25519WrapperDescriptor,
    pub encoded_sealed_key_package: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct X25519WrapperDescriptor {
    pub protocol_version: u16,
    pub wrapper_suite_id: String,
    pub purpose: String,
    pub scope: EnvelopeScopeContract,
    pub resource_revision: String,
    pub wrapped_key_version: u32,
    pub member_key_generation: Option<u32>,
    pub recipient_key_kind: String,
    pub recipient_key_version: u32,
    pub recipient_fingerprint: String,
    pub parent_descriptor_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeScopeContract {
    pub organization_id: String,
    pub vault_id: String,
    pub entry_id: Option<String>,
    pub grant_or_request_id: Option<String>,
    pub agent_id: Option<String>,
    pub member_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultManifest {
    pub protocol_version: u16,
    pub crypto_suite_id: String,
    pub wrapper_suite_id: String,
    pub signature_suite_id: String,
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentVaultManifestsResponse {
    pub agent_access_epoch: u32,
    pub items: Vec<AgentVaultManifestItem>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDiscoveryEnvelopeDescriptor {
    pub protocol_version: u16,
    pub crypto_suite_id: String,
    pub purpose: String,
    pub scope: EnvelopeScopeContract,
    pub resource_revision: String,
    pub key_version: u32,
    pub member_key_generation: Option<u32>,
    pub binding: EmptyEnvelopeBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EmptyEnvelopeBinding {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDiscoveryEnvelope {
    pub descriptor: AgentDiscoveryEnvelopeDescriptor,
    pub encoded_suite_payload: String,
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
pub(crate) struct StaleRequestBody {
    pub code: StaleReasonCode,
}

#[cfg(test)]
mod tests {
    use super::{
        AgentDiscoverySnapshotResponse, AgentVaultManifestsResponse, ApprovedCredentialMethods,
        CredentialAccess, CredentialCiphertext, CredentialGrantType,
    };

    const GRANTED: &str = r#"{
        "access":"granted",
        "organizationId":"organization",
        "vaultId":"vault",
        "grantId":"grant",
        "agentId":"agent",
        "entryId":"entry",
        "approvedMethods":"get, exec, inject",
        "label":"Example",
        "grantEnvelopeRevision":"3",
        "entryRevision":"12",
        "protocolVersion":2,
        "algorithmSuite":1,
        "grantKeyVersion":4,
        "memberKeyGeneration":5,
        "recipientAgentKeyVersion":6,
        "fieldIds":["password","username"],
        "ciphertext":"ciphertext",
        "nonce":"nonce",
        "agentWrappedGrantDek":"wrapped",
        "agentWrapperSuite":1,
        "agentKeyFingerprint":"fingerprint",
        "envelopeExpiresAt":null,
        "envelopeRemainingUses":5,
        "urlDomain":"example.com"
    }"#;

    #[test]
    fn granted_rejects_the_superseded_flat_v2_contract() {
        assert!(serde_json::from_str::<CredentialAccess>(GRANTED).is_err());
    }

    #[test]
    fn approved_methods_accepts_only_backend_flag_strings() {
        let cases = [
            ("get", ApprovedCredentialMethods::Get),
            ("exec", ApprovedCredentialMethods::Exec),
            ("get, exec", ApprovedCredentialMethods::GetExec),
            ("inject", ApprovedCredentialMethods::Inject),
            ("get, inject", ApprovedCredentialMethods::GetInject),
            ("exec, inject", ApprovedCredentialMethods::ExecInject),
            (
                "get, exec, inject",
                ApprovedCredentialMethods::GetExecInject,
            ),
        ];
        for (wire, expected) in cases {
            let json = format!(r#""{wire}""#);
            assert_eq!(
                serde_json::from_str::<ApprovedCredentialMethods>(&json).expect("approved methods"),
                expected
            );
        }
        for rejected in [r#"""#, r#""Get""#, r#""exec, get""#, "3", r#""delete""#] {
            assert!(serde_json::from_str::<ApprovedCredentialMethods>(rejected).is_err());
        }
    }

    #[test]
    fn granted_rejects_legacy_or_incomplete_envelopes() {
        let legacy = r#"{"access":"granted","entryId":"entry","label":"Example","urlDomain":null,"ciphertext":"ciphertext","nonce":"nonce","wrappedDek":"wrapped"}"#;
        assert!(serde_json::from_str::<CredentialAccess>(legacy).is_err());

        let unknown = GRANTED.replace(
            r#""urlDomain":"example.com""#,
            r#""urlDomain":"example.com","legacyField":"rejected""#,
        );
        assert!(serde_json::from_str::<CredentialAccess>(&unknown).is_err());
    }

    #[test]
    fn pending_accepts_the_backend_record_shape_without_weakening_the_union() {
        let pending = r#"{
            "access":"pending","organizationId":null,"vaultId":null,"agentId":null,
            "approvedMethods":null,"entryId":null,"grantEnvelope":null,
            "grantId":"77777777-7777-4777-8777-777777777777","created":true,
            "pollIntervalMs":30000,"maxWaitMs":180000
        }"#;
        assert!(matches!(
            serde_json::from_str::<CredentialAccess>(pending).expect("pending"),
            CredentialAccess::Pending {
                created: Some(true),
                ..
            }
        ));

        let confused = pending.replace(
            r#""organizationId":null"#,
            r#""organizationId":"organization""#,
        );
        assert!(serde_json::from_str::<CredentialAccess>(&confused).is_err());
    }

    #[test]
    fn granted_accepts_current_backend_named_enums() {
        let scope = serde_json::json!({
            "organizationId": "00112233-4455-4677-8899-aabbccddeeff",
            "vaultId": "11112222-3333-4444-8555-666677778888",
            "entryId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "grantOrRequestId": "12345678-1234-4234-8234-1234567890ab",
            "agentId": "fedcba98-7654-4321-8765-abcdefabcdef"
        });
        let granted = serde_json::json!({
            "access": "granted",
            "organizationId": "00112233-4455-4677-8899-aabbccddeeff",
            "vaultId": "11112222-3333-4444-8555-666677778888",
            "grantId": "12345678-1234-4234-8234-1234567890ab",
            "agentId": "fedcba98-7654-4321-8765-abcdefabcdef",
            "agentAccessEpoch": 1,
            "approvedMethods": "inject",
            "entryId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "grantType": "granular",
            "deliveryPolicy": "standard",
            "expiresAt": null,
            "grantEnvelope": {
                "descriptor": {
                    "protocolVersion": 2,
                    "cryptoSuiteId": "palladin-vault-xchacha-v1",
                    "purpose": "grantPayload",
                    "scope": scope.clone(),
                    "resourceRevision": "1",
                    "keyVersion": 1,
                    "memberKeyGeneration": 1,
                    "binding": {
                        "entryRevision": "1",
                        "wrapperSuiteId": "palladin-x25519-sealed-box-v1",
                        "recipientKeyVersion": 1,
                        "recipientKeyFingerprint": "fingerprint",
                        "approvedMethods": 4,
                        "deliveryPolicy": 0,
                        "fieldSetCommitment": "commitment",
                        "expiresAt": null,
                        "remainingUses": 1
                    }
                },
                "encodedSuitePayload": "payload",
                "wrappedGrantDek": {
                    "descriptor": {
                        "protocolVersion": 2,
                        "wrapperSuiteId": "palladin-x25519-sealed-box-v1",
                        "purpose": "grantDek",
                        "scope": scope,
                        "resourceRevision": "1",
                        "wrappedKeyVersion": 1,
                        "memberKeyGeneration": 1,
                        "recipientKeyKind": "agentX25519",
                        "recipientKeyVersion": 1,
                        "recipientFingerprint": "fingerprint",
                        "parentDescriptorHash": "hash"
                    },
                    "encodedSealedKeyPackage": "wrapped"
                },
                "fieldIds": ["credential.username"]
            },
            "created": null,
            "pollIntervalMs": null,
            "maxWaitMs": null
        });

        assert!(matches!(
            serde_json::from_value::<CredentialAccess>(granted).expect("current granted response"),
            CredentialAccess::Granted {
                approved_methods: 4,
                ..
            }
        ));
    }

    #[test]
    fn full_granted_requires_a_disjoint_complete_material_set() {
        let entry_scope = serde_json::json!({
            "organizationId": "00112233-4455-4677-8899-aabbccddeeff",
            "vaultId": "11112222-3333-4444-8555-666677778888",
            "entryId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "grantOrRequestId": null,
            "agentId": null,
            "memberId": null
        });
        let wrapper_scope = serde_json::json!({
            "organizationId": "00112233-4455-4677-8899-aabbccddeeff",
            "vaultId": "11112222-3333-4444-8555-666677778888",
            "entryId": null,
            "grantOrRequestId": "12345678-1234-4234-8234-1234567890ab",
            "agentId": "fedcba98-7654-4321-8765-abcdefabcdef",
            "memberId": null
        });
        let mut granted = serde_json::json!({
            "access": "granted",
            "organizationId": "00112233-4455-4677-8899-aabbccddeeff",
            "vaultId": "11112222-3333-4444-8555-666677778888",
            "grantId": "12345678-1234-4234-8234-1234567890ab",
            "agentId": "fedcba98-7654-4321-8765-abcdefabcdef",
            "agentAccessEpoch": 7,
            "approvedMethods": "get",
            "entryId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "grantType": "full",
            "deliveryPolicy": "standard",
            "expiresAt": null,
            "agentWrappedVaultKey": {
                "wrappedVaultKey": {
                    "descriptor": {
                        "protocolVersion": 2,
                        "wrapperSuiteId": "palladin-x25519-sealed-box-v1",
                        "purpose": "agentVaultKey",
                        "scope": wrapper_scope,
                        "resourceRevision": "7",
                        "wrappedKeyVersion": 3,
                        "memberKeyGeneration": null,
                        "recipientKeyKind": "agentX25519",
                        "recipientKeyVersion": 2,
                        "recipientFingerprint": "fingerprint",
                        "parentDescriptorHash": null
                    },
                    "encodedSealedKeyPackage": "wrapped-vault-key"
                },
                "vaultSigningKeyVersion": 5,
                "vaultSigningKeyFingerprint": "signing-fingerprint",
                "producerSignature": "producer-signature"
            },
            "entryKey": {
                "descriptor": {
                    "protocolVersion": 2,
                    "cryptoSuiteId": "palladin-vault-xchacha-v1",
                    "purpose": "entryDekByVaultKey",
                    "scope": entry_scope.clone(),
                    "resourceRevision": "1",
                    "keyVersion": 4,
                    "memberKeyGeneration": 5,
                    "binding": { "wrappingVaultKeyVersion": 3 }
                },
                "encodedSuitePayload": "entry-key"
            },
            "memberSecret": {
                "descriptor": {
                    "protocolVersion": 2,
                    "cryptoSuiteId": "palladin-vault-xchacha-v1",
                    "purpose": "memberSecret",
                    "scope": entry_scope,
                    "resourceRevision": "9",
                    "keyVersion": 4,
                    "memberKeyGeneration": 5,
                    "binding": { "operation": 2 }
                },
                "encodedSuitePayload": "member-secret"
            }
        });

        assert!(matches!(
            serde_json::from_value::<CredentialAccess>(granted.clone())
                .expect("complete FULL response"),
            CredentialAccess::Granted {
                grant_type: CredentialGrantType::Full,
                material: CredentialCiphertext::Full { .. },
                ..
            }
        ));

        let mut named_operation = granted.clone();
        named_operation["memberSecret"]["descriptor"]["binding"]["operation"] =
            serde_json::json!("updated");
        assert!(matches!(
            serde_json::from_value::<CredentialAccess>(named_operation)
                .expect("FULL response with the backend enum wire format"),
            CredentialAccess::Granted {
                grant_type: CredentialGrantType::Full,
                material: CredentialCiphertext::Full { .. },
                ..
            }
        ));

        let mut unknown_operation = granted.clone();
        unknown_operation["memberSecret"]["descriptor"]["binding"]["operation"] =
            serde_json::json!("rotated");
        assert!(serde_json::from_value::<CredentialAccess>(unknown_operation).is_err());
        let mut missing_expiry = granted.clone();
        missing_expiry
            .as_object_mut()
            .expect("FULL response object")
            .remove("expiresAt");
        assert!(serde_json::from_value::<CredentialAccess>(missing_expiry).is_err());

        granted
            .as_object_mut()
            .expect("FULL response object")
            .insert(
                "grantEnvelope".to_owned(),
                serde_json::json!({
                    "descriptor": {
                        "protocolVersion": 2,
                        "cryptoSuiteId": "palladin-vault-xchacha-v1",
                        "purpose": "grantPayload",
                        "scope": {
                            "organizationId": "00112233-4455-4677-8899-aabbccddeeff",
                            "vaultId": "11112222-3333-4444-8555-666677778888",
                            "entryId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                            "grantOrRequestId": "12345678-1234-4234-8234-1234567890ab",
                            "agentId": "fedcba98-7654-4321-8765-abcdefabcdef",
                            "memberId": null
                        },
                        "resourceRevision": "1",
                        "keyVersion": 1,
                        "memberKeyGeneration": 1,
                        "binding": {
                            "entryRevision": "1",
                            "wrapperSuiteId": "palladin-x25519-sealed-box-v1",
                            "recipientKeyVersion": 2,
                            "recipientKeyFingerprint": "fingerprint",
                            "approvedMethods": 1,
                            "deliveryPolicy": 0,
                            "fieldSetCommitment": "commitment",
                            "expiresAt": null,
                            "remainingUses": null
                        }
                    },
                    "encodedSuitePayload": "payload",
                    "wrappedGrantDek": {
                        "descriptor": {
                            "protocolVersion": 2,
                            "wrapperSuiteId": "palladin-x25519-sealed-box-v1",
                            "purpose": "grantDek",
                            "scope": {
                                "organizationId": "00112233-4455-4677-8899-aabbccddeeff",
                                "vaultId": "11112222-3333-4444-8555-666677778888",
                                "entryId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                                "grantOrRequestId": "12345678-1234-4234-8234-1234567890ab",
                                "agentId": "fedcba98-7654-4321-8765-abcdefabcdef",
                                "memberId": null
                            },
                            "resourceRevision": "1",
                            "wrappedKeyVersion": 1,
                            "memberKeyGeneration": 1,
                            "recipientKeyKind": "agentX25519",
                            "recipientKeyVersion": 2,
                            "recipientFingerprint": "fingerprint",
                            "parentDescriptorHash": "hash"
                        },
                        "encodedSealedKeyPackage": "wrapped-grant-dek"
                    },
                    "fieldIds": ["key.value"]
                }),
            );
        assert!(serde_json::from_value::<CredentialAccess>(granted).is_err());
    }

    #[test]
    fn discovery_snapshot_contract_cannot_embed_entry_history() {
        let snapshot = serde_json::json!({
            "snapshotBaseSequence":"10",
            "items":[],
            "nextCursor":null,
            "history":[{"entryId":"secret-history"}]
        });

        assert!(serde_json::from_value::<AgentDiscoverySnapshotResponse>(snapshot).is_err());
    }

    #[test]
    fn manifest_list_requires_the_authenticated_agent_access_epoch_wrapper() {
        let response = serde_json::from_str::<AgentVaultManifestsResponse>(
            r#"{"agentAccessEpoch":7,"items":[]}"#,
        )
        .expect("current manifest response");
        assert_eq!(response.agent_access_epoch, 7);

        for rejected in [
            r#"{"items":[]}"#,
            r#"{"agentAccessEpoch":7,"items":[],"nextCursor":null}"#,
        ] {
            assert!(serde_json::from_str::<AgentVaultManifestsResponse>(rejected).is_err());
        }
    }
}
