use palladin_crypto::EncryptedCredential;
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
    pub reason: Option<String>,
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
    pub reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_methods: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct StaleRequestBody<'a> {
    pub code: StaleReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'a str>,
}
