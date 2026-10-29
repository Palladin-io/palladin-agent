use reqwest::{Method, StatusCode};
use serde::Deserialize;

use super::{ApiClient, ApiError, encode_component, read_bounded_response_with_limit};

const MAX_SUBMISSION_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_MANIFEST_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SUBMISSION_LIST_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Value-free rejection codes returned by Agent Submission endpoints as `{ "code": ... }`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionRejection {
    NoApprovers,
    ApproverKeyRotated,
    SubmissionConflict,
    UpdateNotGranted,
    RevisionReplay,
    RewrapChangedPayload,
    SubmissionNotUsable,
    InvalidInput,
    UnsupportedEntryType,
    InvalidAgentSignature,
    ContextMismatch,
    AgentNotActive,
    AgentKeyMismatch,
    ApproverKeyUnavailable,
    SubmissionNotPending,
    SubmissionNotFound,
}

impl SubmissionRejection {
    fn parse(code: &str) -> Option<Self> {
        Some(match code {
            "no-approvers" => Self::NoApprovers,
            "approver-key-rotated" => Self::ApproverKeyRotated,
            "submission-conflict" => Self::SubmissionConflict,
            "update-not-granted" => Self::UpdateNotGranted,
            "revision-replay" => Self::RevisionReplay,
            "rewrap-changed-payload" => Self::RewrapChangedPayload,
            "submission-not-usable" => Self::SubmissionNotUsable,
            "invalid-input" => Self::InvalidInput,
            "unsupported-entry-type" => Self::UnsupportedEntryType,
            "invalid-agent-signature" => Self::InvalidAgentSignature,
            "context-mismatch" => Self::ContextMismatch,
            "agent-not-active" => Self::AgentNotActive,
            "agent-key-mismatch" => Self::AgentKeyMismatch,
            "approver-key-unavailable" => Self::ApproverKeyUnavailable,
            "submission-not-pending" => Self::SubmissionNotPending,
            "submission-not-found" => Self::SubmissionNotFound,
            _ => return None,
        })
    }
}

/// Current authenticated Agent context plus the organization's approver manifests after a revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApproverManifestsResponse {
    pub organization_id: String,
    pub agent_key_version: u32,
    pub agent_access_epoch: String,
    /// Decoded strictly by `palladin_crypto::OrganizationApproverManifest`.
    pub manifests: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmissionAccepted {
    pub submission_id: String,
    pub state: String,
    pub submission_revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmissionDecision {
    pub vault_id: String,
    pub entry_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

/// Structural view of one of the Agent's own submissions; it never carries ciphertext.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentSubmissionSummary {
    pub submission_id: String,
    pub submission_kind: u16,
    pub entry_type: u16,
    pub target: serde_json::Value,
    pub state: String,
    pub agent_use_suspended: bool,
    pub submission_revision: String,
    pub approver_key_version: u32,
    pub current_approver_key_version: Option<u32>,
    #[serde(default)]
    pub decision: Option<SubmissionDecision>,
    pub created_at: String,
    #[serde(default)]
    pub decided_at: Option<String>,
}

/// Side-effect-free view of an Entry covered by the Agent's active grant. It never carries the
/// Entry type: the backend does not know it, and the approver client verifies the Agent's claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmissionTargetResponse {
    pub vault_id: String,
    pub entry_id: String,
    pub entry_revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentSubmissionList {
    pub items: Vec<AgentSubmissionSummary>,
}

impl ApiClient {
    pub async fn list_approver_manifests(
        &self,
        after_revision: Option<u64>,
    ) -> Result<ApproverManifestsResponse, ApiError> {
        let path = match after_revision {
            Some(revision) => format!("/api/agent/approver-manifests?afterRevision={revision}"),
            None => "/api/agent/approver-manifests".to_owned(),
        };
        let response = self.send(Method::GET, &path, None, &[]).await?;
        decode(response, MAX_MANIFEST_RESPONSE_BYTES).await
    }

    /// Sends the complete signed submission once. A transport failure is ambiguous; callers
    /// reconcile it through `list_submissions` and never resend different bytes for the ID.
    pub async fn create_submission(
        &self,
        submission: &serde_json::Value,
    ) -> Result<SubmissionAccepted, ApiError> {
        let body = serde_json::to_vec(submission).map_err(|_| ApiError::InvalidInput)?;
        let response = self
            .send(Method::POST, "/api/agent/submissions", Some(body), &[])
            .await?;
        decode(response, MAX_SUBMISSION_RESPONSE_BYTES).await
    }

    pub async fn rewrap_submission(
        &self,
        submission_id: &str,
        submission: &serde_json::Value,
    ) -> Result<SubmissionAccepted, ApiError> {
        let body = serde_json::to_vec(submission).map_err(|_| ApiError::InvalidInput)?;
        let path = format!(
            "/api/agent/submissions/{}/wrap",
            encode_component(submission_id)
        );
        let response = self.send(Method::PUT, &path, Some(body), &[]).await?;
        decode(response, MAX_SUBMISSION_RESPONSE_BYTES).await
    }

    /// Never creates a grant or access request and never consumes a grant use.
    pub async fn get_submission_target(
        &self,
        vault_id: &str,
        entry_id: &str,
    ) -> Result<SubmissionTargetResponse, ApiError> {
        let path = format!(
            "/api/agent/vaults/{}/entries/{}/submission-target",
            encode_component(vault_id),
            encode_component(entry_id)
        );
        let response = self.send(Method::GET, &path, None, &[]).await?;
        decode(response, MAX_SUBMISSION_RESPONSE_BYTES).await
    }

    pub async fn list_submissions(&self) -> Result<AgentSubmissionList, ApiError> {
        let response = self
            .send(Method::GET, "/api/agent/submissions", None, &[])
            .await?;
        decode(response, MAX_SUBMISSION_LIST_RESPONSE_BYTES).await
    }

    /// Fetches the complete transport object for a fresh pre-approval Inject. The caller decodes
    /// it strictly and verifies it before use; nothing is cached.
    pub async fn get_submission(&self, submission_id: &str) -> Result<serde_json::Value, ApiError> {
        let path = format!("/api/agent/submissions/{}", encode_component(submission_id));
        let response = self.send(Method::GET, &path, None, &[]).await?;
        decode(response, MAX_SUBMISSION_RESPONSE_BYTES).await
    }
}

#[derive(Deserialize)]
struct RejectionBody {
    code: String,
}

async fn decode<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<T, ApiError> {
    let (status, body) = read_bounded_response_with_limit(response, maximum_bytes).await?;
    if status.is_success() {
        return serde_json::from_slice(&body).map_err(|_| ApiError::InvalidResponse);
    }
    if status.is_client_error()
        && status != StatusCode::UNAUTHORIZED
        && let Some(rejection) = serde_json::from_slice::<RejectionBody>(&body)
            .ok()
            .and_then(|body| SubmissionRejection::parse(&body.code))
    {
        return Err(ApiError::SubmissionRejected(rejection));
    }
    Err(ApiError::Http(status.as_u16()))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use palladin_core::{host::ApiHost, secret::OrganizationApiKey};
    use palladin_crypto::X25519Identity;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    async fn server(responses: Vec<(u16, &'static str)>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut buffer = vec![0_u8; 64 * 1024];
                let mut read = 0;
                loop {
                    let count = stream.read(&mut buffer[read..]).await.expect("read");
                    read += count;
                    let text = String::from_utf8_lossy(&buffer[..read]);
                    if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|value| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if body.len() >= length {
                            break;
                        }
                    }
                    if count == 0 {
                        break;
                    }
                }
                captured
                    .lock()
                    .expect("requests")
                    .push(String::from_utf8_lossy(&buffer[..read]).into_owned());
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.expect("write");
            }
        });
        (format!("http://{address}"), requests)
    }

    fn client(host: &str) -> ApiClient {
        let identity = X25519Identity::from_private_bytes(vec![41; 32]).expect("identity");
        ApiClient::new_with_timeout(
            ApiHost::parse(host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &identity,
            "fixture-host",
            None,
            Duration::from_secs(2),
        )
        .expect("client")
    }

    #[tokio::test]
    async fn approver_manifests_are_requested_after_the_pinned_revision() {
        let (host, requests) = server(vec![(
            200,
            r#"{"organizationId":"0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a","agentKeyVersion":3,"agentAccessEpoch":"4","manifests":[]}"#,
        )])
        .await;
        let response = client(&host)
            .list_approver_manifests(Some(7))
            .await
            .expect("manifests");
        assert_eq!(response.agent_key_version, 3);
        assert_eq!(response.agent_access_epoch, "4");
        assert!(
            requests.lock().unwrap()[0]
                .starts_with("GET /api/agent/approver-manifests?afterRevision=7 HTTP/1.1")
        );
    }

    #[tokio::test]
    async fn contract_rejection_codes_are_mapped_and_unknown_codes_stay_http_errors() {
        let (host, _) = server(vec![
            (404, r#"{"code":"no-approvers"}"#),
            (409, r#"{"code":"approver-key-rotated"}"#),
            (409, r#"{"code":"submission-conflict"}"#),
            (403, r#"{"code":"update-not-granted"}"#),
            (409, r#"{"code":"something-new"}"#),
            (503, r#"{"code":"no-approvers"}"#),
        ])
        .await;
        let api = client(&host);
        let submission = serde_json::json!({});
        assert_eq!(
            api.list_approver_manifests(None).await.unwrap_err(),
            ApiError::SubmissionRejected(SubmissionRejection::NoApprovers)
        );
        for expected in [
            ApiError::SubmissionRejected(SubmissionRejection::ApproverKeyRotated),
            ApiError::SubmissionRejected(SubmissionRejection::SubmissionConflict),
            ApiError::SubmissionRejected(SubmissionRejection::UpdateNotGranted),
            ApiError::Http(409),
            ApiError::Http(503),
        ] {
            assert_eq!(
                api.create_submission(&submission).await.unwrap_err(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn submissions_are_posted_once_and_rewrap_targets_the_encoded_id() {
        let (host, requests) = server(vec![
            (503, ""),
            (
                201,
                r#"{"submissionId":"0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d","state":"pending","submissionRevision":"2"}"#,
            ),
        ])
        .await;
        let api = client(&host);
        let body = serde_json::json!({ "submissionId": "0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d" });
        assert_eq!(
            api.create_submission(&body).await.unwrap_err(),
            ApiError::Http(503),
            "a non-idempotent POST is never retried automatically"
        );
        let accepted = api
            .rewrap_submission("0d0d0d0d/../x", &body)
            .await
            .expect("re-wrap");
        assert_eq!(accepted.submission_revision, "2");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("POST /api/agent/submissions HTTP/1.1"));
        assert!(
            requests[1].starts_with("PUT /api/agent/submissions/0d0d0d0d%2F..%2Fx/wrap HTTP/1.1")
        );
    }

    #[tokio::test]
    async fn submission_list_decodes_structural_items() {
        let (host, requests) = server(vec![(
            200,
            r#"{"items":[{"submissionId":"0d0d0d0d-0d0d-4d0d-8d0d-0d0d0d0d0d0d","submissionKind":1,"entryType":1,"target":{"kind":"new"},"state":"pending","agentUseSuspended":false,"submissionRevision":"1","approverKeyVersion":1,"currentApproverKeyVersion":2,"createdAt":"2026-10-29T08:00:00Z"}]}"#,
        )])
        .await;
        let list = client(&host).list_submissions().await.expect("list");
        assert_eq!(list.items[0].current_approver_key_version, Some(2));
        assert!(requests.lock().unwrap()[0].starts_with("GET /api/agent/submissions HTTP/1.1"));
    }
}
