use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use palladin_browser_bridge::{FormDiscoveryMap, FormDiscoveryMapDefinition};
use palladin_core::{
    host::ApiHost, public_store::MAX_VAULT_TRUST_ANCHORS, secret::OrganizationApiKey,
};
use palladin_crypto::{
    Ed25519Identity, EncryptedReasonContext, EncryptedReasonEnvelope, X25519Identity,
    encrypt_reason, generate_nonce_base64, sign_request,
};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Method, StatusCode, header::HeaderValue};
use thiserror::Error;

use crate::types::{
    AgentDiscoveryDeltaBody, AgentDiscoverySnapshotBody, AgentRegistrationResult,
    CreatePairingActivationBody, CredentialAccess, CredentialRequestBody, GetCredentialOptions,
    RegistrationBody, ReportCredentialStaleInput, StaleRequestBody,
};

const MAX_BOUNDED_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_FORM_MAP_RESPONSE_BYTES: usize = 128 * 1024;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitFormDiscoveryMapBody<'a> {
    domain: &'a str,
    login_url: &'a str,
    provider: &'a str,
    fingerprint: &'a str,
    map: &'a FormDiscoveryMapDefinition,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubmitFormDiscoveryMapResponse {
    map_id: String,
    map_version: u32,
    status: String,
    created_at: String,
}

const ENCODE_URI_COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(0x7f);

pub struct SigningContext {
    pub agent_id: String,
    pub identity: Ed25519Identity,
}

pub struct ApiClient {
    http: reqwest::Client,
    host: ApiHost,
    organization_api_key: OrganizationApiKey,
    encryption_public_key_base64: String,
    hostname: HeaderValue,
    signing: Option<SigningContext>,
}

impl ApiClient {
    pub fn encrypt_access_reason(
        &self,
        reason: &str,
        context: EncryptedReasonContext,
    ) -> Result<EncryptedReasonEnvelope, ApiError> {
        let signer = self.signing.as_ref().ok_or(ApiError::InvalidInput)?;
        encrypt_reason(reason, context, &signer.identity).map_err(|_| ApiError::InvalidInput)
    }

    pub fn new(
        host: ApiHost,
        organization_api_key: OrganizationApiKey,
        encryption_identity: &X25519Identity,
        hostname: &str,
        signing: Option<SigningContext>,
    ) -> Result<Self, ApiError> {
        Self::new_with_timeout(
            host,
            organization_api_key,
            encryption_identity,
            hostname,
            signing,
            Duration::from_secs(30),
        )
    }

    fn new_with_timeout(
        host: ApiHost,
        organization_api_key: OrganizationApiKey,
        encryption_identity: &X25519Identity,
        hostname: &str,
        signing: Option<SigningContext>,
        timeout: Duration,
    ) -> Result<Self, ApiError> {
        let hostname = HeaderValue::from_str(hostname).map_err(|_| ApiError::InvalidInput)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(timeout)
            .build()
            .map_err(|_| ApiError::Transport)?;
        Ok(Self {
            http,
            host,
            organization_api_key,
            encryption_public_key_base64: STANDARD.encode(encryption_identity.public_key()),
            hostname,
            signing,
        })
    }

    pub async fn register_agent(
        &self,
        name: Option<&str>,
        agent_type: Option<&str>,
        signing_public_key: Option<&[u8; 32]>,
    ) -> Result<AgentRegistrationResult, ApiError> {
        let mut extra = Vec::new();
        if let Some(name) = name {
            extra.push(("X-Agent-Name", header(name)?));
        }
        if let Some(agent_type) = agent_type.map(str::trim).filter(|value| !value.is_empty()) {
            extra.push(("X-Agent-Type", header(agent_type)?));
        }
        if let Some(public_key) = signing_public_key {
            extra.push(("X-Agent-Signing-Key", header(&STANDARD.encode(public_key))?));
        }

        let response = match self.send(Method::GET, "/api/agent/me", None, &extra).await {
            Ok(response) => response,
            Err(ApiError::Transport) => {
                return Ok(AgentRegistrationResult::Unreachable {
                    error: "API transport failed".to_owned(),
                });
            }
            Err(error) => return Err(error),
        };
        if response.status() == StatusCode::UNAUTHORIZED {
            return Ok(response
                .headers()
                .get("X-Agent-Id")
                .and_then(|value| value.to_str().ok())
                .map_or(AgentRegistrationResult::InvalidKey, |agent_id| {
                    AgentRegistrationResult::Pending {
                        agent_id: agent_id.to_owned(),
                    }
                }));
        }
        if !response.status().is_success() {
            return Ok(AgentRegistrationResult::Unreachable {
                error: format!("HTTP {}", response.status().as_u16()),
            });
        }
        let body: RegistrationBody = response
            .json()
            .await
            .map_err(|_| ApiError::InvalidResponse)?;
        match body.status.as_str() {
            "active" => Ok(AgentRegistrationResult::Active {
                agent_id: body.agent_id,
                name: body.name,
            }),
            "pending" => Ok(AgentRegistrationResult::Pending {
                agent_id: body.agent_id,
            }),
            "deactivated" => Ok(AgentRegistrationResult::Deactivated {
                agent_id: body.agent_id,
            }),
            _ => Err(ApiError::InvalidResponse),
        }
    }

    pub async fn list_vault_manifests(
        &self,
    ) -> Result<crate::AgentVaultManifestsResponse, ApiError> {
        let response = self
            .send(
                Method::GET,
                "/api/agent/vault-manifests",
                None,
                &[("X-Palladin-Vault-Protocol", HeaderValue::from_static("2"))],
            )
            .await?;
        decode_vault_manifests(response).await
    }

    pub async fn get_agent_discovery_snapshot(
        &self,
        vault_id: &str,
        cursor: Option<&str>,
        page_size: Option<u32>,
    ) -> Result<crate::AgentDiscoverySnapshotResponse, ApiError> {
        let body = serde_json::to_vec(&AgentDiscoverySnapshotBody {
            vault_id,
            cursor,
            page_size,
        })
        .map_err(|_| ApiError::InvalidInput)?;
        let path = format!(
            "/api/agent/vaults/{}/discovery/sync/snapshot",
            encode_component(vault_id)
        );
        let response = self.send_discovery_sync(&path, body).await?;
        decode_discovery_sync(response).await
    }

    pub async fn get_agent_discovery_delta(
        &self,
        vault_id: &str,
        after_sequence: Option<&str>,
        continuation_cursor: Option<&str>,
        page_size: Option<u32>,
    ) -> Result<crate::AgentDiscoveryDeltaResponse, ApiError> {
        let body = serde_json::to_vec(&AgentDiscoveryDeltaBody {
            vault_id,
            after_sequence,
            continuation_cursor,
            page_size,
        })
        .map_err(|_| ApiError::InvalidInput)?;
        let path = format!(
            "/api/agent/vaults/{}/discovery/sync/delta",
            encode_component(vault_id)
        );
        let response = self.send_discovery_sync(&path, body).await?;
        decode_discovery_sync(response).await
    }

    async fn send_discovery_sync(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<reqwest::Response, ApiError> {
        let response = self
            .send(
                Method::POST,
                path,
                Some(body),
                &[
                    ("X-Palladin-Vault-Protocol", HeaderValue::from_static("2")),
                    ("X-Palladin-Sync-Policy", HeaderValue::from_static("1")),
                ],
            )
            .await?;
        if response.headers().get("X-Palladin-Vault-Protocol")
            != Some(&HeaderValue::from_static("2"))
            || response.headers().get("X-Palladin-Sync-Policy")
                != Some(&HeaderValue::from_static("1"))
            || response.headers().get(reqwest::header::CONTENT_ENCODING)
                != Some(&HeaderValue::from_static("identity"))
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(response)
    }

    pub async fn create_pairing_activation(
        &self,
        activation_id: &str,
    ) -> Result<crate::AgentPairingActivationResponse, ApiError> {
        let body = serde_json::to_vec(&CreatePairingActivationBody { activation_id })
            .map_err(|_| ApiError::InvalidInput)?;
        let response = self
            .send(
                Method::POST,
                "/api/agent/pairing/activations",
                Some(body),
                &[("X-Palladin-Vault-Protocol", HeaderValue::from_static("2"))],
            )
            .await?;
        decode_bounded_success(response).await
    }

    pub async fn get_pairing_status(
        &self,
        activation_id: &str,
    ) -> Result<crate::AgentPairingStatusResponse, ApiError> {
        let path = format!(
            "/api/agent/pairing/activations/{}",
            encode_component(activation_id)
        );
        let response = self.send(Method::GET, &path, None, &[]).await?;
        decode_bounded_success(response).await
    }

    pub async fn get_form_discovery_map(
        &self,
        domain: &str,
        provider: &str,
    ) -> Result<Option<FormDiscoveryMap>, ApiError> {
        let path = format!(
            "/api/agent/form-discovery-maps/{}?provider={}",
            encode_component(domain),
            encode_component(provider),
        );
        let response = self.send(Method::GET, &path, None, &[]).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let (status, body) =
            read_bounded_response_with_limit(response, MAX_FORM_MAP_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(ApiError::Http(status.as_u16()));
        }
        let map: FormDiscoveryMap =
            serde_json::from_slice(&body).map_err(|_| ApiError::InvalidResponse)?;
        map.validate(domain, provider)
            .map_err(|_| ApiError::InvalidResponse)?;
        Ok(Some(map))
    }

    pub async fn submit_form_discovery_map_candidate(
        &self,
        domain: &str,
        login_url: &str,
        provider: &str,
        fingerprint: &str,
        map: &FormDiscoveryMapDefinition,
    ) -> Result<(), ApiError> {
        let body = serde_json::to_vec(&SubmitFormDiscoveryMapBody {
            domain,
            login_url,
            provider,
            fingerprint,
            map,
        })
        .map_err(|_| ApiError::InvalidInput)?;
        let response = self
            .send(
                Method::POST,
                "/api/agent/form-discovery-maps",
                Some(body),
                &[],
            )
            .await?;
        let (status, body) =
            read_bounded_response_with_limit(response, MAX_FORM_MAP_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(ApiError::Http(status.as_u16()));
        }
        let submitted: SubmitFormDiscoveryMapResponse =
            serde_json::from_slice(&body).map_err(|_| ApiError::InvalidResponse)?;
        if submitted.map_id.is_empty()
            || submitted.map_version == 0
            || !matches!(
                submitted.status.as_str(),
                "candidate" | "observed" | "verified"
            )
            || submitted.created_at.is_empty()
        {
            return Err(ApiError::InvalidResponse);
        }
        Ok(())
    }

    pub async fn get_credential(
        &self,
        vault_id: &str,
        entry_id: &str,
        options: &GetCredentialOptions,
    ) -> Result<CredentialAccess, ApiError> {
        let requested_methods = (!options.requested_methods.is_empty()).then(|| {
            options
                .requested_methods
                .iter()
                .map(|method| method.backend_name())
                .collect::<Vec<_>>()
                .join(", ")
        });
        let body = serde_json::to_vec(&CredentialRequestBody {
            encrypted_reason: options.encrypted_reason.as_ref(),
            method: options.method.map(|method| method.backend_name()),
            requested_methods,
        })
        .map_err(|_| ApiError::InvalidInput)?;
        let path = format!(
            "/api/agent/vaults/{}/entries/{}/credential",
            encode_component(vault_id),
            encode_component(entry_id)
        );
        let response = self
            .send(
                Method::POST,
                &path,
                Some(body),
                &[("X-Palladin-Vault-Protocol", HeaderValue::from_static("2"))],
            )
            .await?;
        match response.status() {
            StatusCode::OK
            | StatusCode::ACCEPTED
            | StatusCode::FORBIDDEN
            | StatusCode::TOO_MANY_REQUESTS => {
                response.json().await.map_err(|_| ApiError::InvalidResponse)
            }
            StatusCode::BAD_REQUEST if options.encrypted_reason.is_none() => {
                Err(ApiError::ReasonRequired)
            }
            StatusCode::BAD_REQUEST => Err(ApiError::Http(400)),
            status => Err(ApiError::Http(status.as_u16())),
        }
    }

    pub async fn get_grant_status(
        &self,
        vault_id: &str,
        grant_id: &str,
    ) -> Result<crate::GrantStatusResponse, ApiError> {
        let path = format!(
            "/api/agent/vaults/{}/grants/{}/status",
            encode_component(vault_id),
            encode_component(grant_id)
        );
        let response = self.send(Method::GET, &path, None, &[]).await?;
        decode_bounded_success(response).await
    }

    pub async fn report_credential_stale(
        &self,
        input: &ReportCredentialStaleInput,
    ) -> Result<(), ApiError> {
        let path = format!(
            "/api/agent/vaults/{}/entries/{}/credential-failure",
            encode_component(&input.vault_id),
            encode_component(&input.entry_id)
        );
        let body = serde_json::to_vec(&StaleRequestBody { code: input.code })
            .map_err(|_| ApiError::InvalidInput)?;
        let response = self.send(Method::POST, &path, Some(body), &[]).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ApiError::Http(response.status().as_u16()))
        }
    }

    pub async fn try_report_credential_stale(&self, input: &ReportCredentialStaleInput) -> bool {
        diagnostics_enabled() && self.report_credential_stale(input).await.is_ok()
    }

    async fn send(
        &self,
        method: Method,
        path_with_query: &str,
        body: Option<Vec<u8>>,
        extra_headers: &[(&'static str, HeaderValue)],
    ) -> Result<reqwest::Response, ApiError> {
        let url = self
            .host
            .endpoint(path_with_query)
            .map_err(|_| ApiError::InvalidInput)?;
        let attempts = if method == Method::GET { 3 } else { 1 };
        for attempt in 0..attempts {
            let mut api_key = header(self.organization_api_key.expose_for_authorized_request())?;
            api_key.set_sensitive(true);
            let mut request = self
                .http
                .request(method.clone(), url.clone())
                .header("X-Api-Key", api_key)
                .header("X-Agent-Key", &self.encryption_public_key_base64)
                .header("X-Agent-Hostname", self.hostname.clone());
            if let Some(body) = body.as_ref() {
                request = request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.clone());
            }
            for (name, value) in extra_headers {
                request = request.header(*name, value.clone());
            }
            if let Some(signing) = &self.signing {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| ApiError::Clock)?
                    .as_secs();
                let nonce = generate_nonce_base64().map_err(|_| ApiError::Signing)?;
                let signed = sign_request(
                    &signing.agent_id,
                    &signing.identity,
                    method.as_str(),
                    path_with_query,
                    timestamp,
                    &nonce,
                    body.as_deref().unwrap_or_default(),
                )
                .map_err(|_| ApiError::Signing)?;
                request = request
                    .header("X-Agent-Id", header(&signed.agent_id)?)
                    .header("X-Agent-Timestamp", signed.timestamp)
                    .header("X-Agent-Nonce", header(&signed.nonce_base64)?)
                    .header("X-Agent-Signature", header(&signed.signature_base64)?);
            }

            match request.send().await {
                Ok(response)
                    if attempt + 1 < attempts
                        && matches!(
                            response.status(),
                            StatusCode::BAD_GATEWAY
                                | StatusCode::SERVICE_UNAVAILABLE
                                | StatusCode::GATEWAY_TIMEOUT
                        ) => {}
                Ok(response) => return Ok(response),
                Err(_) if attempt + 1 < attempts => {}
                Err(_) => return Err(ApiError::Transport),
            }
            tokio::time::sleep(Duration::from_millis(50 * (attempt + 1) as u64)).await;
        }
        Err(ApiError::Transport)
    }
}

async fn decode_bounded_success<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, ApiError> {
    let (status, body) = read_bounded_response(response).await?;
    if !status.is_success() {
        return Err(ApiError::Http(status.as_u16()));
    }
    serde_json::from_slice(&body).map_err(|_| ApiError::InvalidResponse)
}

async fn read_bounded_response(
    response: reqwest::Response,
) -> Result<(StatusCode, Vec<u8>), ApiError> {
    read_bounded_response_with_limit(response, MAX_BOUNDED_RESPONSE_BYTES).await
}

async fn read_bounded_response_with_limit(
    mut response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<(StatusCode, Vec<u8>), ApiError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(ApiError::SizeLimitExceeded);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Transport)? {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(ApiError::SizeLimitExceeded);
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

async fn decode_vault_manifests(
    response: reqwest::Response,
) -> Result<crate::AgentVaultManifestsResponse, ApiError> {
    let (status, body) = read_bounded_response(response).await?;
    if !status.is_success() {
        return Err(ApiError::Http(status.as_u16()));
    }
    let manifests: crate::AgentVaultManifestsResponse =
        serde_json::from_slice(&body).map_err(|_| ApiError::InvalidResponse)?;
    enforce_vault_manifest_item_limit(manifests.items.len())?;
    Ok(manifests)
}

fn enforce_vault_manifest_item_limit(count: usize) -> Result<(), ApiError> {
    (count <= MAX_VAULT_TRUST_ANCHORS)
        .then_some(())
        .ok_or(ApiError::SizeLimitExceeded)
}

async fn decode_discovery_sync<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, ApiError> {
    let (status, body) = read_bounded_response(response).await?;
    match status {
        status if status.is_success() => {
            serde_json::from_slice(&body).map_err(|_| ApiError::InvalidResponse)
        }
        StatusCode::CONFLICT => {
            #[derive(serde::Deserialize)]
            #[serde(tag = "outcome", rename_all_fields = "camelCase", deny_unknown_fields)]
            enum Conflict {
                #[serde(rename = "sync-state-changed")]
                SyncStateChanged,
                #[serde(rename = "resetRequired")]
                ResetRequired {
                    current_sequence: String,
                    min_retained_sequence: String,
                    new_snapshot_required: bool,
                },
            }
            let conflict: Conflict =
                serde_json::from_slice(&body).map_err(|_| ApiError::InvalidResponse)?;
            match conflict {
                Conflict::SyncStateChanged => Err(ApiError::SyncStateChanged),
                Conflict::ResetRequired {
                    current_sequence,
                    min_retained_sequence,
                    new_snapshot_required: true,
                } => Err(ApiError::ResetRequired {
                    current_sequence,
                    min_retained_sequence,
                }),
                Conflict::ResetRequired { .. } => Err(ApiError::InvalidResponse),
            }
        }
        StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Outcome {
                outcome: String,
            }
            let outcome: Outcome =
                serde_json::from_slice(&body).map_err(|_| ApiError::InvalidResponse)?;
            match (status, outcome.outcome.as_str()) {
                (StatusCode::BAD_REQUEST, "invalid-cursor") => Err(ApiError::InvalidCursor),
                (StatusCode::PAYLOAD_TOO_LARGE, "size-limit-exceeded") => {
                    Err(ApiError::SizeLimitExceeded)
                }
                _ => Err(ApiError::InvalidResponse),
            }
        }
        status => Err(ApiError::Http(status.as_u16())),
    }
}

fn header(value: &str) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(value).map_err(|_| ApiError::InvalidInput)
}

fn encode_component(value: &str) -> String {
    utf8_percent_encode(value, ENCODE_URI_COMPONENT).to_string()
}

fn diagnostics_enabled() -> bool {
    diagnostics_enabled_for(std::env::var_os("PALLADIN_NO_DIAGNOSTICS").as_deref())
}

fn diagnostics_enabled_for(value: Option<&std::ffi::OsStr>) -> bool {
    value != Some(std::ffi::OsStr::new("1"))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApiError {
    #[error("API request input is invalid")]
    InvalidInput,
    #[error("API transport failed")]
    Transport,
    #[error("API returned HTTP {0}")]
    Http(u16),
    #[error("API returned an invalid response")]
    InvalidResponse,
    #[error("a reason is required to request access")]
    ReasonRequired,
    #[error("system clock is invalid")]
    Clock,
    #[error("request signing failed")]
    Signing,
    #[error("vault discovery sync requires a fresh snapshot")]
    ResetRequired {
        current_sequence: String,
        min_retained_sequence: String,
    },
    #[error("vault discovery authorization changed during synchronization")]
    SyncStateChanged,
    #[error("vault discovery sync cursor is invalid")]
    InvalidCursor,
    #[error("API response exceeds the size limit")]
    SizeLimitExceeded,
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use base64::{Engine, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use palladin_browser_bridge::{
        FormDiscoveryMapDefinition, InjectionControl, InjectionFormDefinition, InjectionFormField,
        InjectionFormStep, InjectionSubmit, InjectionSubmitKind,
    };
    use palladin_core::{host::ApiHost, secret::OrganizationApiKey};
    use palladin_crypto::{Ed25519Identity, X25519Identity, canonical_request};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        ApiClient, ApiError, MAX_BOUNDED_RESPONSE_BYTES, SigningContext, diagnostics_enabled_for,
        encode_component, enforce_vault_manifest_item_limit,
    };
    use crate::{
        AgentRegistrationResult, CredentialMethod, GetCredentialOptions,
        ReportCredentialStaleInput, StaleReasonCode,
    };

    #[test]
    fn path_encoding_matches_javascript_encode_uri_component() {
        assert_eq!(encode_component("a/b c!~*'()"), "a%2Fb%20c!~*'()");
    }

    #[test]
    fn diagnostics_opt_out_matches_the_typescript_contract() {
        assert!(!diagnostics_enabled_for(Some(std::ffi::OsStr::new("1"))));
        assert!(diagnostics_enabled_for(Some(std::ffi::OsStr::new("0"))));
        assert!(diagnostics_enabled_for(None));
    }

    #[tokio::test]
    async fn malformed_api_bodies_are_never_embedded_in_errors() {
        const CANARY: &str = "api-secret-canary-must-never-be-diagnosed";
        let (host, _) = response_server(vec![(200, CANARY)]).await;
        let error = client(&host, vec![1; 32], Duration::from_secs(1))
            .list_vault_manifests()
            .await
            .expect_err("malformed response");

        assert!(matches!(error, ApiError::InvalidResponse));
        assert!(!format!("{error:?} {error}").contains(CANARY));
    }

    #[tokio::test]
    async fn form_map_lookup_is_provider_bound_and_treats_not_found_as_cacheable_absence() {
        const MAP: &str = r#"{
          "mapId":"11111111-1111-4111-8111-111111111111","mapVersion":1,
          "domain":"accounts.google.com","loginUrl":"https://accounts.google.com/","provider":"playwright",
          "fingerprint":"f6f9b42f136c52f404542e6596a7aae9af598d05d49004a29615a83e3479aa35",
          "map":{"version":1,"form":{"version":1,"steps":[
            {"fields":[{"entryFieldId":"credential.username","selector":"input[autocomplete=\"username\"]","control":"username"}],"submit":{"action":"click","selector":"button[type=\"submit\"],input[type=\"submit\"]"},"waitFor":{"selector":"input[type=\"password\"]"}},
            {"fields":[{"entryFieldId":"credential.password","selector":"input[type=\"password\"]","control":"password"}],"submit":{"action":"click","selector":"button[type=\"submit\"],input[type=\"submit\"]"}}
          ]}},"updatedAt":"2026-08-15T12:00:00Z"
        }"#;
        let (host, requests) = response_server(vec![(200, MAP), (404, "")]).await;
        let api = client(&host, vec![21; 32], Duration::from_secs(1));

        let map = api
            .get_form_discovery_map("accounts.google.com", "playwright")
            .await
            .expect("lookup")
            .expect("map");
        assert_eq!(map.provider, "playwright");
        assert!(
            api.get_form_discovery_map("missing.example", "playwright")
                .await
                .expect("missing lookup")
                .is_none()
        );

        let requests = requests.lock().expect("requests");
        assert!(requests[0].starts_with(
            "GET /api/agent/form-discovery-maps/accounts.google.com?provider=playwright HTTP/1.1"
        ));
    }

    #[tokio::test]
    async fn form_map_candidate_submission_is_value_free_signed_and_not_retried() {
        let response = r#"{
          "mapId":"11111111-1111-4111-8111-111111111111",
          "mapVersion":7,
          "status":"candidate",
          "createdAt":"2026-08-15T12:00:00Z"
        }"#;
        let (host, requests) = response_server(vec![(200, response)]).await;
        let api = signed_client(&host, vec![22; 32], Duration::from_secs(1));
        let map = FormDiscoveryMapDefinition {
            version: 1,
            form: InjectionFormDefinition {
                version: 1,
                steps: vec![InjectionFormStep {
                    fields: vec![InjectionFormField {
                        entry_field_id: "credential.password".to_owned(),
                        selector: "input[type=password]".to_owned(),
                        control: InjectionControl::Password,
                    }],
                    submit: InjectionSubmit {
                        action: InjectionSubmitKind::Click,
                        selector: "button[type=submit]".to_owned(),
                    },
                    wait_for: None,
                }],
            },
            cookie_overlays: Vec::new(),
        };

        api.submit_form_discovery_map_candidate(
            "example.org",
            "https://example.org/pl/zaloguj",
            "future-browser",
            &"a".repeat(64),
            &map,
        )
        .await
        .expect("candidate submission");

        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("POST /api/agent/form-discovery-maps HTTP/1.1"));
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("x-agent-signature:")
        );
        assert!(requests[0].contains("\"provider\":\"future-browser\""));
        let (_, body) = requests[0]
            .split_once("\r\n\r\n")
            .expect("candidate request body");
        let payload: serde_json::Value =
            serde_json::from_str(body).expect("candidate request JSON");
        let field = payload
            .pointer("/map/form/steps/0/fields/0")
            .and_then(serde_json::Value::as_object)
            .expect("candidate field");
        assert_eq!(field.len(), 3);
        assert!(field.contains_key("entryFieldId"));
        assert!(field.contains_key("selector"));
        assert!(field.contains_key("control"));
    }

    #[tokio::test]
    async fn shared_organization_key_can_authenticate_distinct_agents() {
        let (host, requests) = response_server(vec![
            (200, r#"{"agentAccessEpoch":1,"items":[]}"#),
            (200, r#"{"agentAccessEpoch":1,"items":[]}"#),
        ])
        .await;
        let first = client(&host, vec![1; 32], Duration::from_secs(1));
        let second = client(&host, vec![2; 32], Duration::from_secs(1));

        first.list_vault_manifests().await.expect("first");
        second.list_vault_manifests().await.expect("second");

        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        let all_requests_contain_key = requests.iter().all(|request| {
            request
                .to_ascii_lowercase()
                .contains("x-api-key: pl_shared_organization_fixture")
        });
        assert!(
            all_requests_contain_key,
            "one or more requests omitted the organization credential"
        );
        let first_agent_key = header_value(&requests[0], "x-agent-key");
        let second_agent_key = header_value(&requests[1], "x-agent-key");
        assert_ne!(first_agent_key, second_agent_key);
    }

    #[tokio::test]
    async fn retries_safe_get_but_never_duplicates_mutating_post() {
        let (get_host, get_requests) = response_server(vec![
            (503, ""),
            (200, r#"{"agentAccessEpoch":1,"items":[]}"#),
        ])
        .await;
        signed_client(&get_host, vec![3; 32], Duration::from_secs(1))
            .list_vault_manifests()
            .await
            .expect("GET retry");
        {
            let get_requests = get_requests.lock().expect("requests");
            assert_eq!(get_requests.len(), 2);
            assert_ne!(
                header_value(&get_requests[0], "x-agent-nonce"),
                header_value(&get_requests[1], "x-agent-nonce")
            );
        }

        let (post_host, post_requests) = response_server(vec![(503, "")]).await;
        let error = client(&post_host, vec![4; 32], Duration::from_secs(1))
            .get_credential("vault", "entry", &GetCredentialOptions::default())
            .await
            .expect_err("POST must fail without retry");
        assert_eq!(error, ApiError::Http(503));
        assert_eq!(post_requests.lock().expect("requests").len(), 1);
    }

    #[tokio::test]
    async fn timeouts_are_bounded_and_post_is_not_retried() {
        let (get_host, get_count) = hanging_server().await;
        let get_error = client(&get_host, vec![5; 32], Duration::from_millis(20))
            .list_vault_manifests()
            .await
            .expect_err("GET timeout");
        assert_eq!(get_error, ApiError::Transport);
        assert_eq!(get_count.load(Ordering::SeqCst), 3);

        let (post_host, post_count) = hanging_server().await;
        let post_error = client(&post_host, vec![6; 32], Duration::from_millis(20))
            .get_credential("vault", "entry", &GetCredentialOptions::default())
            .await
            .expect_err("POST timeout");
        assert_eq!(post_error, ApiError::Transport);
        assert_eq!(post_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn signature_covers_the_exact_json_bytes_sent_on_the_wire() {
        let response = r#"{"access":"pending","grantId":"grant-1"}"#;
        let (host, requests) = response_server(vec![(202, response)]).await;
        let encryption = X25519Identity::from_private_bytes(vec![7; 32]).expect("X25519");
        let signing_identity = Ed25519Identity::from_seed(vec![9; 32]).expect("Ed25519");
        let public_key = *signing_identity.public_key();
        let api = ApiClient::new_with_timeout(
            ApiHost::parse(&host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &encryption,
            "fixture-host",
            Some(SigningContext {
                agent_id: "agent-123".to_owned(),
                identity: signing_identity,
            }),
            Duration::from_secs(1),
        )
        .expect("client");
        api.get_credential(
            "vault/one",
            "entry two",
            &GetCredentialOptions {
                encrypted_reason: None,
                method: Some(CredentialMethod::Exec),
                requested_methods: vec![CredentialMethod::Get, CredentialMethod::Inject],
            },
        )
        .await
        .expect("credential request");

        let requests = requests.lock().expect("requests");
        let request = &requests[0];
        let (headers, body) = request.split_once("\r\n\r\n").expect("HTTP request");
        assert_eq!(
            body,
            r#"{"method":"Exec","requestedMethods":"Get, Inject"}"#
        );
        assert!(!body.contains("reason"));
        assert!(headers.starts_with(
            "POST /api/agent/vaults/vault%2Fone/entries/entry%20two/credential HTTP/1.1"
        ));
        assert_eq!(header_value(headers, "x-agent-id"), "agent-123");
        assert_eq!(header_value(headers, "x-palladin-vault-protocol"), "2");

        let timestamp = header_value(headers, "x-agent-timestamp")
            .parse::<u64>()
            .expect("timestamp");
        let nonce = header_value(headers, "x-agent-nonce");
        let canonical = canonical_request(
            "POST",
            "/api/agent/vaults/vault%2Fone/entries/entry%20two/credential",
            timestamp,
            nonce,
            body.as_bytes(),
        )
        .expect("canonical");
        let signature_bytes = STANDARD
            .decode(header_value(headers, "x-agent-signature"))
            .expect("signature base64");
        let signature = Signature::from_slice(&signature_bytes).expect("signature");
        VerifyingKey::from_bytes(&public_key)
            .expect("public key")
            .verify(canonical.as_bytes(), &signature)
            .expect("valid signature");
    }

    #[tokio::test]
    async fn pairing_client_sends_protocol_gate_and_decodes_fail_closed_status() {
        let activation = r#"{"activationId":"aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa","organizationId":"11111111-1111-4111-8111-111111111111","agentId":"55555555-5555-4555-8555-555555555555","agentAccessEpoch":3,"agentX25519Fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","agentEd25519Fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expiresAt":"2026-07-26T19:00:00Z","candidateManifests":[]}"#;
        let status = r#"{"activationId":"aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa","status":"confirmed","expiresAt":"2026-07-26T19:00:00Z","confirmedPairingDigest":"ccccccccccccccccccccccccccccccccccccccccccc"}"#;
        let (host, requests) = response_server(vec![(200, activation), (200, status)]).await;
        let api = client(&host, vec![7; 32], Duration::from_secs(1));
        let created = api
            .create_pairing_activation("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
            .await
            .expect("activation");
        assert_eq!(created.agent_access_epoch, 3);
        let polled = api
            .get_pairing_status("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
            .await
            .expect("status");
        assert_eq!(polled.status, crate::AgentPairingStatus::Confirmed);
        let requests = requests.lock().expect("requests");
        assert!(requests[0].contains("x-palladin-vault-protocol: 2"));
        assert!(
            requests[0].ends_with(r#"{"activationId":"aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"}"#)
        );
        assert!(requests[1].starts_with(
            "GET /api/agent/pairing/activations/aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa HTTP/1.1"
        ));
    }

    #[tokio::test]
    async fn discovery_sync_sends_frozen_headers_and_decodes_exact_pages() {
        let snapshot = r#"{"snapshotBaseSequence":"12","items":[{"entryId":"33333333-3333-4333-8333-333333333333","kind":"head","agentDiscoveryRevision":"7","agentDiscovery":{"descriptor":{"protocolVersion":2,"cryptoSuiteId":"palladin-vault-xchacha-v1","purpose":"agentDiscovery","scope":{"organizationId":"11111111-1111-4111-8111-111111111111","vaultId":"22222222-2222-4222-8222-222222222222","entryId":"33333333-3333-4333-8333-333333333333","grantOrRequestId":null,"agentId":null,"memberId":null},"resourceRevision":"7","keyVersion":3,"memberKeyGeneration":5,"binding":{}},"encodedSuitePayload":"ciphertext"}}],"nextCursor":"next"}"#;
        let delta = r#"{"deltaUpperBound":"14","appliedThroughSequence":"14","items":[{"entryId":"33333333-3333-4333-8333-333333333333","kind":"tombstone","agentDiscoveryRevision":null,"agentDiscovery":null}],"continuationCursor":null}"#;
        let (host, requests) = response_server(vec![(200, snapshot), (200, delta)]).await;
        let api = client(&host, vec![13; 32], Duration::from_secs(1));

        let snapshot_page = api
            .get_agent_discovery_snapshot("vault/id", Some("cursor"), Some(50))
            .await
            .expect("snapshot");
        assert_eq!(snapshot_page.snapshot_base_sequence, "12");
        assert_eq!(snapshot_page.items.len(), 1);
        let delta_page = api
            .get_agent_discovery_delta("vault/id", Some("12"), None, Some(25))
            .await
            .expect("delta");
        assert_eq!(delta_page.applied_through_sequence, "14");

        let requests = requests.lock().expect("requests");
        assert!(requests.iter().all(|request| {
            request.contains("x-palladin-vault-protocol: 2")
                && request.contains("x-palladin-sync-policy: 1")
        }));
        assert!(
            requests[0]
                .starts_with("POST /api/agent/vaults/vault%2Fid/discovery/sync/snapshot HTTP/1.1")
        );
        assert!(requests[0].ends_with(r#"{"vaultId":"vault/id","cursor":"cursor","pageSize":50}"#));
        assert!(
            requests[1].ends_with(r#"{"vaultId":"vault/id","afterSequence":"12","pageSize":25}"#)
        );
    }

    #[tokio::test]
    async fn discovery_sync_maps_only_exact_structured_errors() {
        let (host, _) = response_server(vec![
            (409, r#"{"outcome":"sync-state-changed"}"#),
            (409, r#"{"outcome":"resetRequired","currentSequence":"20","minRetainedSequence":"10","newSnapshotRequired":true}"#),
            (409, r#"{"outcome":"state-changed"}"#),
            (400, r#"{"outcome":"invalid-cursor"}"#),
            (413, r#"{"outcome":"size-limit-exceeded"}"#),
            (404, r#"{"outcome":"invalid-cursor"}"#),
        ])
        .await;
        let api = client(&host, vec![14; 32], Duration::from_secs(1));

        assert_eq!(
            api.get_agent_discovery_snapshot("vault", None, None)
                .await
                .expect_err("concurrent authorization change"),
            ApiError::SyncStateChanged
        );

        assert_eq!(
            api.get_agent_discovery_delta("vault", Some("1"), None, None)
                .await
                .expect_err("reset"),
            ApiError::ResetRequired {
                current_sequence: "20".to_owned(),
                min_retained_sequence: "10".to_owned(),
            }
        );
        assert_eq!(
            api.get_agent_discovery_snapshot("vault", None, None)
                .await
                .expect_err("other conflicts remain fail-closed"),
            ApiError::InvalidResponse
        );
        assert_eq!(
            api.get_agent_discovery_snapshot("vault", Some("bad"), None)
                .await
                .expect_err("invalid cursor"),
            ApiError::InvalidCursor
        );
        assert_eq!(
            api.get_agent_discovery_delta("vault", Some("1"), None, None)
                .await
                .expect_err("size limit"),
            ApiError::SizeLimitExceeded
        );
        assert_eq!(
            api.get_agent_discovery_snapshot("vault", None, None)
                .await
                .expect_err("404 remains generic"),
            ApiError::Http(404)
        );
    }

    #[tokio::test]
    async fn discovery_sync_streaming_decoder_enforces_the_response_byte_budget() {
        let oversized = Box::leak("x".repeat(MAX_BOUNDED_RESPONSE_BYTES + 1).into_boxed_str());
        let (host, _) = response_server(vec![(200, oversized)]).await;
        let api = client(&host, vec![15; 32], Duration::from_secs(2));

        assert_eq!(
            api.get_agent_discovery_snapshot("vault", None, Some(200))
                .await
                .expect_err("oversized response"),
            ApiError::SizeLimitExceeded
        );

        let oversized_error =
            Box::leak("x".repeat(MAX_BOUNDED_RESPONSE_BYTES + 1).into_boxed_str());
        let (host, _) = response_server(vec![(409, oversized_error)]).await;
        let api = client(&host, vec![16; 32], Duration::from_secs(2));
        assert_eq!(
            api.get_agent_discovery_delta("vault", Some("1"), None, None)
                .await
                .expect_err("oversized error response"),
            ApiError::SizeLimitExceeded
        );
    }

    #[tokio::test]
    async fn vault_manifest_decoder_enforces_the_response_byte_budget() {
        let oversized = Box::leak("x".repeat(MAX_BOUNDED_RESPONSE_BYTES + 1).into_boxed_str());
        let (host, _) = response_server(vec![(200, oversized)]).await;
        let api = client(&host, vec![17; 32], Duration::from_secs(2));

        assert_eq!(
            api.list_vault_manifests()
                .await
                .expect_err("oversized manifest response"),
            ApiError::SizeLimitExceeded
        );
    }

    #[tokio::test]
    async fn protocol_control_responses_enforce_the_response_byte_budget() {
        let oversized = Box::leak("x".repeat(MAX_BOUNDED_RESPONSE_BYTES + 1).into_boxed_str());
        let (host, _) = response_server(vec![(200, oversized)]).await;
        let api = client(&host, vec![18; 32], Duration::from_secs(2));
        assert_eq!(
            api.create_pairing_activation("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                .await
                .expect_err("oversized pairing activation"),
            ApiError::SizeLimitExceeded
        );

        let (host, _) = response_server(vec![(200, oversized)]).await;
        let api = client(&host, vec![19; 32], Duration::from_secs(2));
        assert_eq!(
            api.get_pairing_status("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                .await
                .expect_err("oversized pairing status"),
            ApiError::SizeLimitExceeded
        );

        let (host, _) = response_server(vec![(200, oversized)]).await;
        let api = client(&host, vec![20; 32], Duration::from_secs(2));
        assert_eq!(
            api.get_grant_status("vault", "grant")
                .await
                .expect_err("oversized grant status"),
            ApiError::SizeLimitExceeded
        );
    }

    #[test]
    fn vault_manifest_decoder_enforces_the_profile_anchor_item_budget() {
        assert_eq!(
            enforce_vault_manifest_item_limit(
                palladin_core::public_store::MAX_VAULT_TRUST_ANCHORS + 1
            ),
            Err(ApiError::SizeLimitExceeded)
        );
    }

    #[tokio::test]
    async fn registration_failures_are_clean_unreachable_results() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let transport_result = client(
            &format!("http://{address}"),
            vec![10; 32],
            Duration::from_millis(20),
        )
        .register_agent(None, None, None)
        .await
        .expect("clean transport result");
        assert_eq!(
            transport_result,
            AgentRegistrationResult::Unreachable {
                error: "API transport failed".to_owned()
            }
        );

        let (host, _) = response_server(vec![(503, ""), (503, ""), (503, "")]).await;
        let http_result = client(&host, vec![11; 32], Duration::from_secs(1))
            .register_agent(None, None, None)
            .await
            .expect("clean HTTP result");
        assert_eq!(
            http_result,
            AgentRegistrationResult::Unreachable {
                error: "HTTP 503".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn best_effort_stale_report_never_propagates_transport_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let reported = client(
            &format!("http://{address}"),
            vec![12; 32],
            Duration::from_millis(20),
        )
        .try_report_credential_stale(&ReportCredentialStaleInput {
            vault_id: "vault".to_owned(),
            entry_id: "entry".to_owned(),
            code: StaleReasonCode::Manual,
        })
        .await;
        assert!(!reported);
    }

    fn client(host: &str, private_key: Vec<u8>, timeout: Duration) -> ApiClient {
        let identity = X25519Identity::from_private_bytes(private_key).expect("identity");
        ApiClient::new_with_timeout(
            ApiHost::parse(host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &identity,
            "fixture-host",
            None,
            timeout,
        )
        .expect("client")
    }

    fn signed_client(host: &str, private_key: Vec<u8>, timeout: Duration) -> ApiClient {
        let identity = X25519Identity::from_private_bytes(private_key).expect("identity");
        ApiClient::new_with_timeout(
            ApiHost::parse(host).expect("host"),
            OrganizationApiKey::new("pl_shared_organization_fixture".to_owned()),
            &identity,
            "fixture-host",
            Some(SigningContext {
                agent_id: "agent-retry".to_owned(),
                identity: Ed25519Identity::from_seed(vec![8; 32]).expect("signing identity"),
            }),
            timeout,
        )
        .expect("client")
    }

    async fn response_server(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let request = read_request(&mut stream).await;
                captured.lock().expect("requests").push(request);
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Service Unavailable"
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nX-Palladin-Vault-Protocol: 2\r\nX-Palladin-Sync-Policy: 1\r\nContent-Encoding: identity\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.expect("write");
            }
        });
        (format!("http://{address}"), requests)
    }

    async fn hanging_server() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let count = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&count);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _stream = stream;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                });
            }
        });
        (format!("http://{address}"), count)
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await.expect("read");
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..header_end + 4]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        String::from_utf8(bytes).expect("UTF-8 request")
    }

    fn header_value<'a>(request: &'a str, name: &str) -> &'a str {
        request
            .lines()
            .find_map(|line| {
                let (header_name, value) = line.split_once(':')?;
                header_name.eq_ignore_ascii_case(name).then(|| value.trim())
            })
            .expect("header")
    }
}
