use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use palladin_core::{host::ApiHost, secret::OrganizationApiKey};
use palladin_crypto::{Ed25519Identity, X25519Identity, generate_nonce_base64, sign_request};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Method, StatusCode, header::HeaderValue};
use thiserror::Error;

use crate::types::{
    AgentRegistrationResult, CredentialAccess, CredentialRequestBody, EntrySearchResult,
    GetCredentialOptions, InjectFailureUpload, RegistrationBody, ReportCredentialStaleInput,
    StaleRequestBody,
};

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

    pub async fn search_entries(
        &self,
        query: &str,
        cursor: Option<&str>,
        page_size: Option<u32>,
    ) -> Result<EntrySearchResult, ApiError> {
        let path = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("query", query);
            if let Some(cursor) = cursor {
                serializer.append_pair("cursor", cursor);
            }
            if let Some(page_size) = page_size {
                serializer.append_pair("pageSize", &page_size.to_string());
            }
            format!("/api/agent/entries?{}", serializer.finish())
        };
        let response = self.send(Method::GET, &path, None, &[]).await?;
        decode_success(response).await
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
            reason: options.reason.as_deref(),
            method: options.method.map(|method| method.backend_name()),
            requested_methods,
        })
        .map_err(|_| ApiError::InvalidInput)?;
        let path = format!(
            "/api/agent/vaults/{}/entries/{}/credential",
            encode_component(vault_id),
            encode_component(entry_id)
        );
        let response = self.send(Method::POST, &path, Some(body), &[]).await?;
        match response.status() {
            StatusCode::OK
            | StatusCode::ACCEPTED
            | StatusCode::FORBIDDEN
            | StatusCode::TOO_MANY_REQUESTS => {
                response.json().await.map_err(|_| ApiError::InvalidResponse)
            }
            StatusCode::BAD_REQUEST => Err(ApiError::ReasonRequired),
            status => Err(ApiError::Http(status.as_u16())),
        }
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
        let body = serde_json::to_vec(&StaleRequestBody {
            code: input.code,
            note: input.note.as_deref(),
        })
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

    pub async fn upload_inject_failure(&self, body: &InjectFailureUpload) -> bool {
        if !diagnostics_enabled() {
            return false;
        }
        let body = match serde_json::to_vec(body) {
            Ok(body) => body,
            Err(_) => return false,
        };
        self.send(Method::POST, "/api/agent/inject-failures", Some(body), &[])
            .await
            .is_ok_and(|response| response.status().is_success())
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

async fn decode_success<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, ApiError> {
    if !response.status().is_success() {
        return Err(ApiError::Http(response.status().as_u16()));
    }
    response.json().await.map_err(|_| ApiError::InvalidResponse)
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

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
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
    use palladin_core::{host::ApiHost, secret::OrganizationApiKey};
    use palladin_crypto::{Ed25519Identity, X25519Identity, canonical_request};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{ApiClient, ApiError, SigningContext, diagnostics_enabled_for, encode_component};
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
    async fn shared_organization_key_can_authenticate_distinct_agents() {
        let (host, requests) = response_server(vec![
            (200, r#"{"items":[],"nextCursor":null}"#),
            (200, r#"{"items":[],"nextCursor":null}"#),
        ])
        .await;
        let first = client(&host, vec![1; 32], Duration::from_secs(1));
        let second = client(&host, vec![2; 32], Duration::from_secs(1));

        first.search_entries("ab", None, None).await.expect("first");
        second
            .search_entries("ab", None, None)
            .await
            .expect("second");

        let requests = requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| {
            request
                .to_ascii_lowercase()
                .contains("x-api-key: pl_shared_organization_fixture")
        }));
        let first_agent_key = header_value(&requests[0], "x-agent-key");
        let second_agent_key = header_value(&requests[1], "x-agent-key");
        assert_ne!(first_agent_key, second_agent_key);
    }

    #[tokio::test]
    async fn retries_safe_get_but_never_duplicates_mutating_post() {
        let (get_host, get_requests) =
            response_server(vec![(503, ""), (200, r#"{"items":[],"nextCursor":null}"#)]).await;
        signed_client(&get_host, vec![3; 32], Duration::from_secs(1))
            .search_entries("ab", None, None)
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
            .search_entries("ab", None, None)
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
                reason: Some("because".to_owned()),
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
            r#"{"reason":"because","method":"Exec","requestedMethods":"Get, Inject"}"#
        );
        assert!(headers.starts_with(
            "POST /api/agent/vaults/vault%2Fone/entries/entry%20two/credential HTTP/1.1"
        ));
        assert_eq!(header_value(headers, "x-agent-id"), "agent-123");

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
            note: None,
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
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
