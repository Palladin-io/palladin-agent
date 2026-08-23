use std::path::Path;
use std::time::Duration;

use nix::sys::time::TimeValLike;
use nix::time::{ClockId, clock_gettime};
use palladin_browser_bridge::InjectionFormDefinition;
use palladin_browser_bridge::framing::{read_message, write_message};
use palladin_browser_bridge::local_transport::{
    LOCAL_TRANSPORT_PROTOCOL, LocalClientHandshake, LocalSecureFrame, LocalSessionReady,
};
use palladin_browser_bridge::secure_transport::{BrowserHostIdentity, INJECT_PROVIDER_PROTOCOL};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::time::{Instant, timeout, timeout_at};

use crate::BrowserTarget;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_LOCAL_INJECT_VALIDITY: Duration = Duration::from_secs(5 * 60);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareRequest<'a> {
    protocol: &'static str,
    #[serde(rename = "type")]
    message_type: &'static str,
    nonce: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_tab_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_url: Option<&'a str>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareResult {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub nonce: Option<String>,
    pub current_url: Option<String>,
    pub outcome: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InjectFieldValue<'a> {
    pub entry_field_id: &'a str,
    pub value: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InjectRequest<'a> {
    pub protocol: &'static str,
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub transaction_id: &'a str,
    pub grant_id: &'a str,
    pub entry_id: &'a str,
    pub expected_domain: &'a str,
    pub form: &'a InjectionFormDefinition,
    pub values: Vec<InjectFieldValue<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalInjectCommand<'a> {
    protocol: &'static str,
    #[serde(rename = "type")]
    message_type: &'static str,
    not_after_monotonic_ns: String,
    request: &'a InjectRequest<'a>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectResult {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub transaction_id: Option<String>,
    pub outcome: String,
}

pub struct ExtensionClient {
    stream: UnixStream,
    session: palladin_browser_bridge::local_transport::LocalSecureSession,
}

pub struct SealedInject {
    frame: LocalSecureFrame,
    transaction_id: String,
}

impl ExtensionClient {
    pub async fn connect(
        root: &Path,
        identity: &BrowserHostIdentity,
    ) -> Result<Self, NativeBrowserError> {
        let path = root.join("browser-bridge.sock");
        validate_socket_path(&path)?;
        let mut stream = timeout(HANDSHAKE_TIMEOUT, UnixStream::connect(&path))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)?
            .map_err(|_| NativeBrowserError::Unavailable)?;
        validate_peer(&stream)?;
        let (open, pending) = LocalClientHandshake::start(identity)?;
        timeout(HANDSHAKE_TIMEOUT, write_message(&mut stream, &open))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let ready: LocalSessionReady = timeout(HANDSHAKE_TIMEOUT, read_message(&mut stream))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let session = pending.finish(&ready)?;
        Ok(Self { stream, session })
    }

    pub async fn prepare(
        &mut self,
        nonce: &str,
        target: Option<BrowserTarget<'_>>,
    ) -> Result<PrepareResult, NativeBrowserError> {
        let request = PrepareRequest {
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "prepare",
            nonce,
            target_tab_id: target.map(|value| value.tab_id),
            target_url: target.map(|value| value.page_url),
        };
        let frame = self.session.seal(&request)?;
        timeout(OPERATION_TIMEOUT, write_message(&mut self.stream, &frame))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let response: LocalSecureFrame = timeout(OPERATION_TIMEOUT, read_message(&mut self.stream))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let result: PrepareResult = self.session.open(&response)?;
        validate_prepare_result(&result, nonce)?;
        Ok(result)
    }

    /// Seal the only plaintext-bearing request synchronously so the caller can wipe every
    /// credential owner before any socket write or response wait begins.
    pub fn seal_inject(
        &mut self,
        request: &InjectRequest<'_>,
        not_after_monotonic_ns: u64,
    ) -> Result<SealedInject, NativeBrowserError> {
        let command = LocalInjectCommand {
            protocol: LOCAL_TRANSPORT_PROTOCOL,
            message_type: "inject.forward",
            not_after_monotonic_ns: not_after_monotonic_ns.to_string(),
            request,
        };
        let frame = self.session.seal(&command)?;
        Ok(SealedInject {
            frame,
            transaction_id: request.transaction_id.to_owned(),
        })
    }

    pub async fn send_inject(
        &mut self,
        sealed: SealedInject,
        authorization_remaining: Duration,
    ) -> Result<InjectResult, NativeBrowserError> {
        let operation_timeout = OPERATION_TIMEOUT.min(authorization_remaining);
        if operation_timeout.is_zero() {
            return Err(NativeBrowserError::AuthorizationExpired);
        }
        let deadline = Instant::now() + operation_timeout;
        timeout_at(deadline, write_message(&mut self.stream, &sealed.frame))
            .await
            .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
        let response: LocalSecureFrame = timeout_at(deadline, read_message(&mut self.stream))
            .await
            .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
        let result: InjectResult = self.session.open(&response)?;
        validate_inject_result(&result, &sealed.transaction_id)?;
        Ok(result)
    }
}

pub fn monotonic_now_ns() -> Result<u64, NativeBrowserError> {
    let now = clock_gettime(ClockId::CLOCK_MONOTONIC)
        .map_err(|_| NativeBrowserError::AuthorizationClockUnavailable)?;
    u64::try_from(now.num_nanoseconds())
        .map_err(|_| NativeBrowserError::AuthorizationClockUnavailable)
}

pub fn monotonic_not_after_ns(
    sampled_now_ns: u64,
    authorization_remaining: Duration,
) -> Result<u64, NativeBrowserError> {
    let remaining_ns = u64::try_from(authorization_remaining.as_nanos())
        .map_err(|_| NativeBrowserError::AuthorizationExpired)?;
    if remaining_ns == 0 || authorization_remaining > MAX_LOCAL_INJECT_VALIDITY {
        return Err(NativeBrowserError::AuthorizationExpired);
    }
    sampled_now_ns
        .checked_add(remaining_ns)
        .ok_or(NativeBrowserError::AuthorizationExpired)
}

fn validate_prepare_result(result: &PrepareResult, nonce: &str) -> Result<(), NativeBrowserError> {
    let valid_outcome = matches!(
        result.outcome.as_str(),
        "ready"
            | "provider-unavailable"
            | "target-tab-unavailable"
            | "target-url-mismatch"
            | "invalid-request"
    );
    if result.protocol != INJECT_PROVIDER_PROTOCOL
        || result.message_type != "prepare.result"
        || !valid_outcome
        || result.nonce.as_deref() != Some(nonce)
        || (result.outcome == "ready" && result.current_url.is_none())
        || (result.outcome != "ready" && result.current_url.is_some())
    {
        return Err(NativeBrowserError::InvalidMessage);
    }
    Ok(())
}

fn validate_inject_result(
    result: &InjectResult,
    transaction_id: &str,
) -> Result<(), NativeBrowserError> {
    let valid_outcome = matches!(
        result.outcome.as_str(),
        "injected"
            | "rejected"
            | "no-password-field"
            | "no-submit-control"
            | "origin-mismatch"
            | "insecure-origin"
            | "ambiguous-form"
            | "provider-unavailable"
            | "stale-form-map"
    );
    if result.protocol != INJECT_PROVIDER_PROTOCOL
        || result.message_type != "inject.result"
        || result.transaction_id.as_deref() != Some(transaction_id)
        || !valid_outcome
    {
        return Err(NativeBrowserError::InvalidMessage);
    }
    Ok(())
}

fn validate_socket_path(path: &Path) -> Result<(), NativeBrowserError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path).map_err(|_| NativeBrowserError::Unavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(NativeBrowserError::UnsafeSocket);
    }
    Ok(())
}

fn validate_peer(stream: &UnixStream) -> Result<(), NativeBrowserError> {
    let credentials = stream
        .peer_cred()
        .map_err(|_| NativeBrowserError::UnsafeSocket)?;
    if credentials.uid() != nix::unistd::geteuid().as_raw() {
        return Err(NativeBrowserError::UnsafeSocket);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum NativeBrowserError {
    #[error("the authenticated Palladin browser extension is unavailable")]
    Unavailable,
    #[error("the authenticated browser message is invalid")]
    InvalidMessage,
    #[error("the local browser host socket is unsafe")]
    UnsafeSocket,
    #[error("the authenticated browser authorization expired")]
    AuthorizationExpired,
    #[error("the authenticated browser authorization clock is unavailable")]
    AuthorizationClockUnavailable,
    #[error(transparent)]
    Framing(#[from] palladin_browser_bridge::framing::FramingError),
    #[error(transparent)]
    Secure(#[from] palladin_browser_bridge::secure_transport::SecureTransportError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use palladin_browser_bridge::{
        InjectionControl, InjectionFormField, InjectionFormStep, InjectionSubmit,
        InjectionSubmitKind,
    };

    #[test]
    fn local_inject_deadline_is_bounded() {
        assert_eq!(
            monotonic_not_after_ns(1_000, Duration::from_nanos(20)).expect("deadline"),
            1_020
        );
        assert!(monotonic_not_after_ns(1_000, Duration::ZERO).is_err());
        assert!(monotonic_not_after_ns(1_000, Duration::from_secs(301)).is_err());
    }

    #[test]
    fn provider_frame_contains_only_declared_field_values() {
        let form = InjectionFormDefinition {
            version: 1,
            steps: vec![InjectionFormStep {
                fields: vec![InjectionFormField {
                    entry_field_id: "credential.password".to_owned(),
                    selector: "#password".to_owned(),
                    control: InjectionControl::Password,
                }],
                submit: InjectionSubmit {
                    action: InjectionSubmitKind::PressEnter,
                    selector: "#password".to_owned(),
                },
                wait_for: None,
            }],
        };
        let wire = InjectRequest {
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "inject",
            transaction_id: "transaction",
            grant_id: "grant",
            entry_id: "entry",
            expected_domain: "example.com",
            form: &form,
            values: vec![InjectFieldValue {
                entry_field_id: "credential.password",
                value: "fixture-password-not-production",
            }],
        };
        let encoded = serde_json::to_value(wire).expect("provider frame");
        assert!(encoded.get("username").is_none());
        assert!(encoded.get("password").is_none());
        assert_eq!(encoded["values"][0]["entryFieldId"], "credential.password");
    }
}
