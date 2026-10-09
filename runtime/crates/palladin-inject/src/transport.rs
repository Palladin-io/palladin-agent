use palladin_browser_bridge::target_probe::{
    TargetProbeOutcome, TargetProbeRequest, TargetProbeResult, TargetProbeType,
};
use std::path::Path;
use std::time::Duration;

use nix::sys::time::TimeValLike;
use nix::time::{ClockId, clock_gettime};
use palladin_browser_bridge::InjectionFormDefinition;
use palladin_browser_bridge::discovery::{
    BrowserSessionInfo, BrowserStatusRequest, BrowserStatusRequestType, BrowserStatusResult,
};
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

pub(crate) async fn discover_browser_sessions(
    root: &Path,
    identity: &BrowserHostIdentity,
) -> Result<palladin_browser_bridge::discovery::BrowserDiscovery, NativeBrowserError> {
    use futures_util::stream::{self, StreamExt};
    let paths = palladin_browser_bridge::routing::browser_socket_paths(root)
        .map_err(|_| NativeBrowserError::Unavailable)?;
    let mut report = palladin_browser_bridge::discovery::BrowserDiscovery::default();
    let mut candidates = Vec::new();
    for path in paths {
        validate_socket_path(&path)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(NativeBrowserError::InvalidMessage)?;
        if name == "browser-bridge.sock" {
            // Pre-discovery hosts can exit even on a connection probe. Report
            // only the file's presence; never pretend it is an authenticated session.
            report.legacy_socket_present = true;
            continue;
        }
        let id = name
            .strip_prefix("b-")
            .and_then(|name| name.strip_suffix(".sock"))
            .filter(|id| palladin_browser_bridge::routing::valid_browser_session_id(id))
            .ok_or(NativeBrowserError::InvalidMessage)?
            .to_owned();
        candidates.push((path, id));
    }
    let mut queries = stream::iter(candidates)
        .map(|(path, id)| async move {
            timeout(HANDSHAKE_TIMEOUT, async {
                let stream = UnixStream::connect(&path)
                    .await
                    .map_err(|_| NativeBrowserError::Unavailable)?;
                let mut client = ExtensionClient::authenticate(stream, identity).await?;
                client.browser_status(&id).await
            })
            .await
            .map_err(|_| NativeBrowserError::Unavailable)?
        })
        .buffer_unordered(8);
    while let Some(result) = queries.next().await {
        match result {
            Ok(session) => report.sessions.push(session),
            Err(
                NativeBrowserError::Unavailable
                | NativeBrowserError::Framing(
                    palladin_browser_bridge::framing::FramingError::Transport,
                ),
            ) => report.unavailable_connections += 1,
            Err(error) => return Err(error),
        }
    }
    report
        .sessions
        .sort_by(|left, right| left.browser_session.cmp(&right.browser_session));
    Ok(report)
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    live_detection: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_form: Option<InjectionFormDefinition>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continue_live: Option<bool>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit_ready: Option<palladin_browser_bridge::live_login::SubmitReady>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<palladin_browser_bridge::live_login::LiveContinuation>,
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
    /// Prepare carries no credentials and never writes to the page. Only this
    /// phase may reconnect; send_inject must remain a single attempt.
    pub async fn connect_prepared(
        root: &Path,
        identity: &BrowserHostIdentity,
        nonce: &str,
        target: Option<BrowserTarget<'_>>,
        live_forms: bool,
    ) -> Result<(Self, PrepareResult), NativeBrowserError> {
        Self::connect_prepared_with_budget(
            root,
            identity,
            nonce,
            target,
            live_forms,
            Duration::from_secs(45),
            Duration::from_millis(250),
        )
        .await
    }

    async fn connect_prepared_with_budget(
        root: &Path,
        identity: &BrowserHostIdentity,
        nonce: &str,
        target: Option<BrowserTarget<'_>>,
        live_forms: bool,
        budget: Duration,
        mut delay: Duration,
    ) -> Result<(Self, PrepareResult), NativeBrowserError> {
        let deadline = Instant::now() + budget;
        loop {
            // A fresh authenticated channel and a fresh DOM preparation on each
            // attempt. Never reuse a failed session or any credential-bearing frame.
            let attempt = async {
                let mut client = match target {
                    Some(target) if target.browser_session.is_none() => {
                        Self::connect_exact_target(root, identity, nonce, target).await?
                    }
                    _ => {
                        Self::connect(
                            root,
                            identity,
                            target.and_then(|value| value.browser_session),
                        )
                        .await?
                    }
                };
                let prepared = client.prepare(nonce, target, live_forms).await?;
                Ok((client, prepared))
            };
            match timeout_at(deadline, attempt).await {
                Ok(Ok(prepared)) => return Ok(prepared),
                Ok(Err(
                    NativeBrowserError::Unavailable
                    | NativeBrowserError::Framing(
                        palladin_browser_bridge::framing::FramingError::Transport,
                    ),
                )) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(NativeBrowserError::ReconnectTimeout),
            }
            if timeout_at(deadline, tokio::time::sleep(delay))
                .await
                .is_err()
            {
                return Err(NativeBrowserError::ReconnectTimeout);
            }
            delay = delay.saturating_mul(2).min(Duration::from_secs(2));
        }
    }

    async fn connect_exact_target(
        root: &Path,
        identity: &BrowserHostIdentity,
        nonce: &str,
        target: BrowserTarget<'_>,
    ) -> Result<Self, NativeBrowserError> {
        use futures_util::stream::{self, StreamExt};
        let mut connections = browser_connections(root, None).await?;
        if connections.len() == 1 {
            return Self::authenticate(connections.pop().unwrap().1, identity).await;
        }
        let mut probes = stream::iter(connections)
            .map(|(path, socket)| async move {
                let mut client = Self::authenticate(socket, identity).await?;
                let frame = client.session.seal(&TargetProbeRequest {
                    protocol: INJECT_PROVIDER_PROTOCOL.into(),
                    message_type: TargetProbeType::Probe,
                    nonce: nonce.into(),
                    target_tab_id: target.tab_id,
                    target_url: target.page_url.into(),
                })?;
                timeout(HANDSHAKE_TIMEOUT, write_message(&mut client.stream, &frame))
                    .await
                    .map_err(|_| NativeBrowserError::Unavailable)??;
                let frame: LocalSecureFrame =
                    timeout(HANDSHAKE_TIMEOUT, read_message(&mut client.stream))
                        .await
                        .map_err(|_| NativeBrowserError::Unavailable)??;
                let response: TargetProbeResult = client.session.open(&frame)?;
                if response.protocol != INJECT_PROVIDER_PROTOCOL
                    || response.message_type != "target.probe.result"
                    || response.nonce != nonce
                {
                    return Err(NativeBrowserError::InvalidMessage);
                }
                Ok((path, response.outcome))
            })
            .buffer_unordered(8);
        let mut matched = None;
        while let Some(result) = probes.next().await {
            let (path, outcome) = result?;
            match outcome {
                TargetProbeOutcome::Match => {
                    if matched.is_some() {
                        return Err(NativeBrowserError::AmbiguousBrowser);
                    }
                    matched = Some(path);
                }
                TargetProbeOutcome::NoMatch => {}
                TargetProbeOutcome::Unavailable => {
                    return Err(NativeBrowserError::TargetResolutionUnavailable);
                }
            }
        }
        let path = matched.ok_or(NativeBrowserError::TargetNotFound)?;
        validate_socket_path(&path)?;
        let socket = timeout(HANDSHAKE_TIMEOUT, UnixStream::connect(path))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)?
            .map_err(|_| NativeBrowserError::Unavailable)?;
        // Preparation rechecks and pins the current document on this exact route.
        // No credential or submit message has been sent during discovery.
        Self::authenticate(socket, identity).await
    }

    pub async fn connect(
        root: &Path,
        identity: &BrowserHostIdentity,
        browser_session: Option<&str>,
    ) -> Result<Self, NativeBrowserError> {
        let stream = connect_browser_socket(root, browser_session).await?;
        Self::authenticate(stream, identity).await
    }

    async fn authenticate(
        mut stream: UnixStream,
        identity: &BrowserHostIdentity,
    ) -> Result<Self, NativeBrowserError> {
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

    async fn browser_status(
        &mut self,
        expected_session: &str,
    ) -> Result<BrowserSessionInfo, NativeBrowserError> {
        if !palladin_browser_bridge::routing::valid_browser_session_id(expected_session) {
            return Err(NativeBrowserError::InvalidMessage);
        }
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| NativeBrowserError::Unavailable)?;
        let nonce = hex::encode(nonce);
        let frame = self.session.seal(&BrowserStatusRequest {
            protocol: LOCAL_TRANSPORT_PROTOCOL.into(),
            message_type: BrowserStatusRequestType::Status,
            nonce: nonce.clone(),
        })?;
        timeout(HANDSHAKE_TIMEOUT, write_message(&mut self.stream, &frame))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let frame: LocalSecureFrame = timeout(HANDSHAKE_TIMEOUT, read_message(&mut self.stream))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let result: BrowserStatusResult = self.session.open(&frame)?;
        // The nonce comes from this request, and the locator from the selected
        // socket path. Neither expected binding is derived from the response.
        if result.protocol != LOCAL_TRANSPORT_PROTOCOL
            || result.message_type != "browser.status.result"
            || result.nonce != nonce
            || result.session.browser_session != expected_session
        {
            return Err(NativeBrowserError::InvalidMessage);
        }
        Ok(result.session)
    }

    pub async fn prepare(
        &mut self,
        nonce: &str,
        target: Option<BrowserTarget<'_>>,
        live_forms: bool,
    ) -> Result<PrepareResult, NativeBrowserError> {
        let request = PrepareRequest {
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "prepare",
            nonce,
            target_tab_id: target.map(|value| value.tab_id),
            target_url: target.map(|value| value.page_url),
            live_detection: live_forms.then_some(true),
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

    pub fn seal_submit(
        &mut self,
        request: &palladin_browser_bridge::live_login::SubmitRequest,
        not_after_monotonic_ns: u64,
    ) -> Result<SealedInject, NativeBrowserError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Command<'a> {
            protocol: &'static str,
            #[serde(rename = "type")]
            message_type: &'static str,
            not_after_monotonic_ns: String,
            request: &'a palladin_browser_bridge::live_login::SubmitRequest,
        }
        let frame = self.session.seal(&Command {
            protocol: LOCAL_TRANSPORT_PROTOCOL,
            message_type: "submit.forward",
            not_after_monotonic_ns: not_after_monotonic_ns.to_string(),
            request,
        })?;
        Ok(SealedInject {
            frame,
            transaction_id: request.transaction_id.clone(),
        })
    }

    /// Best-effort value-free cleanup. Never retries or authorizes a submit.
    pub async fn cancel_submit(&mut self, prepared_transaction_id: &str, pending_id: &str) {
        #[derive(Serialize)]
        struct Command {
            protocol: &'static str,
            #[serde(rename = "type")]
            message_type: &'static str,
            request: palladin_browser_bridge::live_login::CancelSubmitRequest,
        }
        let request = palladin_browser_bridge::live_login::CancelSubmitRequest {
            protocol: INJECT_PROVIDER_PROTOCOL.into(),
            message_type: "cancel-submit".into(),
            transaction_id: format!("cancel-{prepared_transaction_id}"),
            prepared_transaction_id: prepared_transaction_id.into(),
            pending_id: pending_id.into(),
        };
        if let Ok(frame) = self.session.seal(&Command {
            protocol: LOCAL_TRANSPORT_PROTOCOL,
            message_type: "submit.cancel",
            request,
        }) {
            let _ = timeout(
                Duration::from_millis(200),
                write_message(&mut self.stream, &frame),
            )
            .await;
        }
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
            .map_err(|_| inject_timeout_error(authorization_remaining))??;
        let response: LocalSecureFrame = timeout_at(deadline, read_message(&mut self.stream))
            .await
            .map_err(|_| inject_timeout_error(authorization_remaining))??;
        let result: InjectResult = self.session.open(&response)?;
        validate_inject_result(&result, &sealed.transaction_id)?;
        Ok(result)
    }
}

async fn connect_browser_socket(
    root: &Path,
    browser_session: Option<&str>,
) -> Result<UnixStream, NativeBrowserError> {
    let mut connections = browser_connections(root, browser_session).await?;
    if connections.len() != 1 {
        return Err(NativeBrowserError::AmbiguousBrowser);
    }
    Ok(connections.pop().unwrap().1)
}

async fn browser_connections(
    root: &Path,
    browser_session: Option<&str>,
) -> Result<Vec<(std::path::PathBuf, UnixStream)>, NativeBrowserError> {
    use palladin_browser_bridge::routing::{browser_socket_paths, select_browser_socket};

    let paths = match browser_session {
        Some(id) => vec![
            select_browser_socket(root, Some(id)).map_err(|_| NativeBrowserError::Unavailable)?,
        ],
        None => browser_socket_paths(root).map_err(|_| NativeBrowserError::Unavailable)?,
    };
    let mut connected = Vec::new();
    for path in paths {
        validate_socket_path(&path)?;
        let stream = match timeout(HANDSHAKE_TIMEOUT, UnixStream::connect(&path)).await {
            Ok(Ok(stream)) => stream,
            // A crashed host leaves its socket behind. Ignore only definite
            // absence; never unlink a path that a restarted host may now own.
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) =>
            {
                continue;
            }
            _ => return Err(NativeBrowserError::Unavailable),
        };
        validate_peer(&stream)?;
        connected.push((path, stream));
    }
    // Keep the connection used for discovery. A second connect would introduce
    // a host-replacement race and needlessly consume another listener slot.
    if connected.is_empty() {
        return Err(NativeBrowserError::Unavailable);
    }
    Ok(connected)
}

fn inject_timeout_error(authorization_remaining: Duration) -> NativeBrowserError {
    if authorization_remaining <= OPERATION_TIMEOUT {
        NativeBrowserError::AuthorizationExpired
    } else {
        NativeBrowserError::OperationTimeout
    }
}

pub fn epoch_expiry(remaining: Duration) -> Result<u64, NativeBrowserError> {
    if remaining.is_zero() {
        return Err(NativeBrowserError::AuthorizationExpired);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| NativeBrowserError::AuthorizationClockUnavailable)?;
    // Round down, never extend a sub-millisecond native lease.
    u64::try_from((now + remaining).as_millis())
        .map_err(|_| NativeBrowserError::AuthorizationExpired)
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
            | "target-tab-busy"
            | "target-url-mismatch"
            | "invalid-request"
            | "unsupported-live-detection"
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
            | "submit-ready"
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
        || (result.outcome != "injected" && result.continuation.is_some())
        || (result.outcome == "submit-ready") != result.submit_ready.is_some()
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
    #[error("multiple browser connections are available; select the target browser session")]
    AmbiguousBrowser,
    #[error(
        "no connected browser contains the exact requested tab and URL; refresh the trusted browser target"
    )]
    TargetNotFound,
    #[error(
        "a browser connection could not verify the target; specify its browser session or restore the connection"
    )]
    TargetResolutionUnavailable,
    #[error(
        "browser connection could not be restored before preparation timed out; no credential was sent"
    )]
    ReconnectTimeout,
    #[error("the authenticated Palladin browser extension is unavailable")]
    Unavailable,
    #[error("the authenticated browser message is invalid")]
    InvalidMessage,
    #[error("the local browser host socket is unsafe")]
    UnsafeSocket,
    #[error("the authenticated browser authorization expired")]
    AuthorizationExpired,
    #[error("the authenticated browser provider operation timed out")]
    OperationTimeout,
    #[error("the authenticated browser authorization clock is unavailable")]
    AuthorizationClockUnavailable,
    #[error(transparent)]
    Framing(#[from] palladin_browser_bridge::framing::FramingError),
    #[error(transparent)]
    Secure(#[from] palladin_browser_bridge::secure_transport::SecureTransportError),
}

#[cfg(test)]
#[path = "transport/reconnect_tests.rs"]
mod reconnect_tests;

#[cfg(test)]
#[path = "transport/discovery_tests.rs"]
mod discovery_tests;

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
    fn inject_timeout_preserves_the_budget_that_expired() {
        assert!(matches!(
            inject_timeout_error(OPERATION_TIMEOUT),
            NativeBrowserError::AuthorizationExpired
        ));
        assert!(matches!(
            inject_timeout_error(OPERATION_TIMEOUT + Duration::from_nanos(1)),
            NativeBrowserError::OperationTimeout
        ));
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
            expires_at: None,
            continue_live: None,
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
