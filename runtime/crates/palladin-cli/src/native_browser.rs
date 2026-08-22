use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use palladin_browser_bridge::InjectionFormDefinition;
use palladin_browser_bridge::framing::{read_message, write_message};
use palladin_browser_bridge::local_transport::{
    LOCAL_TRANSPORT_PROTOCOL, LocalClientHandshake, LocalSecureFrame, LocalSessionOpen,
    LocalSessionReady, accept_local_client,
};
use palladin_browser_bridge::secure_transport::{
    BrowserHostIdentity, ExtensionSessionOpen, HostSessionReady, INJECT_PROVIDER_PROTOCOL,
    SecureFrame,
};
use palladin_credential::wait::MAX_WAIT_MS;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{Instant, timeout, timeout_at};
use zeroize::Zeroize;

use crate::browser::{
    CHROME_EXTENSION_ORIGIN, PAIRING_DISCOVER_TYPE, PairingDiscoveryRequest, PairingOffer,
    local_socket_path,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_WAIT_TIMEOUT: Duration = Duration::from_secs(300);
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const APPROVAL_TIMEOUT_MARGIN_MS: u64 = 30_000;
const GRANT_APPROVAL_TIMEOUT: Duration =
    Duration::from_millis(MAX_WAIT_MS + APPROVAL_TIMEOUT_MARGIN_MS);
const MAX_LOCAL_INJECT_VALIDITY: Duration = Duration::from_millis(MAX_WAIT_MS);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareRequest<'a> {
    pub protocol: &'static str,
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub nonce: &'a str,
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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedPrepareRequest {
    protocol: String,
    #[serde(rename = "type")]
    message_type: String,
    nonce: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedInjectFieldValue {
    entry_field_id: String,
    value: String,
}

impl Drop for OwnedInjectFieldValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for OwnedInjectFieldValue {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedInjectRequest {
    protocol: String,
    #[serde(rename = "type")]
    message_type: String,
    transaction_id: String,
    grant_id: String,
    entry_id: String,
    expected_domain: String,
    form: InjectionFormDefinition,
    values: Vec<OwnedInjectFieldValue>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedLocalInjectCommand {
    protocol: String,
    #[serde(rename = "type")]
    message_type: String,
    not_after_monotonic_ns: String,
    request: OwnedInjectRequest,
}

impl Drop for OwnedLocalInjectCommand {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for OwnedLocalInjectCommand {
    fn zeroize(&mut self) {
        self.request.zeroize();
    }
}

impl Drop for OwnedInjectRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for OwnedInjectRequest {
    fn zeroize(&mut self) {
        for value in &mut self.values {
            value.zeroize();
        }
    }
}

impl Serialize for OwnedInjectFieldValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("InjectFieldValue", 2)?;
        state.serialize_field("entryFieldId", &self.entry_field_id)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
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
        let path = local_socket_path(root);
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

    pub async fn prepare(&mut self, nonce: &str) -> Result<PrepareResult, NativeBrowserError> {
        let request = PrepareRequest {
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "prepare",
            nonce,
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

    /// Seal the only plaintext-bearing request synchronously. Callers can then destroy every
    /// owned credential buffer before any socket write or response wait begins.
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

pub async fn serve_native_host<F, G>(
    root: &Path,
    identity: &BrowserHostIdentity,
    lifecycle_guard: F,
) -> Result<(), NativeBrowserError>
where
    F: Fn(Duration) -> Result<G, NativeBrowserError>,
{
    let mut native_input = tokio::io::stdin();
    let mut native_output = tokio::io::stdout();
    let initial: serde_json::Value = timeout(HANDSHAKE_TIMEOUT, read_message(&mut native_input))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
    let open = match parse_initial_native_message(initial)? {
        InitialNativeMessage::PairingDiscovery(request) => {
            let offer = PairingOffer::from_request(request, identity)
                .map_err(|_| NativeBrowserError::InvalidMessage)?;
            let _lifecycle = lifecycle_guard(HANDSHAKE_TIMEOUT)?;
            timeout(HANDSHAKE_TIMEOUT, write_message(&mut native_output, &offer))
                .await
                .map_err(|_| NativeBrowserError::Unavailable)??;
            return Ok(());
        }
        InitialNativeMessage::SecureSession(open) => open,
    };
    let (ready, mut extension_session) = identity.accept(CHROME_EXTENSION_ORIGIN, &open)?;
    let _lifecycle = lifecycle_guard(HANDSHAKE_TIMEOUT)?;
    timeout(
        HANDSHAKE_TIMEOUT,
        write_message::<HostSessionReady>(&mut native_output, &ready),
    )
    .await
    .map_err(|_| NativeBrowserError::Unavailable)??;
    drop(_lifecycle);

    let (listener, _guard) = bind_local_listener(root).await?;
    let (mut local, _) = timeout(CLIENT_WAIT_TIMEOUT, listener.accept())
        .await
        .map_err(|_| NativeBrowserError::Unavailable)?
        .map_err(|_| NativeBrowserError::Unavailable)?;
    validate_peer(&local)?;
    let local_open: LocalSessionOpen = timeout(HANDSHAKE_TIMEOUT, read_message(&mut local))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
    let (local_ready, mut local_session) = accept_local_client(identity, &local_open)?;
    let _lifecycle = lifecycle_guard(HANDSHAKE_TIMEOUT)?;
    timeout(HANDSHAKE_TIMEOUT, write_message(&mut local, &local_ready))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
    drop(_lifecycle);

    let local_frame: LocalSecureFrame = timeout(OPERATION_TIMEOUT, read_message(&mut local))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
    let prepare: OwnedPrepareRequest = local_session.open(&local_frame)?;
    validate_prepare(&prepare)?;
    let _lifecycle = lifecycle_guard(OPERATION_TIMEOUT)?;
    let extension_frame = extension_session.seal(&prepare)?;
    timeout(
        OPERATION_TIMEOUT,
        write_message(&mut native_output, &extension_frame),
    )
    .await
    .map_err(|_| NativeBrowserError::Unavailable)??;
    let extension_response: SecureFrame =
        timeout(OPERATION_TIMEOUT, read_message(&mut native_input))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
    let prepared: PrepareResult = extension_session.open(&extension_response)?;
    validate_prepare_result(&prepared, &prepare.nonce)?;
    let local_response = local_session.seal(&prepared)?;
    timeout(
        OPERATION_TIMEOUT,
        write_message(&mut local, &local_response),
    )
    .await
    .map_err(|_| NativeBrowserError::Unavailable)??;
    if prepared.outcome != "ready" {
        return Ok(());
    }
    drop(_lifecycle);

    let local_frame: LocalSecureFrame = timeout(GRANT_APPROVAL_TIMEOUT, read_message(&mut local))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
    let injection: OwnedLocalInjectCommand = local_session.open(&local_frame)?;
    let authorization_remaining = validate_local_inject_command(&injection)?;
    let transaction_id = injection.request.transaction_id.clone();
    let _lifecycle = lifecycle_guard(OPERATION_TIMEOUT.min(authorization_remaining))?;
    authorization_remaining_until(&injection.not_after_monotonic_ns)?;
    let extension_frame = extension_session.seal(&injection.request)?;
    let not_after_monotonic_ns = injection.not_after_monotonic_ns.clone();
    drop(injection);
    let extension_deadline = write_authorized_extension_frame(
        &mut native_output,
        &extension_frame,
        &not_after_monotonic_ns,
    )
    .await?;
    let extension_response: SecureFrame =
        timeout_at(extension_deadline, read_message(&mut native_input))
            .await
            .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
    let result: InjectResult = extension_session.open(&extension_response)?;
    validate_inject_result(&result, &transaction_id)?;
    let local_response = local_session.seal(&result)?;
    timeout(
        OPERATION_TIMEOUT,
        write_message(&mut local, &local_response),
    )
    .await
    .map_err(|_| NativeBrowserError::Unavailable)??;
    Ok(())
}

enum InitialNativeMessage {
    PairingDiscovery(PairingDiscoveryRequest),
    SecureSession(ExtensionSessionOpen),
}

fn parse_initial_native_message(
    value: serde_json::Value,
) -> Result<InitialNativeMessage, NativeBrowserError> {
    let message_type = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(serde_json::Value::as_str);
    if message_type == Some(PAIRING_DISCOVER_TYPE) {
        return serde_json::from_value(value)
            .map(InitialNativeMessage::PairingDiscovery)
            .map_err(|_| NativeBrowserError::InvalidMessage);
    }
    serde_json::from_value(value)
        .map(InitialNativeMessage::SecureSession)
        .map_err(|_| NativeBrowserError::InvalidMessage)
}

fn validate_prepare(request: &OwnedPrepareRequest) -> Result<(), NativeBrowserError> {
    if request.protocol != INJECT_PROVIDER_PROTOCOL
        || request.message_type != "prepare"
        || !valid_nonce(&request.nonce)
    {
        return Err(NativeBrowserError::InvalidMessage);
    }
    Ok(())
}

fn validate_prepare_result(result: &PrepareResult, nonce: &str) -> Result<(), NativeBrowserError> {
    let valid_outcome = matches!(
        result.outcome.as_str(),
        "ready" | "provider-unavailable" | "invalid-request"
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

fn validate_inject_request(request: &OwnedInjectRequest) -> Result<(), NativeBrowserError> {
    if request.protocol != INJECT_PROVIDER_PROTOCOL
        || request.message_type != "inject"
        || !valid_identifier(&request.transaction_id)
        || !valid_identifier(&request.grant_id)
        || !valid_identifier(&request.entry_id)
        || request.expected_domain.is_empty()
        || request.expected_domain.len() > 253
        || request.form.validate().is_err()
        || request.values.is_empty()
        || request.values.len() > 16
    {
        return Err(NativeBrowserError::InvalidMessage);
    }
    let form_ids: BTreeSet<&str> = request.form.field_ids().collect();
    let mut value_ids = BTreeSet::new();
    if request.values.iter().any(|value| {
        value.value.is_empty()
            || value.value.len() > 64 * 1024
            || !form_ids.contains(value.entry_field_id.as_str())
            || !value_ids.insert(value.entry_field_id.as_str())
    }) || value_ids != form_ids
    {
        return Err(NativeBrowserError::InvalidMessage);
    }
    Ok(())
}

fn validate_local_inject_command(
    command: &OwnedLocalInjectCommand,
) -> Result<Duration, NativeBrowserError> {
    if command.protocol != LOCAL_TRANSPORT_PROTOCOL || command.message_type != "inject.forward" {
        return Err(NativeBrowserError::InvalidMessage);
    }
    validate_inject_request(&command.request)?;
    let remaining = authorization_remaining_until(&command.not_after_monotonic_ns)?;
    if remaining > MAX_LOCAL_INJECT_VALIDITY {
        return Err(NativeBrowserError::InvalidMessage);
    }
    Ok(remaining)
}

fn authorization_remaining_until(value: &str) -> Result<Duration, NativeBrowserError> {
    authorization_remaining_from(parse_not_after_monotonic_ns(value)?)
}

fn parse_not_after_monotonic_ns(value: &str) -> Result<u64, NativeBrowserError> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(NativeBrowserError::InvalidMessage);
    }
    value
        .parse::<u64>()
        .map_err(|_| NativeBrowserError::InvalidMessage)
}

fn authorization_remaining_from(not_after: u64) -> Result<Duration, NativeBrowserError> {
    let now = monotonic_now_ns()?;
    let remaining = not_after
        .checked_sub(now)
        .filter(|remaining| *remaining != 0)
        .ok_or(NativeBrowserError::AuthorizationExpired)?;
    Ok(Duration::from_nanos(remaining))
}

type MonotonicNow = fn() -> Result<u64, NativeBrowserError>;

struct MonotonicDeadlineWriter<W, N = MonotonicNow> {
    inner: W,
    not_after_monotonic_ns: u64,
    monotonic_now: N,
}

impl<W> MonotonicDeadlineWriter<W, MonotonicNow> {
    fn new(inner: W, not_after_monotonic_ns: u64) -> Self {
        Self {
            inner,
            not_after_monotonic_ns,
            monotonic_now: monotonic_now_ns,
        }
    }
}

impl<W, N> MonotonicDeadlineWriter<W, N>
where
    N: Fn() -> Result<u64, NativeBrowserError>,
{
    fn ensure_authorized(&self) -> io::Result<()> {
        match (self.monotonic_now)() {
            Ok(now) if now < self.not_after_monotonic_ns => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "browser authorization expired",
            )),
        }
    }

    #[cfg(test)]
    fn with_clock(inner: W, not_after_monotonic_ns: u64, monotonic_now: N) -> Self {
        Self {
            inner,
            not_after_monotonic_ns,
            monotonic_now,
        }
    }
}

impl<W, N> tokio::io::AsyncWrite for MonotonicDeadlineWriter<W, N>
where
    W: tokio::io::AsyncWrite + Unpin,
    N: Fn() -> Result<u64, NativeBrowserError> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.ensure_authorized() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.ensure_authorized() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(context)
    }
}

/// This is the final secret-forwarding gate. The caller holds the shared lifecycle lock, and the
/// clock check occurs inside this helper immediately before the first extension write is polled.
async fn write_authorized_extension_frame<W>(
    writer: &mut W,
    frame: &SecureFrame,
    not_after_monotonic_ns: &str,
) -> Result<Instant, NativeBrowserError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let timer_sample = Instant::now();
    let not_after_monotonic_ns = parse_not_after_monotonic_ns(not_after_monotonic_ns)?;
    let authorization_remaining = authorization_remaining_from(not_after_monotonic_ns)?;
    let deadline = timer_sample + OPERATION_TIMEOUT.min(authorization_remaining);
    let mut guarded_writer = MonotonicDeadlineWriter::new(writer, not_after_monotonic_ns);
    let write = write_message(&mut guarded_writer, frame);
    tokio::pin!(write);
    let timer = tokio::time::sleep_until(deadline);
    tokio::pin!(timer);
    tokio::select! {
        biased;
        _ = &mut timer => return Err(NativeBrowserError::AuthorizationExpired),
        result = &mut write => result?,
    }
    Ok(deadline)
}

/// Read the system-wide Unix monotonic clock shared by the CLI and Native Messaging host.
pub fn monotonic_now_ns() -> Result<u64, NativeBrowserError> {
    let now = nix::time::ClockId::CLOCK_MONOTONIC
        .now()
        .map_err(|_| NativeBrowserError::AuthorizationClockUnavailable)?;
    let seconds = u64::try_from(now.tv_sec())
        .map_err(|_| NativeBrowserError::AuthorizationClockUnavailable)?;
    let nanoseconds = u64::try_from(now.tv_nsec())
        .map_err(|_| NativeBrowserError::AuthorizationClockUnavailable)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(NativeBrowserError::AuthorizationClockUnavailable)
}

/// Convert an already sampled monotonic time and remaining authorization into a not-after. The
/// caller samples before reading the remaining lease so this conversion can only narrow it.
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

fn valid_nonce(value: &str) -> bool {
    (32..=128).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

async fn bind_local_listener(
    root: &Path,
) -> Result<(UnixListener, SocketGuard), NativeBrowserError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let path = local_socket_path(root);
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if !metadata.file_type().is_socket()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
        {
            return Err(NativeBrowserError::UnsafeSocket);
        }
        if UnixStream::connect(&path).await.is_ok() {
            return Err(NativeBrowserError::Unavailable);
        }
        std::fs::remove_file(&path).map_err(|_| NativeBrowserError::UnsafeSocket)?;
    }
    let listener = UnixListener::bind(&path).map_err(|_| NativeBrowserError::Unavailable)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| NativeBrowserError::UnsafeSocket)?;
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| NativeBrowserError::UnsafeSocket)?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(NativeBrowserError::UnsafeSocket);
    }
    let guard = SocketGuard {
        path,
        inode: metadata.ino(),
    };
    Ok((listener, guard))
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

struct SocketGuard {
    path: PathBuf,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;

        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| metadata.ino() == self.inode)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Error)]
pub enum NativeBrowserError {
    #[error("the authenticated Palladin Chrome extension is unavailable")]
    Unavailable,
    #[error("the authenticated browser message is invalid")]
    InvalidMessage,
    #[error("the local browser host socket is unsafe")]
    UnsafeSocket,
    #[error("the authenticated browser host pairing was revoked")]
    Revoked,
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
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    use super::*;

    #[test]
    fn initial_native_message_accepts_only_exact_discovery_or_secure_session() {
        let discovery = serde_json::json!({
            "protocol": crate::browser::PAIRING_PROTOCOL,
            "type": crate::browser::PAIRING_DISCOVER_TYPE,
            "extensionOrigin": CHROME_EXTENSION_ORIGIN,
            "challenge": "00000000-0000-4000-8000-000000000001"
        });
        assert!(matches!(
            parse_initial_native_message(discovery),
            Ok(InitialNativeMessage::PairingDiscovery(_))
        ));

        let secure = serde_json::json!({
            "protocol": INJECT_PROVIDER_PROTOCOL,
            "type": "session.open",
            "extensionNonce": "A".repeat(43),
            "extensionEphemeralPublicKey": "A".repeat(43)
        });
        assert!(matches!(
            parse_initial_native_message(secure),
            Ok(InitialNativeMessage::SecureSession(_))
        ));

        let discovery_with_extra = serde_json::json!({
            "protocol": crate::browser::PAIRING_PROTOCOL,
            "type": crate::browser::PAIRING_DISCOVER_TYPE,
            "extensionOrigin": CHROME_EXTENSION_ORIGIN,
            "challenge": "00000000-0000-4000-8000-000000000001",
            "extra": true
        });
        assert!(matches!(
            parse_initial_native_message(discovery_with_extra),
            Err(NativeBrowserError::InvalidMessage)
        ));
    }

    #[derive(Default)]
    struct CountingWriter {
        bytes_written: usize,
    }

    impl tokio::io::AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.bytes_written += buffer.len();
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PendingThenReadyWriter {
        ready: Arc<AtomicBool>,
        polls: Arc<AtomicUsize>,
        bytes_written: Arc<AtomicUsize>,
        first_poll: Arc<tokio::sync::Notify>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl tokio::io::AsyncWrite for PendingThenReadyWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            if !self.ready.load(Ordering::SeqCst) {
                *self.waker.lock().expect("waker lock") = Some(context.waker().clone());
                self.first_poll.notify_one();
                return Poll::Pending;
            }
            self.bytes_written.fetch_add(buffer.len(), Ordering::SeqCst);
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn valid_form() -> InjectionFormDefinition {
        InjectionFormDefinition {
            version: 1,
            steps: vec![palladin_browser_bridge::InjectionFormStep {
                fields: vec![palladin_browser_bridge::InjectionFormField {
                    entry_field_id: "credential.password".to_owned(),
                    selector: "#password".to_owned(),
                    control: palladin_browser_bridge::InjectionControl::Password,
                }],
                submit: palladin_browser_bridge::InjectionSubmit {
                    action: palladin_browser_bridge::InjectionSubmitKind::Click,
                    selector: "#submit".to_owned(),
                },
                wait_for: None,
            }],
        }
    }

    fn owned_inject_request() -> OwnedInjectRequest {
        OwnedInjectRequest {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "inject".to_owned(),
            transaction_id: "transaction-1".to_owned(),
            grant_id: "grant-1".to_owned(),
            entry_id: "entry-1".to_owned(),
            expected_domain: "example.test".to_owned(),
            form: valid_form(),
            values: vec![OwnedInjectFieldValue {
                entry_field_id: "credential.password".to_owned(),
                value: "fixture-sensitive-value".to_owned(),
            }],
        }
    }

    #[test]
    fn host_operation_window_covers_maximum_grant_approval_wait_with_margin() {
        assert!(GRANT_APPROVAL_TIMEOUT > Duration::from_millis(MAX_WAIT_MS));
        assert_eq!(
            GRANT_APPROVAL_TIMEOUT,
            Duration::from_millis(MAX_WAIT_MS + APPROVAL_TIMEOUT_MARGIN_MS)
        );
        assert!(OPERATION_TIMEOUT < GRANT_APPROVAL_TIMEOUT);
    }

    #[test]
    fn invalid_prepare_and_inject_results_fail_closed() {
        let bad_prepare = PrepareResult {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "prepare.result".to_owned(),
            nonce: Some("A".repeat(32)),
            current_url: Some("https://example.test".to_owned()),
            outcome: "unexpected".to_owned(),
        };
        assert!(validate_prepare_result(&bad_prepare, &"A".repeat(32)).is_err());

        let missing_transaction = InjectResult {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "inject.result".to_owned(),
            transaction_id: None,
            outcome: "injected".to_owned(),
        };
        assert!(validate_inject_result(&missing_transaction, "tx").is_err());

        let stale_map = InjectResult {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "inject.result".to_owned(),
            transaction_id: Some("tx".to_owned()),
            outcome: "stale-form-map".to_owned(),
        };
        assert!(validate_inject_result(&stale_map, "tx").is_ok());

        let mut identifiers = owned_inject_request();
        identifiers.transaction_id = "transaction.v1".to_owned();
        identifiers.grant_id = "grant:1".to_owned();
        identifiers.entry_id = "entry_1".to_owned();
        assert!(validate_inject_request(&identifiers).is_ok());
    }

    #[test]
    fn decrypted_owned_field_value_has_explicit_zeroization() {
        let mut request = OwnedInjectRequest {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "inject".to_owned(),
            transaction_id: "transaction-1".to_owned(),
            grant_id: "grant-1".to_owned(),
            entry_id: "entry-1".to_owned(),
            expected_domain: "example.test".to_owned(),
            form: InjectionFormDefinition {
                version: 1,
                steps: Vec::new(),
            },
            values: vec![OwnedInjectFieldValue {
                entry_field_id: "credential.password".to_owned(),
                value: "fixture-sensitive-value".to_owned(),
            }],
        };
        request.zeroize();
        assert!(request.values[0].value.is_empty());
        assert_eq!(request.values[0].entry_field_id, "credential.password");
    }

    #[tokio::test]
    async fn sealed_inject_has_no_plaintext_owner_lifetime() {
        let identity = BrowserHostIdentity::from_secret_bytes([31_u8; 32]);
        let (open, pending) = LocalClientHandshake::start(&identity).expect("client open");
        let (ready, _host_session) = accept_local_client(&identity, &open).expect("host accept");
        let session = pending.finish(&ready).expect("client session");
        let (stream, _peer) = UnixStream::pair().expect("socket pair");
        let mut client = ExtensionClient { stream, session };
        let sealed = {
            let sensitive = "fixture-sensitive-value".to_owned();
            let form = InjectionFormDefinition {
                version: 1,
                steps: vec![palladin_browser_bridge::InjectionFormStep {
                    fields: vec![palladin_browser_bridge::InjectionFormField {
                        entry_field_id: "credential.password".to_owned(),
                        selector: "#password".to_owned(),
                        control: palladin_browser_bridge::InjectionControl::Password,
                    }],
                    submit: palladin_browser_bridge::InjectionSubmit {
                        action: palladin_browser_bridge::InjectionSubmitKind::Click,
                        selector: "#submit".to_owned(),
                    },
                    wait_for: None,
                }],
            };
            let request = InjectRequest {
                protocol: INJECT_PROVIDER_PROTOCOL,
                message_type: "inject",
                transaction_id: "transaction-1",
                grant_id: "grant-1",
                entry_id: "entry-1",
                expected_domain: "example.test",
                form: &form,
                values: vec![InjectFieldValue {
                    entry_field_id: "credential.password",
                    value: &sensitive,
                }],
            };
            let not_after = monotonic_now_ns()
                .and_then(|now| monotonic_not_after_ns(now, Duration::from_secs(1)))
                .expect("deadline");
            client
                .seal_inject(&request, not_after)
                .expect("seal inject")
        };
        let encoded = serde_json::to_string(&sealed.frame).expect("sealed frame");
        assert!(!encoded.contains("fixture-sensitive-value"));
        assert_eq!(sealed.transaction_id, "transaction-1");
    }

    #[tokio::test]
    async fn fully_queued_local_inject_expires_before_host_forward_and_wipes() {
        let identity = BrowserHostIdentity::from_secret_bytes([37_u8; 32]);
        let (open, pending) = LocalClientHandshake::start(&identity).expect("client open");
        let (ready, mut host_session) = accept_local_client(&identity, &open).expect("host accept");
        let mut client_session = pending.finish(&ready).expect("client session");
        let (mut sender, mut receiver) = UnixStream::pair().expect("socket pair");
        let form = valid_form();
        let request = InjectRequest {
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "inject",
            transaction_id: "transaction-queued",
            grant_id: "grant-queued",
            entry_id: "entry-queued",
            expected_domain: "example.test",
            form: &form,
            values: vec![InjectFieldValue {
                entry_field_id: "credential.password",
                value: "fixture-sensitive-queued-value",
            }],
        };
        let deadline = monotonic_now_ns()
            .and_then(|now| monotonic_not_after_ns(now, Duration::from_millis(20)))
            .expect("deadline");
        let command = LocalInjectCommand {
            protocol: LOCAL_TRANSPORT_PROTOCOL,
            message_type: "inject.forward",
            not_after_monotonic_ns: deadline.to_string(),
            request: &request,
        };
        let frame = client_session.seal(&command).expect("seal command");

        write_message(&mut sender, &frame)
            .await
            .expect("fully queue frame");
        tokio::time::sleep(Duration::from_millis(40)).await;

        let frame: LocalSecureFrame = read_message(&mut receiver).await.expect("queued frame");
        let mut command: OwnedLocalInjectCommand =
            host_session.open(&frame).expect("decrypt queued command");
        let authorization = validate_local_inject_command(&command);
        assert!(matches!(
            authorization,
            Err(NativeBrowserError::AuthorizationExpired)
        ));
        let extension_frame = SecureFrame {
            protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
            message_type: "secure".to_owned(),
            session_id: "test-session".to_owned(),
            sequence: "0".to_owned(),
            ciphertext: "AA".to_owned(),
        };
        let mut extension_output = CountingWriter::default();
        assert!(matches!(
            write_authorized_extension_frame(
                &mut extension_output,
                &extension_frame,
                &command.not_after_monotonic_ns,
            )
            .await,
            Err(NativeBrowserError::AuthorizationExpired)
        ));
        command.zeroize();
        assert_eq!(extension_output.bytes_written, 0);
        assert!(command.request.values[0].value.is_empty());
    }

    #[tokio::test]
    async fn deadline_writer_refuses_ready_second_poll_after_expiry() {
        use tokio::io::AsyncWriteExt;

        let ready = Arc::new(AtomicBool::new(false));
        let polls = Arc::new(AtomicUsize::new(0));
        let bytes_written = Arc::new(AtomicUsize::new(0));
        let first_poll = Arc::new(tokio::sync::Notify::new());
        let waker = Arc::new(Mutex::new(None));
        let clock = Arc::new(AtomicU64::new(100));
        let deadline = 200;
        let writer = PendingThenReadyWriter {
            ready: ready.clone(),
            polls: polls.clone(),
            bytes_written: bytes_written.clone(),
            first_poll: first_poll.clone(),
            waker: waker.clone(),
        };
        let writer_clock = clock.clone();
        let write = tokio::spawn(async move {
            let mut guarded = MonotonicDeadlineWriter::with_clock(writer, deadline, move || {
                Ok(writer_clock.load(Ordering::SeqCst))
            });
            guarded.write_all(b"fixture-frame").await
        });

        tokio::time::timeout(Duration::from_secs(1), first_poll.notified())
            .await
            .expect("first pending poll");
        clock.store(deadline, Ordering::SeqCst);
        ready.store(true, Ordering::SeqCst);
        waker
            .lock()
            .expect("waker lock")
            .take()
            .expect("pending waker")
            .wake();

        let error = write
            .await
            .expect("writer task")
            .expect_err("expired write must fail");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(bytes_written.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn local_inject_deadline_is_canonical_and_bounded() {
        let now = monotonic_now_ns().expect("clock");
        let mut command = OwnedLocalInjectCommand {
            protocol: LOCAL_TRANSPORT_PROTOCOL.to_owned(),
            message_type: "inject.forward".to_owned(),
            not_after_monotonic_ns: format!("0{}", now + 1_000_000_000),
            request: owned_inject_request(),
        };
        assert!(matches!(
            validate_local_inject_command(&command),
            Err(NativeBrowserError::InvalidMessage)
        ));
        command.not_after_monotonic_ns = (monotonic_now_ns().expect("clock")
            + u64::try_from((MAX_LOCAL_INJECT_VALIDITY + Duration::from_secs(1)).as_nanos())
                .expect("bounded duration"))
        .to_string();
        assert!(matches!(
            validate_local_inject_command(&command),
            Err(NativeBrowserError::InvalidMessage)
        ));
        assert!(matches!(
            monotonic_not_after_ns(now, MAX_LOCAL_INJECT_VALIDITY + Duration::from_nanos(1)),
            Err(NativeBrowserError::AuthorizationExpired)
        ));
    }

    #[tokio::test]
    async fn cli_and_host_complete_mutually_authenticated_prepare_over_socket() {
        let root = tempfile::tempdir().expect("root");
        let identity = BrowserHostIdentity::from_secret_bytes([41_u8; 32]);
        let (listener, _guard) = bind_local_listener(root.path()).await.expect("listener");
        let host_identity = BrowserHostIdentity::from_secret_bytes([41_u8; 32]);
        let host = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let open: LocalSessionOpen = read_message(&mut socket).await.expect("open");
            let (ready, mut session) =
                accept_local_client(&host_identity, &open).expect("authenticate client");
            write_message(&mut socket, &ready).await.expect("ready");
            let frame: LocalSecureFrame = read_message(&mut socket).await.expect("frame");
            let prepare: OwnedPrepareRequest = session.open(&frame).expect("prepare");
            validate_prepare(&prepare).expect("valid prepare");
            let result = PrepareResult {
                protocol: INJECT_PROVIDER_PROTOCOL.to_owned(),
                message_type: "prepare.result".to_owned(),
                nonce: Some(prepare.nonce),
                current_url: Some("https://example.test/login".to_owned()),
                outcome: "ready".to_owned(),
            };
            let frame = session.seal(&result).expect("seal result");
            write_message(&mut socket, &frame).await.expect("result");
        });
        let mut client = ExtensionClient::connect(root.path(), &identity)
            .await
            .expect("client");
        let nonce = "A".repeat(32);
        let result = client.prepare(&nonce).await.expect("prepare result");
        assert_eq!(result.outcome, "ready");
        assert_eq!(
            result.current_url.as_deref(),
            Some("https://example.test/login")
        );
        host.await.expect("host task");
    }

    #[tokio::test]
    async fn fake_socket_with_wrong_host_identity_is_rejected() {
        let root = tempfile::tempdir().expect("root");
        let identity = BrowserHostIdentity::from_secret_bytes([43_u8; 32]);
        let attacker = BrowserHostIdentity::from_secret_bytes([47_u8; 32]);
        let (listener, _guard) = bind_local_listener(root.path()).await.expect("listener");
        let fake_host = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let open: LocalSessionOpen = read_message(&mut socket).await.expect("open");
            assert!(accept_local_client(&attacker, &open).is_err());
        });
        assert!(
            ExtensionClient::connect(root.path(), &identity)
                .await
                .is_err()
        );
        fake_host.await.expect("fake host task");
    }
}
