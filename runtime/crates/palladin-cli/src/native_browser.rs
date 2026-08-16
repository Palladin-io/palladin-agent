use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use palladin_browser_bridge::InjectionFormDefinition;
use palladin_browser_bridge::framing::{read_message, write_message};
use palladin_browser_bridge::local_transport::{
    LocalClientHandshake, LocalSecureFrame, LocalSessionOpen, LocalSessionReady,
    accept_local_client,
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

use crate::browser::{CHROME_EXTENSION_ORIGIN, local_socket_path};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_WAIT_TIMEOUT: Duration = Duration::from_secs(300);
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const APPROVAL_TIMEOUT_MARGIN_MS: u64 = 30_000;
const GRANT_APPROVAL_TIMEOUT: Duration =
    Duration::from_millis(MAX_WAIT_MS + APPROVAL_TIMEOUT_MARGIN_MS);

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
    ) -> Result<SealedInject, NativeBrowserError> {
        let frame = self.session.seal(request)?;
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
    let open: ExtensionSessionOpen = timeout(HANDSHAKE_TIMEOUT, read_message(&mut native_input))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
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
    let injection: OwnedInjectRequest = local_session.open(&local_frame)?;
    validate_inject_request(&injection)?;
    let transaction_id = injection.transaction_id.clone();
    let _lifecycle = lifecycle_guard(OPERATION_TIMEOUT)?;
    let extension_frame = extension_session.seal(&injection)?;
    drop(injection);
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
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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
    #[error(transparent)]
    Framing(#[from] palladin_browser_bridge::framing::FramingError),
    #[error(transparent)]
    Secure(#[from] palladin_browser_bridge::secure_transport::SecureTransportError),
}

#[cfg(test)]
mod tests {
    use super::*;

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
            client.seal_inject(&request).expect("seal inject")
        };
        let encoded = serde_json::to_string(&sealed.frame).expect("sealed frame");
        assert!(!encoded.contains("fixture-sensitive-value"));
        assert_eq!(sealed.transaction_id, "transaction-1");
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
