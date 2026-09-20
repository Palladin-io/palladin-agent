//! Private, value-free second phase. A prepared identifier is never a committed step.
use super::*;
use palladin_browser_bridge::live_login::{CancelSubmitRequest, SubmitReady, SubmitRequest};
use palladin_browser_bridge::local_transport::LocalSecureSession;
use palladin_browser_bridge::secure_transport::HostSecureSession;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommitCommand {
    protocol: String,
    #[serde(rename = "type")]
    message_type: String,
    not_after_monotonic_ns: String,
    request: SubmitRequest,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CancelCommand {
    protocol: String,
    #[serde(rename = "type")]
    message_type: String,
    request: CancelSubmitRequest,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum PendingCommand {
    Commit(CommitCommand),
    Cancel(CancelCommand),
}

pub(super) struct PendingBinding {
    pub prepared_transaction_id: String,
    pub grant_id: String,
    pub entry_id: String,
    pub expected_domain: String,
    pub form: InjectionFormDefinition,
    pub original_url: String,
    pub not_after_monotonic_ns: String,
}

pub(super) fn epoch_ms() -> Result<u64, NativeBrowserError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| NativeBrowserError::AuthorizationClockUnavailable)?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| NativeBrowserError::AuthorizationClockUnavailable)
}

pub(super) fn validate_commit(
    request: &SubmitRequest,
    expected: &PendingBinding,
    ready: &SubmitReady,
) -> Result<(), NativeBrowserError> {
    if request.protocol != INJECT_PROVIDER_PROTOCOL
        || request.message_type != "submit"
        || !valid_identifier(&request.transaction_id)
        || request.transaction_id == expected.prepared_transaction_id
        || request.prepared_transaction_id != expected.prepared_transaction_id
        || request.grant_id != expected.grant_id
        || request.entry_id != expected.entry_id
        || request.expected_domain != expected.expected_domain
        || request.submit_ready != *ready
        || request.expires_at <= epoch_ms()?
    {
        return Err(NativeBrowserError::InvalidMessage);
    }
    Ok(())
}

pub(super) async fn finish<R, W, F, G>(
    local: &mut UnixStream,
    local_session: &mut LocalSecureSession,
    extension_session: &mut HostSecureSession,
    native: (&mut R, &mut W),
    prepared: (&PendingBinding, &InjectResult),
    lifecycle_guard: &F,
) -> Result<InjectResult, NativeBrowserError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: Fn(Duration) -> Result<G, NativeBrowserError>,
{
    let (binding, result) = prepared;
    let ready = result
        .submit_ready
        .as_ref()
        .ok_or(NativeBrowserError::InvalidMessage)?;
    ready
        .validate(&binding.original_url, &binding.form)
        .map_err(|_| NativeBrowserError::InvalidMessage)?;
    let remaining = authorization_remaining_until(&binding.not_after_monotonic_ns)?
        .min(Duration::from_secs(10));
    let deadline = Instant::now() + remaining;
    let frame = local_session.seal(result)?;
    timeout_at(deadline, write_message(local, &frame))
        .await
        .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
    // Exactly one response is accepted. Missing ack/cancellation never replays the identifier.
    let next: LocalSecureFrame = timeout_at(deadline, read_message(local))
        .await
        .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
    let command: PendingCommand = local_session.open(&next)?;
    let (native_input, native_output) = native;
    let PendingCommand::Commit(mut command) = command else {
        let PendingCommand::Cancel(cancel) = command else {
            unreachable!()
        };
        if cancel.protocol != LOCAL_TRANSPORT_PROTOCOL
            || cancel.message_type != "submit.cancel"
            || cancel.request.protocol != INJECT_PROVIDER_PROTOCOL
            || cancel.request.message_type != "cancel-submit"
            || !valid_identifier(&cancel.request.transaction_id)
            || cancel.request.prepared_transaction_id != binding.prepared_transaction_id
            || cancel.request.pending_id != ready.pending_id
        {
            return Err(NativeBrowserError::InvalidMessage);
        }
        let frame = extension_session.seal(&cancel.request)?;
        timeout(
            Duration::from_millis(200),
            write_message(native_output, &frame),
        )
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
        return Err(NativeBrowserError::Unavailable);
    };
    if command.protocol != LOCAL_TRANSPORT_PROTOCOL || command.message_type != "submit.forward" {
        return Err(NativeBrowserError::InvalidMessage);
    }
    validate_commit(&command.request, binding, ready)?;
    let not_after = parse_not_after_monotonic_ns(&command.not_after_monotonic_ns)?.min(
        parse_not_after_monotonic_ns(&binding.not_after_monotonic_ns)?,
    );
    let remaining = authorization_remaining_from(not_after)?;
    let _lifecycle = lifecycle_guard(remaining.min(OPERATION_TIMEOUT))?;
    let remaining = authorization_remaining_from(not_after)?;
    // No extension operation may extend the native lease, even if a caller supplies a later wall expiry.
    command.request.expires_at = command
        .request
        .expires_at
        .min(epoch_ms()?.saturating_add(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)));
    if command.request.expires_at <= epoch_ms()? {
        return Err(NativeBrowserError::AuthorizationExpired);
    }
    let frame = extension_session.seal(&command.request)?;
    let response_deadline =
        write_authorized_extension_frame(native_output, &frame, &not_after.to_string()).await?;
    // Pending TTL bounds permission to commit, not discovery after an accepted click.
    // The original native authorization still bounds the reply; no commit is replayed.
    let response: SecureFrame = timeout_at(response_deadline, read_message(native_input))
        .await
        .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
    let result: InjectResult = extension_session.open(&response)?;
    validate_inject_result(&result, &command.request.transaction_id)?;
    if result.submit_ready.is_some() {
        return Err(NativeBrowserError::InvalidMessage);
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
