use super::*;
use palladin_browser_bridge::local_transport::LocalSecureSession;
use palladin_browser_bridge::secure_transport::HostSecureSession;

pub(super) async fn serve_inject_flow<R, W, F, G>(
    local: &mut UnixStream,
    local_session: &mut LocalSecureSession,
    extension_session: &mut HostSecureSession,
    native: (&mut R, &mut W),
    prepared: (&OwnedPrepareRequest, &PrepareResult),
    lifecycle_guard: &F,
) -> Result<(), NativeBrowserError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: Fn(Duration) -> Result<G, NativeBrowserError>,
{
    let (native_input, native_output) = native;
    let (prepare, prepared) = prepared;
    let local_frame: LocalSecureFrame = timeout(GRANT_APPROVAL_TIMEOUT, read_message(local))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
    let mut next_frame = local_frame;
    let mut flow = None;
    let mut binding: Option<(String, String, String)> = None;
    let mut chain_not_after = None;
    loop {
        let mut injection: OwnedLocalInjectCommand = local_session.open(&next_frame)?;
        let authorization_remaining = validate_local_inject_command(&injection)?;
        let continuing = injection.request.continue_live == Some(true);
        let requested_binding = (
            injection.request.grant_id.clone(),
            injection.request.entry_id.clone(),
            injection.request.expected_domain.clone(),
        );
        if let Some(expected) = binding.as_ref() {
            if !continuing || expected != &requested_binding {
                return Err(NativeBrowserError::InvalidMessage);
            }
        } else if continuing {
            if prepare.live_detection != Some(true) {
                return Err(NativeBrowserError::InvalidMessage);
            }
            flow = Some(
                palladin_browser_bridge::live_login::LiveLoginFlow::new(
                    prepared
                        .current_url
                        .as_deref()
                        .ok_or(NativeBrowserError::InvalidMessage)?,
                    prepared
                        .live_form
                        .clone()
                        .ok_or(NativeBrowserError::InvalidMessage)?,
                )
                .map_err(|_| NativeBrowserError::InvalidMessage)?,
            );
            binding = Some(requested_binding);
            chain_not_after = Some(monotonic_not_after_ns(
                monotonic_now_ns()?,
                authorization_remaining.min(palladin_browser_bridge::live_login::LIVE_FLOW_TIMEOUT),
            )?);
        }
        if let Some(flow) = flow.as_ref()
            && flow.form() != &injection.request.form
        {
            return Err(NativeBrowserError::InvalidMessage);
        }
        if let Some(deadline) = chain_not_after {
            injection.not_after_monotonic_ns =
                parse_not_after_monotonic_ns(&injection.not_after_monotonic_ns)?
                    .min(deadline)
                    .to_string();
        }
        let transaction_id = injection.request.transaction_id.clone();
        let _lifecycle = lifecycle_guard(OPERATION_TIMEOUT.min(authorization_remaining))?;
        authorization_remaining_until(&injection.not_after_monotonic_ns)?;
        let extension_frame = extension_session.seal(&injection.request)?;
        let not_after_monotonic_ns = injection.not_after_monotonic_ns.clone();
        drop(injection);
        let extension_deadline = write_authorized_extension_frame(
            native_output,
            &extension_frame,
            &not_after_monotonic_ns,
        )
        .await?;
        let extension_response: SecureFrame =
            timeout_at(extension_deadline, read_message(native_input))
                .await
                .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
        let result: InjectResult = extension_session.open(&extension_response)?;
        validate_inject_result(&result, &transaction_id)?;
        let continue_ready = if result.outcome == "injected" {
            if let Some(flow) = flow.as_mut() {
                flow.submitted()
                    .map_err(|_| NativeBrowserError::InvalidMessage)?;
                if let Some(continuation) = result.continuation.as_ref() {
                    flow.advance(continuation)
                        .map_err(|_| NativeBrowserError::InvalidMessage)?
                } else {
                    false
                }
            } else {
                if result.continuation.is_some() {
                    return Err(NativeBrowserError::InvalidMessage);
                }
                false
            }
        } else {
            false
        };
        let local_response = local_session.seal(&result)?;
        timeout(OPERATION_TIMEOUT, write_message(local, &local_response))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        drop(_lifecycle);
        if !continue_ready {
            break;
        }
        let remaining = authorization_remaining_until(&not_after_monotonic_ns)?;
        next_frame = timeout(remaining, read_message(local))
            .await
            .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
    }

    Ok(())
}

#[cfg(test)]
mod tests;
