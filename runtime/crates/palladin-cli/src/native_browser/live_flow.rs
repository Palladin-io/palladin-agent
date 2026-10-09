use super::*;
use palladin_browser_bridge::local_transport::LocalSecureSession;
#[cfg(test)]
use palladin_browser_bridge::secure_transport::HostSecureSession;

#[cfg(test)]
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
    let mut exchange = super::exchange::BrowserExchange::Direct {
        session: extension_session,
        input: native.0,
        output: native.1,
    };
    serve_inject_flow_with(
        local,
        local_session,
        &mut exchange,
        prepared,
        lifecycle_guard,
    )
    .await
}

pub(super) async fn serve_inject_flow_with<R, W, F, G>(
    local: &mut UnixStream,
    local_session: &mut LocalSecureSession,
    exchange: &mut super::exchange::BrowserExchange<'_, R, W>,
    prepared: (&OwnedPrepareRequest, &PrepareResult),
    lifecycle_guard: &F,
) -> Result<(), NativeBrowserError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: Fn(Duration) -> Result<G, NativeBrowserError>,
{
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
        let pending_binding =
            palladin_browser_bridge::live_login::is_deferred(&injection.request.form).then(|| {
                super::deferred::PendingBinding {
                    prepared_transaction_id: transaction_id.clone(),
                    grant_id: injection.request.grant_id.clone(),
                    entry_id: injection.request.entry_id.clone(),
                    expected_domain: injection.request.expected_domain.clone(),
                    form: injection.request.form.clone(),
                    original_url: flow
                        .as_ref()
                        .map(|flow| flow.current_url().to_owned())
                        .unwrap_or_default(),
                    not_after_monotonic_ns: injection.not_after_monotonic_ns.clone(),
                }
            });
        let mut lifecycle = Some(lifecycle_guard(
            OPERATION_TIMEOUT.min(authorization_remaining),
        )?);
        if let Some(expiry) = injection.request.expires_at.as_mut() {
            let remaining = authorization_remaining_until(&injection.not_after_monotonic_ns)?;
            *expiry = (*expiry).min(
                super::deferred::epoch_ms()?
                    .saturating_add(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)),
            );
        }
        authorization_remaining_until(&injection.not_after_monotonic_ns)?;
        let queued =
            exchange.enqueue(&injection.request, Some(&injection.not_after_monotonic_ns))?;
        let not_after_monotonic_ns = injection.not_after_monotonic_ns.clone();
        drop(injection);
        let mut result: InjectResult = exchange.receive(queued, local).await?;
        validate_inject_result(&result, &transaction_id)?;
        if result.outcome == "submit-ready" {
            let binding = pending_binding
                .as_ref()
                .ok_or(NativeBrowserError::InvalidMessage)?;
            // Release the initial lifecycle guard before the caller reacquires authorization.
            drop(lifecycle.take());
            result = super::deferred::finish_with(
                local,
                local_session,
                exchange,
                (binding, &result),
                lifecycle_guard,
            )
            .await?;
        } else if pending_binding.is_some() && result.outcome == "injected" {
            // A deferred fill cannot bypass its explicit commit phase.
            return Err(NativeBrowserError::InvalidMessage);
        }
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
        drop(lifecycle);
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
