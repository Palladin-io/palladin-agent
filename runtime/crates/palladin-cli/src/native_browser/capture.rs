use super::*;
use palladin_browser_bridge::capture::{CapturePlan, CaptureRequest, CaptureResult};
use palladin_browser_bridge::local_transport::LocalSecureSession;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaptureCommand {
    protocol: String,
    #[serde(rename = "type")]
    message_type: String,
    not_after_monotonic_ns: String,
    request: CaptureRequest,
}

impl ExtensionClient {
    pub async fn prepare_capture(
        &mut self,
        nonce: &str,
        plan: &CapturePlan,
    ) -> Result<PrepareResult, NativeBrowserError> {
        plan.validate()
            .map_err(|_| NativeBrowserError::InvalidMessage)?;
        // captureMode is local-only; the native host strips it before ordinary prepare.
        let request = serde_json::json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"prepare","nonce":nonce,"targetTabId":plan.target_tab_id,"targetUrl":plan.target_url,"liveDetection":false,"captureMode":true});
        let frame = self.session.seal(&request)?;
        timeout(OPERATION_TIMEOUT, write_message(&mut self.stream, &frame))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let frame: LocalSecureFrame = timeout(OPERATION_TIMEOUT, read_message(&mut self.stream))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let response: PrepareResult = self.session.open(&frame)?;
        validate_prepare_result(&response, nonce)?;
        if response.outcome == "ready"
            && response.current_url.as_deref() != Some(plan.target_url.as_str())
        {
            return Err(NativeBrowserError::InvalidMessage);
        }
        Ok(response)
    }
    pub async fn capture(
        &mut self,
        request: CaptureRequest,
        not_after_monotonic_ns: u64,
    ) -> Result<CaptureResult, NativeBrowserError> {
        request
            .validate()
            .map_err(|_| NativeBrowserError::InvalidMessage)?;
        let command = CaptureCommand {
            protocol: LOCAL_TRANSPORT_PROTOCOL.into(),
            message_type: "capture.forward".into(),
            not_after_monotonic_ns: not_after_monotonic_ns.to_string(),
            request,
        };
        let remaining = authorization_remaining_until(&command.not_after_monotonic_ns)?;
        let frame = self.session.seal(&command)?;
        let deadline = Instant::now() + remaining.min(OPERATION_TIMEOUT);
        timeout_at(deadline, write_message(&mut self.stream, &frame))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let frame: LocalSecureFrame = timeout_at(deadline, read_message(&mut self.stream))
            .await
            .map_err(|_| NativeBrowserError::Unavailable)??;
        let result: CaptureResult = self.session.open(&frame)?;
        result
            .validate(&command.request)
            .map_err(|_| NativeBrowserError::InvalidMessage)?;
        authorization_remaining_until(&command.not_after_monotonic_ns)?;
        Ok(result)
    }
}

pub(super) async fn serve_capture<R, W, F, G>(
    local: &mut UnixStream,
    local_session: &mut LocalSecureSession,
    exchange: &mut super::exchange::BrowserExchange<'_, R, W>,
    prepare: &OwnedPrepareRequest,
    lifecycle_guard: &F,
) -> Result<(), NativeBrowserError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: Fn(Duration) -> Result<G, NativeBrowserError>,
{
    let frame: LocalSecureFrame = timeout(OPERATION_TIMEOUT, read_message(local))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
    let command: CaptureCommand = local_session.open(&frame)?;
    command
        .request
        .validate()
        .map_err(|_| NativeBrowserError::InvalidMessage)?;
    if command.protocol != LOCAL_TRANSPORT_PROTOCOL
        || command.message_type != "capture.forward"
        || prepare.target_url.as_deref() != Some(command.request.target_url.as_str())
    {
        return Err(NativeBrowserError::InvalidMessage);
    }
    let remaining = authorization_remaining_until(&command.not_after_monotonic_ns)?;
    if remaining > OPERATION_TIMEOUT {
        return Err(NativeBrowserError::InvalidMessage);
    }
    let _guard = lifecycle_guard(remaining)?;
    let queued = exchange.enqueue(&command.request, Some(&command.not_after_monotonic_ns))?;
    let result: CaptureResult = exchange.receive(queued, local).await?;
    result
        .validate(&command.request)
        .map_err(|_| NativeBrowserError::InvalidMessage)?;
    authorization_remaining_until(&command.not_after_monotonic_ns)?;
    let sealed = local_session.seal(&result)?;
    drop(result);
    timeout(
        authorization_remaining_until(&command.not_after_monotonic_ns)?,
        write_message(local, &sealed),
    )
    .await
    .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_browser::test_peer::ExtensionPeer;
    use serde_json::json;
    #[tokio::test]
    async fn encrypted_capture_rejects_changed_target_and_mismatched_reply() {
        for case in [
            "success",
            "changed-target",
            "wrong-transaction",
            "partial",
            "revoked",
        ] {
            let identity = BrowserHostIdentity::from_secret_bytes([51; 32]);
            let (open, pending) = LocalClientHandshake::start(&identity).unwrap();
            let (ready, mut local_session) = accept_local_client(&identity, &open).unwrap();
            let (stream, mut local) = UnixStream::pair().unwrap();
            let mut client = ExtensionClient {
                stream,
                session: pending.finish(&ready).unwrap(),
            };
            let (mut extension_session, peer) = ExtensionPeer::start(&identity);
            let (native, mut extension) = tokio::io::duplex(32768);
            let (mut input, mut output) = tokio::io::split(native);
            let host = tokio::spawn(async move {
                let prepare = OwnedPrepareRequest {
                    capture_mode: true,
                    protocol: INJECT_PROVIDER_PROTOCOL.into(),
                    message_type: "prepare".into(),
                    nonce: "a".repeat(32),
                    target_tab_id: Some(7),
                    target_url: Some("https://example.test/token".into()),
                    live_detection: Some(false),
                };
                let mut exchange = super::super::exchange::BrowserExchange::Direct {
                    session: &mut extension_session,
                    input: &mut input,
                    output: &mut output,
                };
                serve_capture(
                    &mut local,
                    &mut local_session,
                    &mut exchange,
                    &prepare,
                    &|_| {
                        if case == "revoked" {
                            Err(NativeBrowserError::AuthorizationExpired)
                        } else {
                            Ok(())
                        }
                    },
                )
                .await
            });
            let peer_task = tokio::spawn(async move {
                let frame = read_message::<SecureFrame>(&mut extension).await;
                if matches!(case, "changed-target" | "revoked") {
                    assert!(frame.is_err());
                    return;
                }
                let frame = frame.unwrap();
                let request = peer.open(&frame, 0);
                assert_eq!(request["type"], "capture");
                let response = json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"capture.result","transactionId":if case=="wrong-transaction" {"different"} else {"capture-1"},"outcome":"captured","values":if case=="partial" {json!([])} else {json!([{ "entryFieldId":"password","value":"synthetic-capture-secret" }])}});
                let sealed = peer.seal(response, 0);
                assert!(
                    !serde_json::to_string(&sealed)
                        .unwrap()
                        .contains("synthetic-capture-secret"),
                    "encrypted capture frame must not expose plaintext"
                );
                write_message(&mut extension, &sealed).await.unwrap();
            });
            let plan=CapturePlan::parse(&json!({"targetTabId":7,"targetUrl":if case=="changed-target" {"https://example.test/other"}else{"https://example.test/token"},"fields":[{"entryFieldId":"password","selector":"#token","read":"value"}]}).to_string()).unwrap();
            let deadline =
                monotonic_not_after_ns(monotonic_now_ns().unwrap(), Duration::from_secs(5))
                    .unwrap();
            let result = client
                .capture(CaptureRequest::new("capture-1", plan), deadline)
                .await;
            if case == "success" {
                assert_eq!(
                    result.unwrap().values.unwrap()[0].value,
                    "synthetic-capture-secret"
                );
                assert!(host.await.unwrap().is_ok());
            } else {
                assert!(result.is_err());
                assert!(host.await.unwrap().is_err());
            }
            peer_task.await.unwrap();
        }
    }
}
