use super::*;
use palladin_browser_bridge::secure_transport::HostSecureSession;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Multiplex,
    Legacy,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready {
    protocol: String,
    #[serde(rename = "type")]
    kind: String,
    version: u32,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Response {
    Ready(Ready),
    Legacy(Box<InjectResult>),
}

pub(super) async fn negotiate<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    session: &mut HostSecureSession,
    input: &mut R,
    output: &mut W,
) -> Result<Mode, NativeBrowserError> {
    let frame = session.seal(&serde_json::json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.hello","version":1}))?;
    timeout(HANDSHAKE_TIMEOUT, write_message(output, &frame))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
    let frame: SecureFrame = timeout(HANDSHAKE_TIMEOUT, read_message(input))
        .await
        .map_err(|_| NativeBrowserError::Unavailable)??;
    let response: Response = session
        .open(&frame)
        .map_err(|_| NativeBrowserError::InvalidMessage)?;
    match response {
        Response::Ready(ready)
            if ready.protocol == INJECT_PROVIDER_PROTOCOL
                && ready.kind == "operation.ready"
                && ready.version == 1 =>
        {
            Ok(Mode::Multiplex)
        }
        // Only the old provider's exact unknown-message rejection selects its
        // serial protocol. Corrupt/foreign/ambiguous replies never downgrade.
        Response::Legacy(reply)
            if reply.protocol == INJECT_PROVIDER_PROTOCOL
                && reply.message_type == "inject.result"
                && reply.transaction_id.is_none()
                && reply.outcome == "rejected"
                && reply.submit_ready.is_none()
                && reply.continuation.is_none() =>
        {
            Ok(Mode::Legacy)
        }
        _ => Err(NativeBrowserError::InvalidMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_browser::test_peer::ExtensionPeer;
    use serde_json::json;

    #[tokio::test]
    async fn negotiates_concurrent_or_legacy_protocol_before_any_page_operation() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/inject-provider/operations-v1/negotiation.json"
        ))
        .unwrap();
        for (reply, expected) in [
            (fixture["ready"].clone(), Mode::Multiplex),
            (fixture["legacyRejection"].clone(), Mode::Legacy),
        ] {
            let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
            let (mut session, peer) = ExtensionPeer::start(&identity);
            let (host, mut browser) = tokio::io::duplex(65536);
            let (mut input, mut output) = tokio::io::split(host);
            let host = negotiate(&mut session, &mut input, &mut output);
            let browser = async {
                let frame: SecureFrame = read_message(&mut browser).await.unwrap();
                assert_eq!(peer.open(&frame, 0), fixture["hello"]);
                write_message(&mut browser, &peer.seal(reply, 0))
                    .await
                    .unwrap();
            };
            let (mode, ()) = tokio::join!(host, browser);
            assert_eq!(mode.unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn malformed_capabilities_cannot_select_the_legacy_path() {
        for reply in [
            json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.ready","version":2}),
            json!({"protocol":"wrong","type":"operation.ready","version":1}),
            json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.ready","version":1,"unexpected":true}),
            json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":null,"outcome":"injected"}),
            json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":"another-operation","outcome":"rejected"}),
        ] {
            let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
            let (mut session, peer) = ExtensionPeer::start(&identity);
            let (host, mut browser) = tokio::io::duplex(65536);
            let (mut input, mut output) = tokio::io::split(host);
            let host = negotiate(&mut session, &mut input, &mut output);
            let browser = async {
                let _: SecureFrame = read_message(&mut browser).await.unwrap();
                write_message(&mut browser, &peer.seal(reply, 0))
                    .await
                    .unwrap();
            };
            let (mode, ()) = tokio::join!(host, browser);
            assert!(matches!(mode, Err(NativeBrowserError::InvalidMessage)));
        }
    }
}
