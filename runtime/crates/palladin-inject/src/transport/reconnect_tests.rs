use super::*;
use palladin_browser_bridge::local_transport::{
    LocalSecureSession, LocalSessionOpen, accept_local_client,
};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use tokio::net::UnixListener;

fn listener(root: &Path) -> UnixListener {
    let path = root.join("browser-bridge.sock");
    let socket = UnixListener::bind(&path).expect("bind");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("permissions");
    socket
}
async fn authenticate(listener: &UnixListener) -> (UnixStream, LocalSecureSession) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let open: LocalSessionOpen = read_message(&mut socket).await.expect("open");
    let (ready, session) =
        accept_local_client(&BrowserHostIdentity::from_secret_bytes([41; 32]), &open)
            .expect("authenticate");
    write_message(&mut socket, &ready).await.expect("ready");
    (socket, session)
}
async fn prepare(socket: &mut UnixStream, session: &mut LocalSecureSession) -> Value {
    let frame: LocalSecureFrame = read_message(socket).await.expect("prepare frame");
    let request: Value = session.open(&frame).expect("prepare");
    assert_eq!(request["type"], "prepare");
    assert_eq!(request["targetTabId"], 7);
    assert_eq!(request["targetUrl"], "https://example.test/login");
    assert_eq!(request["liveDetection"], true);
    assert!(request.get("values").is_none());
    request
}
async fn respond(socket: &mut UnixStream, session: &mut LocalSecureSession, request: &Value) {
    let reply = session
        .seal(
            &json!({"protocol": INJECT_PROVIDER_PROTOCOL, "type":"prepare.result",
        "nonce":request["nonce"], "currentUrl":"https://example.test/login", "outcome":"ready"}),
        )
        .expect("seal");
    write_message(socket, &reply).await.expect("reply");
}
async fn connect(root: &Path) -> Result<(ExtensionClient, PrepareResult), NativeBrowserError> {
    ExtensionClient::connect_prepared_with_budget(
        root,
        &BrowserHostIdentity::from_secret_bytes([41; 32]),
        &"A".repeat(64),
        Some(BrowserTarget {
            tab_id: 7,
            page_url: "https://example.test/login",
        }),
        true,
        Duration::from_secs(2),
        Duration::from_millis(5),
    )
    .await
}
#[tokio::test]
async fn closed_prepare_reconnects_without_credential_delivery() {
    let root = tempfile::tempdir().expect("root");
    let socket = listener(root.path());
    let host = tokio::spawn(async move {
        let (mut first, mut session) = authenticate(&socket).await;
        prepare(&mut first, &mut session).await;
        drop(first);
        let (mut second, mut session) = authenticate(&socket).await;
        let request = prepare(&mut second, &mut session).await;
        respond(&mut second, &mut session, &request).await;
    });
    let (_, result) = connect(root.path())
        .await
        .expect("must reconnect before Inject");
    assert_eq!(result.outcome, "ready");
    host.await.expect("host");
}
#[tokio::test]
async fn closed_handshake_reconnects() {
    let root = tempfile::tempdir().expect("root");
    let socket = listener(root.path());
    let host = tokio::spawn(async move {
        let (first, _) = socket.accept().await.expect("first");
        drop(first);
        let (mut second, mut session) = authenticate(&socket).await;
        let request = prepare(&mut second, &mut session).await;
        respond(&mut second, &mut session, &request).await;
    });
    connect(root.path()).await.expect("handshake reconnect");
    host.await.expect("host");
}
#[tokio::test]
async fn missing_socket_waits_for_extension_reconnect() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().to_owned();
    let host = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let socket = listener(&path);
        let (mut stream, mut session) = authenticate(&socket).await;
        let request = prepare(&mut stream, &mut session).await;
        respond(&mut stream, &mut session, &request).await;
    });
    connect(root.path()).await.expect("wait for native host");
    host.await.expect("host");
}
#[tokio::test]
async fn invalid_authenticated_response_is_not_retried() {
    let root = tempfile::tempdir().expect("root");
    let socket = listener(root.path());
    let host = tokio::spawn(async move {
        let (mut stream, mut session) = authenticate(&socket).await;
        prepare(&mut stream, &mut session).await;
        let reply = session
            .seal(
                &json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"prepare.result",
            "nonce":"wrong", "currentUrl":null, "outcome":"provider-unavailable"}),
            )
            .expect("seal");
        write_message(&mut stream, &reply).await.expect("reply");
        assert!(
            timeout(Duration::from_millis(50), socket.accept())
                .await
                .is_err()
        );
    });
    assert!(matches!(
        connect(root.path()).await,
        Err(NativeBrowserError::InvalidMessage)
    ));
    host.await.expect("host");
}
#[tokio::test]
async fn unsafe_socket_is_not_retried() {
    let root = tempfile::tempdir().expect("root");
    std::fs::write(root.path().join("browser-bridge.sock"), "not a socket").expect("file");
    assert!(matches!(
        connect(root.path()).await,
        Err(NativeBrowserError::UnsafeSocket)
    ));
}
#[tokio::test]
async fn cancellation_interrupts_reconnect_wait() {
    let root = tempfile::tempdir().expect("root");
    let cancellation = tokio_util::sync::CancellationToken::new();
    let cancel = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
    });
    tokio::select! {
        biased;
        () = cancellation.cancelled() => {},
        _ = connect(root.path()) => panic!("must wait until cancelled"),
    }
}

#[tokio::test]
async fn unavailable_host_has_a_bounded_retry_budget() {
    let root = tempfile::tempdir().expect("root");
    let started = Instant::now();
    let result = ExtensionClient::connect_prepared_with_budget(
        root.path(),
        &BrowserHostIdentity::from_secret_bytes([41; 32]),
        &"A".repeat(64),
        None,
        false,
        Duration::from_millis(30),
        Duration::from_millis(5),
    )
    .await;
    assert!(matches!(result, Err(NativeBrowserError::ReconnectTimeout)));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn dropped_inject_response_is_never_replayed() {
    let root = tempfile::tempdir().expect("root");
    let socket = listener(root.path());
    let host = tokio::spawn(async move {
        let (mut stream, mut session) = authenticate(&socket).await;
        let request = prepare(&mut stream, &mut session).await;
        respond(&mut stream, &mut session, &request).await;
        let frame: LocalSecureFrame = read_message(&mut stream).await.expect("inject frame");
        let command: Value = session.open(&frame).expect("inject command");
        assert_eq!(command["type"], "inject.forward");
        drop(stream); // Page may have been changed: no second connection is allowed.
        assert!(
            timeout(Duration::from_millis(50), socket.accept())
                .await
                .is_err()
        );
    });
    let (mut client, _) = connect(root.path()).await.expect("prepare");
    let form = InjectionFormDefinition {
        version: 1,
        steps: vec![],
    };
    let request = InjectRequest {
        expires_at: None,
        continue_live: None,
        protocol: INJECT_PROVIDER_PROTOCOL,
        message_type: "inject",
        transaction_id: "fixture-transaction",
        grant_id: "fixture-grant",
        entry_id: "fixture-entry",
        expected_domain: "example.test",
        form: &form,
        values: vec![],
    };
    let sealed = client
        .seal_inject(
            &request,
            monotonic_not_after_ns(monotonic_now_ns().expect("clock"), Duration::from_secs(10))
                .expect("deadline"),
        )
        .expect("seal");
    assert!(matches!(
        client.send_inject(sealed, Duration::from_secs(10)).await,
        Err(NativeBrowserError::Framing(
            palladin_browser_bridge::framing::FramingError::Transport
        ))
    ));
    host.await.expect("host");
}

#[tokio::test]
async fn unauthenticated_host_response_is_not_retried() {
    let root = tempfile::tempdir().expect("root");
    let socket = listener(root.path());
    let host = tokio::spawn(async move {
        let (mut stream, mut session) = authenticate(&socket).await;
        prepare(&mut stream, &mut session).await;
        let reply = session
            .seal(&json!({"type":"prepare.result"}))
            .expect("seal");
        let mut tampered = serde_json::to_value(reply).expect("json");
        // Change the encrypted payload while preserving its syntactic framing.
        let payload = tampered.get_mut("ciphertext").expect("ciphertext");
        let original = payload.as_str().expect("string");
        let mut bytes = original.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        *payload = Value::String(String::from_utf8(bytes).expect("ascii"));
        write_message(&mut stream, &tampered).await.expect("reply");
        assert!(
            timeout(Duration::from_millis(50), socket.accept())
                .await
                .is_err()
        );
    });
    assert!(matches!(
        connect(root.path()).await,
        Err(NativeBrowserError::Secure(_))
    ));
    host.await.expect("host");
}

#[tokio::test]
async fn incompatible_live_provider_is_terminal_without_reconnect() {
    let root = tempfile::tempdir().expect("root");
    let socket = listener(root.path());
    let host = tokio::spawn(async move {
        let (mut stream, mut session) = authenticate(&socket).await;
        let request = prepare(&mut stream, &mut session).await;
        let reply = session
            .seal(&json!({"protocol": INJECT_PROVIDER_PROTOCOL,
            "type":"prepare.result", "nonce":request["nonce"], "currentUrl":null,
            "outcome":"unsupported-live-detection"}))
            .expect("seal");
        write_message(&mut stream, &reply).await.expect("reply");
        assert!(
            timeout(Duration::from_millis(50), socket.accept())
                .await
                .is_err()
        );
    });
    let (_, prepared) = connect(root.path()).await.expect("semantic rejection");
    assert_eq!(prepared.outcome, "unsupported-live-detection");
    host.await.expect("host");
}
