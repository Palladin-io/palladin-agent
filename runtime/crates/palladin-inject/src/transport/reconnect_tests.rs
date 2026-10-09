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
            browser_session: None,
        }),
        true,
        Duration::from_secs(2),
        Duration::from_millis(5),
    )
    .await
}

#[tokio::test]
async fn explicit_browser_session_routes_only_to_that_profile() {
    let root = tempfile::tempdir().unwrap();
    let first_path = root.path().join(format!("b-{}.sock", "a".repeat(32)));
    let second_id = "b".repeat(32);
    let second_path = root.path().join(format!("b-{second_id}.sock"));
    let first = UnixListener::bind(&first_path).unwrap();
    let second = UnixListener::bind(&second_path).unwrap();
    for path in [&first_path, &second_path] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let host = tokio::spawn(async move {
        let (mut socket, mut session) = authenticate(&second).await;
        let request = prepare(&mut socket, &mut session).await;
        respond(&mut socket, &mut session, &request).await;
    });
    let connected = ExtensionClient::connect_prepared_with_budget(
        root.path(),
        &BrowserHostIdentity::from_secret_bytes([41; 32]),
        &"A".repeat(64),
        Some(BrowserTarget {
            tab_id: 7,
            page_url: "https://example.test/login",
            browser_session: Some(&second_id),
        }),
        true,
        Duration::from_secs(1),
        Duration::from_millis(5),
    )
    .await;
    assert!(
        connected.is_ok(),
        "explicit route must disambiguate profiles: {:?}",
        connected.err()
    );
    assert!(
        timeout(Duration::from_millis(30), first.accept())
            .await
            .is_err(),
        "unselected profile must receive no request"
    );
    host.await.unwrap();
}

#[tokio::test]
async fn crashed_profile_socket_does_not_hide_the_only_live_profile() {
    let root = tempfile::tempdir().unwrap();
    let stale_path = root.path().join(format!("b-{}.sock", "a".repeat(32)));
    let stale = UnixListener::bind(&stale_path).unwrap();
    std::fs::set_permissions(&stale_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(stale); // A killed host cannot run its socket guard.
    let live = listener(root.path());
    let host = tokio::spawn(async move {
        let (mut stream, mut session) = authenticate(&live).await;
        let request = prepare(&mut stream, &mut session).await;
        respond(&mut stream, &mut session, &request).await;
    });
    let result = connect(root.path()).await;
    assert!(
        result.is_ok(),
        "stale route must not create ambiguity: {:?}",
        result.err()
    );
    assert!(
        stale_path.exists(),
        "discovery must not unlink another host's path"
    );
    host.await.unwrap();
}

#[tokio::test]
async fn multiple_profiles_without_an_exact_target_are_rejected_before_handshake() {
    let root = tempfile::tempdir().unwrap();
    let first = listener(root.path());
    let path = root.path().join(format!("b-{}.sock", "a".repeat(32)));
    let second = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        ExtensionClient::connect(
            root.path(),
            &BrowserHostIdentity::from_secret_bytes([41; 32]),
            None
        )
        .await,
        Err(NativeBrowserError::AmbiguousBrowser)
    ));
    for listener in [first, second] {
        // Either no connection or a closed, empty liveness connection is safe.
        if let Ok(Ok((mut stream, _))) = timeout(Duration::from_millis(30), listener.accept()).await
        {
            use tokio::io::AsyncReadExt;
            let mut byte = [0];
            assert_eq!(
                timeout(Duration::from_millis(30), stream.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }
}

#[tokio::test]
async fn missing_explicit_profile_never_falls_back_to_another_live_profile() {
    let root = tempfile::tempdir().unwrap();
    let other = listener(root.path());
    let result = ExtensionClient::connect(
        root.path(),
        &BrowserHostIdentity::from_secret_bytes([41; 32]),
        Some(&"a".repeat(32)),
    )
    .await;
    assert!(matches!(result, Err(NativeBrowserError::Unavailable)));
    assert!(
        timeout(Duration::from_millis(30), other.accept())
            .await
            .is_err()
    );
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

#[tokio::test]
async fn absent_browser_session_selects_the_unique_exact_target_before_preparing() {
    let root = tempfile::tempdir().unwrap();
    let mut hosts = Vec::new();
    for (id, matches) in [('a', false), ('b', true)] {
        let path = root
            .path()
            .join(format!("b-{}.sock", id.to_string().repeat(32)));
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        hosts.push(tokio::spawn(async move {
            let (mut socket, mut session) = authenticate(&listener).await;
            let frame: LocalSecureFrame = read_message(&mut socket).await.unwrap();
            let probe: Value = session.open(&frame).unwrap();
            assert_eq!(probe["type"], "target.probe");
            assert_eq!(probe["targetTabId"], 7);
            assert_eq!(probe["targetUrl"], "https://example.test/login");
            assert!(probe.get("values").is_none());
            let reply = session
                .seal(&json!({"protocol": INJECT_PROVIDER_PROTOCOL,
                "type":"target.probe.result", "nonce":probe["nonce"],
                "outcome": if matches {"match"} else {"no-match"}}))
                .unwrap();
            write_message(&mut socket, &reply).await.unwrap();
            drop(socket);
            if matches {
                let (mut socket, mut session) = authenticate(&listener).await;
                let request = prepare(&mut socket, &mut session).await;
                respond(&mut socket, &mut session, &request).await;
            } else {
                assert!(
                    timeout(Duration::from_millis(100), listener.accept())
                        .await
                        .is_err()
                );
            }
        }));
    }
    let result = connect(root.path()).await;
    assert!(
        result.is_ok(),
        "one exact matching profile should be usable: {:?}",
        result.err()
    );
    for host in hosts {
        host.await.unwrap();
    }
}

#[tokio::test]
async fn target_resolution_never_guesses_when_matches_are_ambiguous_or_incomplete() {
    for (outcomes, expected) in [
        (["match", "match"], "ambiguous"),
        (["no-match", "no-match"], "missing"),
        (["match", "unavailable"], "incomplete"),
        (["match", "wrong-nonce"], "invalid"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut hosts = Vec::new();
        for (index, outcome) in outcomes.into_iter().enumerate() {
            let path = root.path().join(format!("b-{index:032x}.sock"));
            let listener = UnixListener::bind(&path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            hosts.push(tokio::spawn(async move {
                let (mut socket, mut session) = authenticate(&listener).await;
                let frame: LocalSecureFrame = read_message(&mut socket).await.unwrap();
                let request: Value = session.open(&frame).unwrap();
                assert_eq!(request["type"], "target.probe");
                let nonce = if outcome == "wrong-nonce" {
                    json!("b".repeat(64))
                } else {
                    request["nonce"].clone()
                };
                let reply = session
                    .seal(
                        &json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"target.probe.result",
                    "nonce":nonce,"outcome":if outcome == "wrong-nonce" {"match"} else {outcome}}),
                    )
                    .unwrap();
                write_message(&mut socket, &reply).await.unwrap();
                drop(socket);
                assert!(
                    timeout(Duration::from_millis(100), listener.accept())
                        .await
                        .is_err(),
                    "an unresolved target must never start credential preparation"
                );
            }));
        }
        let result = connect(root.path()).await;
        assert!(matches!(
            (result, expected),
            (Err(NativeBrowserError::AmbiguousBrowser), "ambiguous")
                | (Err(NativeBrowserError::TargetNotFound), "missing")
                | (
                    Err(NativeBrowserError::TargetResolutionUnavailable),
                    "incomplete"
                )
                | (Err(NativeBrowserError::InvalidMessage), "invalid")
        ));
        for host in hosts {
            host.await.unwrap();
        }
    }
}
