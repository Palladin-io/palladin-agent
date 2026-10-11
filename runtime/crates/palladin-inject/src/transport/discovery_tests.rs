use super::*;
use palladin_browser_bridge::local_transport::accept_local_client;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use tokio::net::UnixListener;

#[tokio::test]
async fn discovery_does_not_treat_a_socket_named_regular_file_as_a_browser() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join(format!("b-{}.sock", "a".repeat(32))),
        "synthetic-not-a-socket",
    )
    .unwrap();
    assert!(matches!(
        discover_browser_sessions(
            root.path(),
            &BrowserHostIdentity::from_secret_bytes([41; 32])
        )
        .await,
        Err(NativeBrowserError::UnsafeSocket)
    ));
}

#[tokio::test]
async fn discovery_authenticates_each_live_session_and_reports_crashed_routes_separately() {
    let root = tempfile::tempdir().unwrap();
    let mut hosts = Vec::new();
    for (id, concurrent) in [("a".repeat(32), true), ("b".repeat(32), false)] {
        let path = root.path().join(format!("b-{id}.sock"));
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        hosts.push(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let open = read_message(&mut stream).await.unwrap();
            let (ready, mut session) =
                accept_local_client(&BrowserHostIdentity::from_secret_bytes([41; 32]), &open)
                    .unwrap();
            write_message(&mut stream, &ready).await.unwrap();
            let frame: LocalSecureFrame = read_message(&mut stream).await.unwrap();
            let request: BrowserStatusRequest = session.open(&frame).unwrap();
            write_message(
                &mut stream,
                &session
                    .seal(&BrowserStatusResult {
                        protocol: LOCAL_TRANSPORT_PROTOCOL.into(),
                        message_type: "browser.status.result".into(),
                        nonce: request.nonce,
                        session: BrowserSessionInfo {
                            browser_session: id,
                            concurrent,
                        },
                    })
                    .unwrap(),
            )
            .await
            .unwrap();
        }));
    }
    let stale = root.path().join(format!("b-{}.sock", "c".repeat(32)));
    let listener = UnixListener::bind(&stale).unwrap();
    std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(listener);
    let report = discover_browser_sessions(
        root.path(),
        &BrowserHostIdentity::from_secret_bytes([41; 32]),
    )
    .await
    .unwrap();
    assert_eq!(
        report.sessions,
        vec![
            BrowserSessionInfo {
                browser_session: "a".repeat(32),
                concurrent: true
            },
            BrowserSessionInfo {
                browser_session: "b".repeat(32),
                concurrent: false
            }
        ]
    );
    assert_eq!(report.unavailable_connections, 1);
    assert!(!report.legacy_socket_present);
    for host in hosts {
        host.await.unwrap();
    }
}

#[tokio::test]
async fn discovery_does_not_probe_a_pre_discovery_legacy_host() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("browser-bridge.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let report = discover_browser_sessions(
        root.path(),
        &BrowserHostIdentity::from_secret_bytes([41; 32]),
    )
    .await
    .unwrap();
    assert!(report.sessions.is_empty());
    assert!(report.legacy_socket_present);
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn status_requires_both_the_request_nonce_and_the_selected_socket_session() {
    for case in [
        "valid",
        "wrong-nonce",
        "wrong-session",
        "wrong-protocol",
        "unexpected-field",
    ] {
        let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
        let (open, pending) = LocalClientHandshake::start(&identity).unwrap();
        let (ready, mut server_session) = accept_local_client(&identity, &open).unwrap();
        let (stream, mut server) = UnixStream::pair().unwrap();
        let mut client = ExtensionClient {
            stream,
            session: pending.finish(&ready).unwrap(),
        };
        let server = tokio::spawn(async move {
            let frame: LocalSecureFrame = read_message(&mut server).await.unwrap();
            let request: Value = server_session.open(&frame).unwrap();
            assert_eq!(request["type"], "browser.status");
            assert_eq!(
                request.as_object().unwrap().len(),
                3,
                "no credential or page data in discovery"
            );
            let mut response = json!({"protocol":LOCAL_TRANSPORT_PROTOCOL,"type":"browser.status.result",
                "nonce":request["nonce"],"session":{"browserSession":"a".repeat(32),"concurrent":true}});
            match case {
                "wrong-nonce" => response["nonce"] = json!("wrong"),
                "wrong-session" => response["session"]["browserSession"] = json!("b".repeat(32)),
                "wrong-protocol" => response["protocol"] = json!("wrong"),
                "unexpected-field" => response["unexpected"] = json!(true),
                _ => {}
            }
            write_message(&mut server, &server_session.seal(&response).unwrap())
                .await
                .unwrap();
        });
        let result = client.browser_status(&"a".repeat(32)).await;
        assert_eq!(result.is_ok(), case == "valid", "case: {case}");
        if let Ok(info) = result {
            assert_eq!(info.browser_session, "a".repeat(32));
            assert!(info.concurrent);
        }
        server.await.unwrap();
    }
}
