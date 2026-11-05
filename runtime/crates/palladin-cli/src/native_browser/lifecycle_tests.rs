use super::test_peer::ExtensionPeer;
use super::*;
use serde_json::json;

async fn start_host(
    root: &Path,
) -> (
    tokio::task::JoinHandle<Result<(), NativeBrowserError>>,
    tokio::io::DuplexStream,
    ExtensionPeer,
) {
    let existing_sockets = socket_paths(root).len();
    let observed_root = root.to_owned();
    let root = root.to_owned();
    let (host_io, mut extension_io) = tokio::io::duplex(32768);
    let host = tokio::spawn(async move {
        let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
        let origin = ChromeExtensionOrigin::from_native_arguments(
            [std::ffi::OsString::from(
                "chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/",
            )]
            .into_iter(),
        )
        .unwrap();
        serve_native_host(&root, &identity, origin, tokio::io::split(host_io), |_| {
            Ok(())
        })
        .await
    });
    let peer = ExtensionPeer::connect(&mut extension_io).await;
    timeout(Duration::from_secs(1), async {
        while socket_paths(&observed_root).len() == existing_sockets {
            assert!(
                !host.is_finished(),
                "host failed before publishing its route"
            );
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("negotiated host publishes its socket");
    (host, extension_io, peer)
}

async fn inject_once(
    root: &Path,
    extension: &mut tokio::io::DuplexStream,
    peer: &ExtensionPeer,
    sequence: u64,
) {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let client = async {
        let mut client = ExtensionClient::connect(root, &identity)
            .await
            .expect("next client authenticates without reconnect");
        let prepared = client
            .prepare(&"a".repeat(32), Some(7), Some("https://example.test/login"))
            .await
            .unwrap();
        assert_eq!(prepared.outcome, "ready");
        let form: InjectionFormDefinition = serde_json::from_value(json!({"version":1,"steps":[{"fields":[{"entryFieldId":"credential.password","selector":"#password","control":"password"}],"submit":{"action":"click","selector":"#submit"}}]})).unwrap();
        let transaction_id = format!("synthetic-transaction-{sequence}");
        let request = InjectRequest {
            expires_at: None,
            continue_live: None,
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "inject",
            transaction_id: &transaction_id,
            grant_id: "synthetic-grant",
            entry_id: "synthetic-entry",
            expected_domain: "example.test",
            form: &form,
            values: vec![InjectFieldValue {
                entry_field_id: "credential.password",
                value: "synthetic-only",
            }],
        };
        let sealed = client
            .seal_inject(
                &request,
                monotonic_not_after_ns(monotonic_now_ns().unwrap(), Duration::from_secs(5))
                    .unwrap(),
            )
            .unwrap();
        let outcome = client
            .send_inject(sealed, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(outcome.outcome, "injected");
    };
    let browser = async {
        let frame: SecureFrame = read_message(extension).await.unwrap();
        let envelope = peer.open(&frame, sequence);
        let operation_id = envelope["operationId"].clone();
        let prepare = &envelope["request"];
        assert_eq!(prepare["targetTabId"], 7);
        write_message(extension, &peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result","operationId":operation_id,"response":{"protocol":INJECT_PROVIDER_PROTOCOL,"type":"prepare.result","nonce":prepare["nonce"],"currentUrl":"https://example.test/login","outcome":"ready"}}), sequence)).await.unwrap();
        let frame: SecureFrame = read_message(extension).await.unwrap();
        let envelope = peer.open(&frame, sequence + 1);
        assert_eq!(envelope["operationId"], operation_id);
        let inject = &envelope["request"];
        assert_eq!(inject["values"][0]["value"], "synthetic-only");
        write_message(extension, &peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result","operationId":operation_id,"response":{"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":inject["transactionId"],"outcome":"injected"}}), sequence + 1)).await.unwrap();
        let frame: SecureFrame = read_message(extension).await.unwrap();
        let close = peer.open(&frame, sequence + 2);
        assert_eq!(close["type"], "operation.close");
        assert_eq!(close["operationId"], operation_id);
        write_message(extension, &peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.closed","operationId":operation_id}), sequence + 2)).await.unwrap();
    };
    timeout(Duration::from_secs(2), async {
        tokio::join!(client, browser);
    })
    .await
    .expect("bounded operation");
}

#[tokio::test]
async fn sequential_injections_keep_the_authenticated_browser_connection() {
    let root = tempfile::tempdir().unwrap();
    let (host, mut extension, peer) = start_host(root.path()).await;
    inject_once(root.path(), &mut extension, &peer, 1).await;
    inject_once(root.path(), &mut extension, &peer, 4).await;
    assert!(
        !host.is_finished(),
        "completed operations must not terminate the host"
    );
    host.abort();
    let _ = host.await;
}

#[tokio::test]
async fn unauthenticated_socket_probe_does_not_disconnect_the_browser() {
    let root = tempfile::tempdir().unwrap();
    let (host, mut extension, peer) = start_host(root.path()).await;
    let probe = UnixStream::connect(socket_paths(root.path()).first().unwrap())
        .await
        .unwrap();
    drop(probe);
    tokio::task::yield_now().await;
    inject_once(root.path(), &mut extension, &peer, 1).await;
    host.abort();
    let _ = host.await;
}

#[tokio::test]
async fn idle_browser_connection_survives_five_minutes() {
    let root = tempfile::tempdir().unwrap();
    let (host, mut extension, peer) = start_host(root.path()).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(301)).await;
    tokio::task::yield_now().await;
    tokio::time::resume();
    assert!(!host.is_finished(), "idle host must remain available");
    inject_once(root.path(), &mut extension, &peer, 1).await;
    host.abort();
    let _ = host.await;
}

#[tokio::test]
async fn wrong_local_identity_does_not_disconnect_the_browser() {
    let root = tempfile::tempdir().unwrap();
    let (host, mut extension, peer) = start_host(root.path()).await;
    let wrong = BrowserHostIdentity::from_secret_bytes([43; 32]);
    assert!(ExtensionClient::connect(root.path(), &wrong).await.is_err());
    inject_once(root.path(), &mut extension, &peer, 1).await;
    host.abort();
    let _ = host.await;
}

#[tokio::test]
async fn browser_disconnect_removes_idle_socket() {
    let root = tempfile::tempdir().unwrap();
    let (host, extension, _) = start_host(root.path()).await;
    drop(extension);
    timeout(Duration::from_secs(1), host)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(socket_paths(root.path()).is_empty());
}

#[tokio::test]
async fn unsolicited_browser_frame_is_not_reused_for_a_new_operation() {
    let root = tempfile::tempdir().unwrap();
    let (host, mut extension, peer) = start_host(root.path()).await;
    write_message(
        &mut extension,
        &peer.seal(json!({"type":"inject.result","outcome":"injected"}), 1),
    )
    .await
    .unwrap();
    let result = timeout(Duration::from_secs(1), host)
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.is_err(),
        "an unsolicited authenticated frame must terminate the channel"
    );
    assert!(socket_paths(root.path()).is_empty());
}

#[tokio::test]
async fn two_browser_profiles_publish_independent_authenticated_routes() {
    let root = tempfile::tempdir().unwrap();
    let (first, mut first_extension, first_peer) = start_host(root.path()).await;
    let first_paths = socket_paths(root.path());
    let (second, mut second_extension, second_peer) = start_host(root.path()).await;
    let paths = socket_paths(root.path());
    assert_eq!(
        paths.len(),
        2,
        "browser profiles must not compete for one socket"
    );
    let first_path = first_paths.first().unwrap();
    let second_path = paths
        .iter()
        .find(|path| !first_paths.contains(path))
        .unwrap();
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    for (path, extension, peer, tab) in [
        (first_path, &mut first_extension, &first_peer, 11),
        (second_path, &mut second_extension, &second_peer, 22),
    ] {
        let client = async {
            let mut socket = UnixStream::connect(path).await.unwrap();
            let (open, pending) = LocalClientHandshake::start(&identity).unwrap();
            write_message(&mut socket, &open).await.unwrap();
            let ready: LocalSessionReady = read_message(&mut socket).await.unwrap();
            let mut client = ExtensionClient {
                stream: socket,
                session: pending.finish(&ready).unwrap(),
            };
            let prepared = client
                .prepare(
                    &"a".repeat(32),
                    Some(tab),
                    Some("https://example.test/login"),
                )
                .await
                .unwrap();
            assert_eq!(prepared.outcome, "target-tab-unavailable");
        };
        let browser = async {
            let frame: SecureFrame = read_message(extension).await.unwrap();
            let envelope = peer.open(&frame, 1);
            let request = &envelope["request"];
            assert_eq!(
                request["targetTabId"], tab,
                "request must reach only the selected profile"
            );
            write_message(extension, &peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result","operationId":envelope["operationId"],"response":{"protocol":INJECT_PROVIDER_PROTOCOL,"type":"prepare.result","nonce":request["nonce"],"currentUrl":null,"outcome":"target-tab-unavailable"}}),1)).await.unwrap();
        };
        timeout(Duration::from_secs(2), async {
            tokio::join!(client, browser);
        })
        .await
        .unwrap();
    }
    drop(first_extension);
    timeout(Duration::from_secs(1), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        second_path.exists(),
        "one profile closing must not remove another profile's route"
    );
    assert!(!second.is_finished());
    drop(second_extension);
    timeout(Duration::from_secs(1), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(socket_paths(root.path()).is_empty());
}

fn socket_paths(root: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_socket())
        .map(|entry| entry.path())
        .collect()
}

fn locator(path: &Path) -> String {
    path.file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("b-")
        .unwrap()
        .strip_suffix(".sock")
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn capture_selection_reaches_only_the_authenticated_browser_with_colliding_tab_ids() {
    use palladin_browser_bridge::capture::{CapturePlan, CaptureRequest};
    let root = tempfile::tempdir().unwrap();
    let (first_host, mut first_browser, first_peer) = start_host(root.path()).await;
    let first_id = locator(&socket_paths(root.path())[0]);
    let (second_host, mut second_browser, second_peer) = start_host(root.path()).await;
    let second_id = socket_paths(root.path())
        .iter()
        .map(|p| locator(p))
        .find(|id| *id != first_id)
        .unwrap();
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    assert!(
        ExtensionClient::connect_for_session(root.path(), &identity, None)
            .await
            .is_err()
    );
    for (selected, browser, peer) in [
        (&first_id, &mut first_browser, &first_peer),
        (&second_id, &mut second_browser, &second_peer),
    ] {
        let client = async {
            let mut client =
                ExtensionClient::connect_for_session(root.path(), &identity, Some(selected))
                    .await
                    .unwrap();
            let plan = CapturePlan::parse(&json!({"targetTabId":7,"targetUrl":"https://example.test/login","fields":[{"entryFieldId":"username","selector":"#username","read":"value"}]}).to_string()).unwrap();
            assert_eq!(
                client
                    .prepare_capture(&"a".repeat(32), &plan)
                    .await
                    .unwrap()
                    .outcome,
                "ready"
            );
            let result = client
                .capture(
                    CaptureRequest::new(&"a".repeat(32), plan),
                    monotonic_not_after_ns(monotonic_now_ns().unwrap(), Duration::from_secs(5))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                result.values.as_ref().unwrap()[0].value == *selected,
                "synthetic captured value mismatch"
            );
        };
        let extension = async {
            let frame: SecureFrame = read_message(browser).await.unwrap();
            let envelope = peer.open(&frame, 1);
            let operation = envelope["operationId"].clone();
            let prepare = &envelope["request"];
            assert_eq!(prepare["targetTabId"], 7);
            write_message(browser,&peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result","operationId":operation,"response":{"protocol":INJECT_PROVIDER_PROTOCOL,"type":"prepare.result","nonce":prepare["nonce"],"currentUrl":"https://example.test/login","outcome":"ready"}}),1)).await.unwrap();
            let frame: SecureFrame = read_message(browser).await.unwrap();
            let envelope = peer.open(&frame, 2);
            assert_eq!(envelope["operationId"], operation);
            let capture = &envelope["request"];
            assert_eq!(capture["type"], "capture");
            assert_eq!(capture["targetUrl"], "https://example.test/login");
            write_message(browser,&peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result","operationId":operation,"response":{"protocol":INJECT_PROVIDER_PROTOCOL,"type":"capture.result","transactionId":capture["transactionId"],"outcome":"captured","values":[{"entryFieldId":"username","value":selected}]}}),2)).await.unwrap();
            let frame: SecureFrame = read_message(browser).await.unwrap();
            assert_eq!(peer.open(&frame, 3)["type"], "operation.close");
            write_message(browser, &peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.closed","operationId":operation}), 3)).await.unwrap();
        };
        tokio::join!(client, extension);
    }
    assert!(
        timeout(
            Duration::from_millis(30),
            read_message::<SecureFrame>(&mut first_browser)
        )
        .await
        .is_err()
    );
    assert!(
        timeout(
            Duration::from_millis(30),
            read_message::<SecureFrame>(&mut second_browser)
        )
        .await
        .is_err()
    );
    first_host.abort();
    second_host.abort();
}

#[tokio::test]
async fn capture_selection_rejects_a_socket_claiming_another_browser_session() {
    let root = tempfile::tempdir().unwrap();
    let (host, mut browser, _peer) = start_host(root.path()).await;
    let path = socket_paths(root.path()).remove(0);
    let false_id = "a".repeat(32);
    std::fs::rename(path, root.path().join(format!("b-{false_id}.sock"))).unwrap();
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    assert!(
        ExtensionClient::connect_for_session(root.path(), &identity, Some(&false_id))
            .await
            .is_err()
    );
    assert!(
        timeout(
            Duration::from_millis(30),
            read_message::<SecureFrame>(&mut browser)
        )
        .await
        .is_err()
    );
    host.abort();
}

#[tokio::test]
async fn capture_selection_does_not_follow_a_browser_reconnect_or_other_live_session() {
    let root = tempfile::tempdir().unwrap();
    let (first_host, first_browser, _) = start_host(root.path()).await;
    let old_id = locator(&socket_paths(root.path())[0]);
    let (other_host, mut other_browser, _) = start_host(root.path()).await;
    drop(first_browser);
    timeout(Duration::from_secs(1), first_host)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    assert!(
        ExtensionClient::connect_for_session(root.path(), &identity, Some(&old_id))
            .await
            .is_err()
    );
    let (replacement_host, mut replacement_browser, _) = start_host(root.path()).await;
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    assert!(
        ExtensionClient::connect_for_session(root.path(), &identity, Some(&old_id))
            .await
            .is_err()
    );
    assert!(
        timeout(
            Duration::from_millis(30),
            read_message::<SecureFrame>(&mut other_browser)
        )
        .await
        .is_err()
    );
    assert!(
        timeout(
            Duration::from_millis(30),
            read_message::<SecureFrame>(&mut replacement_browser)
        )
        .await
        .is_err()
    );
    other_host.abort();
    replacement_host.abort();
}

#[tokio::test]
async fn selected_status_rejects_wrong_nonce_type_protocol_locator_and_disconnect() {
    for invalid in ["nonce", "type", "protocol", "locator", "disconnect"] {
        let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
        let (open, pending) = LocalClientHandshake::start(&identity).unwrap();
        let (ready, mut server_session) = accept_local_client(&identity, &open).unwrap();
        let (stream, mut server) = UnixStream::pair().unwrap();
        let mut client = ExtensionClient {
            stream,
            session: pending.finish(&ready).unwrap(),
        };
        let expected = "a".repeat(32);
        let check = client.verify_browser_session(&expected);
        let reply = async {
            let frame: LocalSecureFrame = read_message(&mut server).await.unwrap();
            let status: BrowserStatusRequest = server_session.open(&frame).unwrap();
            if invalid == "disconnect" {
                drop(server);
                return;
            }
            let mut result = BrowserStatusResult {
                protocol: LOCAL_TRANSPORT_PROTOCOL.into(),
                message_type: "browser.status.result".into(),
                nonce: status.nonce,
                session: BrowserSessionInfo {
                    browser_session: expected.clone(),
                    concurrent: true,
                },
            };
            match invalid {
                "nonce" => result.nonce = "b".repeat(32),
                "type" => result.message_type = "prepare.result".into(),
                "protocol" => result.protocol = "invalid".into(),
                "locator" => result.session.browser_session = "b".repeat(32),
                _ => unreachable!(),
            }
            write_message(&mut server, &server_session.seal(&result).unwrap())
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(check, reply);
        assert!(
            result.is_err(),
            "invalid authenticated preflight must fail closed"
        );
    }
}

#[tokio::test]
async fn selected_capture_disconnect_after_status_never_uses_other_browser() {
    let root = tempfile::tempdir().unwrap();
    let (host, browser, _) = start_host(root.path()).await;
    let selected = locator(&socket_paths(root.path())[0]);
    let (other_host, mut other_browser, _) = start_host(root.path()).await;
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let mut client = ExtensionClient::connect_for_session(root.path(), &identity, Some(&selected))
        .await
        .unwrap();
    drop(browser);
    timeout(Duration::from_secs(1), host)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        client
            .prepare(&"a".repeat(32), Some(7), Some("https://example.test/login"))
            .await
            .is_err()
    );
    assert!(
        timeout(
            Duration::from_millis(30),
            read_message::<SecureFrame>(&mut other_browser)
        )
        .await
        .is_err()
    );
    other_host.abort();
}

#[tokio::test]
async fn repeated_status_preflight_is_rejected_before_page_operation() {
    let root = tempfile::tempdir().unwrap();
    let (host, mut browser, _) = start_host(root.path()).await;
    let selected = locator(&socket_paths(root.path())[0]);
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let mut client = ExtensionClient::connect_for_session(root.path(), &identity, Some(&selected))
        .await
        .unwrap();
    assert!(
        timeout(
            Duration::from_secs(1),
            client.verify_browser_session(&selected)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(
        timeout(
            Duration::from_millis(30),
            read_message::<SecureFrame>(&mut browser)
        )
        .await
        .is_err()
    );
    host.abort();
}

#[tokio::test(start_paused = true)]
async fn status_preflight_has_a_bounded_wait_for_the_next_operation() {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (stream, mut server) = UnixStream::pair().unwrap();
    let expected = "a".repeat(32);
    let info = BrowserSessionInfo {
        browser_session: expected.clone(),
        concurrent: true,
    };
    let host = tokio::spawn(async move {
        prepare_local_client(&mut server, &identity, &info, &|_| Ok(())).await
    });
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (open, pending) = LocalClientHandshake::start(&identity).unwrap();
    let mut stream = stream;
    write_message(&mut stream, &open).await.unwrap();
    let ready: LocalSessionReady = read_message(&mut stream).await.unwrap();
    let mut client = ExtensionClient {
        stream,
        session: pending.finish(&ready).unwrap(),
    };
    client.verify_browser_session(&expected).await.unwrap();
    tokio::time::advance(HANDSHAKE_TIMEOUT + Duration::from_millis(1)).await;
    assert!(matches!(
        host.await.unwrap(),
        Err(NativeBrowserError::Unavailable)
    ));
}

#[tokio::test]
async fn selected_capture_disconnect_after_preparation_never_uses_other_browser() {
    use palladin_browser_bridge::capture::{CapturePlan, CaptureRequest};
    let root = tempfile::tempdir().unwrap();
    let (host, mut browser, peer) = start_host(root.path()).await;
    let selected = locator(&socket_paths(root.path())[0]);
    let (other_host, mut other_browser, _) = start_host(root.path()).await;
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let mut client = ExtensionClient::connect_for_session(root.path(), &identity, Some(&selected))
        .await
        .unwrap();
    let plan = CapturePlan::parse(r##"{"targetTabId":7,"targetUrl":"https://example.test/login","fields":[{"entryFieldId":"username","selector":"#username","read":"value"}]}"##).unwrap();
    let nonce = "a".repeat(32);
    let prepare = client.prepare_capture(&nonce, &plan);
    let reply = async {
        let frame: SecureFrame = read_message(&mut browser).await.unwrap();
        let envelope = peer.open(&frame, 1);
        write_message(&mut browser, &peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result","operationId":envelope["operationId"],"response":{"protocol":INJECT_PROVIDER_PROTOCOL,"type":"prepare.result","nonce":envelope["request"]["nonce"],"currentUrl":"https://example.test/login","outcome":"ready"}}),1)).await.unwrap();
    };
    let (prepared, ()) = tokio::join!(prepare, reply);
    assert_eq!(prepared.unwrap().outcome, "ready");
    drop(browser);
    timeout(Duration::from_secs(1), host)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        client
            .capture(
                CaptureRequest::new(&nonce, plan),
                monotonic_not_after_ns(monotonic_now_ns().unwrap(), Duration::from_secs(5))
                    .unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        timeout(
            Duration::from_millis(30),
            read_message::<SecureFrame>(&mut other_browser)
        )
        .await
        .is_err()
    );
    other_host.abort();
}
