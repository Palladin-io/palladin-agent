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
    start_host_with(root, |_| Ok(())).await
}

async fn start_host_with(
    root: &Path,
    lifecycle_guard: impl Fn(Duration) -> Result<(), NativeBrowserError> + Send + Sync + 'static,
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
        serve_native_host(
            &root,
            &identity,
            origin,
            tokio::io::split(host_io),
            lifecycle_guard,
        )
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
async fn reset_authorization_ends_the_old_host_when_a_new_identity_connects() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let root = tempfile::tempdir().unwrap();
    let revoked = Arc::new(AtomicBool::new(false));
    let guard = Arc::clone(&revoked);
    let (host, _extension, _) = start_host_with(root.path(), move |_| {
        if guard.load(Ordering::SeqCst) {
            Err(NativeBrowserError::Revoked)
        } else {
            Ok(())
        }
    })
    .await;
    revoked.store(true, Ordering::SeqCst);
    let replacement = BrowserHostIdentity::from_secret_bytes([43; 32]);
    assert!(
        ExtensionClient::connect(root.path(), &replacement)
            .await
            .is_err()
    );
    let result = timeout(Duration::from_secs(1), host)
        .await
        .expect("a revoked host must exit so the browser can start a current one")
        .unwrap();
    assert!(matches!(result, Err(NativeBrowserError::Revoked)));
    assert!(socket_paths(root.path()).is_empty());
}

const HOST_PROCESS_ROOT: &str = "PALLADIN_REVOKED_HOST_TEST_ROOT";

/// The browser keeps its end of stdin open, so a pending read must not keep the process alive.
#[tokio::test]
async fn revoked_host_process_exits_while_the_browser_keeps_its_port_open() {
    use std::os::fd::OwnedFd;
    use std::process::{Command, Stdio};

    let root = tempfile::tempdir().unwrap();
    let (browser, host) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "native_browser::lifecycle_tests::revoked_host_process_helper",
            "--nocapture",
        ])
        .env(HOST_PROCESS_ROOT, root.path())
        .stdin(Stdio::from(OwnedFd::from(host.try_clone().unwrap())))
        .stdout(Stdio::null())
        // The test harness writes to stdout, so stderr carries the host frames.
        .stderr(Stdio::from(OwnedFd::from(host)))
        .spawn()
        .unwrap();
    browser.set_nonblocking(true).unwrap();
    let mut browser = UnixStream::from_std(browser).unwrap();
    let _peer = timeout(
        Duration::from_secs(10),
        ExtensionPeer::connect(&mut browser),
    )
    .await
    .expect("host process handshake");
    timeout(Duration::from_secs(5), async {
        while socket_paths(root.path()).is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("host process publishes its socket");
    std::fs::write(root.path().join("revoked"), b"").unwrap();
    let replacement = BrowserHostIdentity::from_secret_bytes([43; 32]);
    assert!(
        ExtensionClient::connect(root.path(), &replacement)
            .await
            .is_err()
    );
    let exited = timeout(Duration::from_secs(5), async {
        while child.try_wait().unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if exited.is_err() {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    exited.expect("a revoked host process must exit to close the browser port");
    assert!(socket_paths(root.path()).is_empty());
}

#[tokio::test]
#[ignore = "subprocess helper"]
async fn revoked_host_process_helper() {
    let root = PathBuf::from(std::env::var_os(HOST_PROCESS_ROOT).expect("test root"));
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let origin = ChromeExtensionOrigin::from_native_arguments(
        [std::ffi::OsString::from(
            "chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/",
        )]
        .into_iter(),
    )
    .unwrap();
    let revoked = root.join("revoked");
    let result = serve_native_host(
        &root,
        &identity,
        origin,
        (tokio::io::stdin(), tokio::io::stderr()),
        |_| {
            if revoked.exists() {
                Err(NativeBrowserError::Revoked)
            } else {
                Ok(())
            }
        },
    )
    .await;
    exit_native_host(result);
}

#[tokio::test]
async fn unverifiable_authorization_denies_the_client_but_keeps_the_connection() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let root = tempfile::tempdir().unwrap();
    let unavailable = Arc::new(AtomicBool::new(false));
    let guard = Arc::clone(&unavailable);
    let (host, mut extension, peer) = start_host_with(root.path(), move |_| {
        if guard.load(Ordering::SeqCst) {
            Err(NativeBrowserError::Unavailable)
        } else {
            Ok(())
        }
    })
    .await;
    unavailable.store(true, Ordering::SeqCst);
    for secret in [41, 43] {
        let identity = BrowserHostIdentity::from_secret_bytes([secret; 32]);
        assert!(
            ExtensionClient::connect(root.path(), &identity)
                .await
                .is_err()
        );
    }
    unavailable.store(false, Ordering::SeqCst);
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
