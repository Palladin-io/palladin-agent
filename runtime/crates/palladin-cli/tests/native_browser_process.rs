#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use palladin_browser_bridge::framing::{read_message, write_message};
use palladin_browser_bridge::local_transport::{
    LocalSecureFrame, LocalSessionOpen, accept_local_client,
};
use palladin_browser_bridge::secure_transport::{BrowserHostIdentity, INJECT_PROVIDER_PROTOCOL};
use palladin_cli::browser::local_socket_path;
use palladin_cli::native_browser::ExtensionClient;
use serde_json::{Value, json};

const TEST_ROOT_ENV: &str = "PALLADIN_NATIVE_HOST_TEST_ROOT";
const FIXTURE_IDENTITY: [u8; 32] = [71_u8; 32];

#[tokio::test]
async fn cli_authenticates_a_separate_host_process_before_prepare() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--ignored",
            "--exact",
            "authenticated_host_process_helper",
            "--nocapture",
        ])
        .env(TEST_ROOT_ENV, temporary.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn host helper");

    let socket = local_socket_path(temporary.path());
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        if child.try_wait().expect("host status").is_some() {
            panic!("host helper exited before opening its socket");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(socket.exists(), "host helper did not open its socket");

    let identity = BrowserHostIdentity::from_secret_bytes(FIXTURE_IDENTITY);
    let mut client = ExtensionClient::connect(temporary.path(), &identity)
        .await
        .expect("mutually authenticated process connection");
    let nonce = "P".repeat(32);
    let result = client.prepare(&nonce).await.expect("prepare result");
    assert_eq!(result.outcome, "ready");
    assert_eq!(
        result.current_url.as_deref(),
        Some("https://process.example.test/login")
    );
    assert!(child.wait().expect("host exit").success());
}

#[tokio::test]
#[ignore = "subprocess helper"]
async fn authenticated_host_process_helper() {
    let root = std::env::var_os(TEST_ROOT_ENV).expect("test root");
    let socket = local_socket_path(std::path::Path::new(&root));
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .expect("socket permissions");
    let identity = BrowserHostIdentity::from_secret_bytes(FIXTURE_IDENTITY);
    let (mut stream, _) = listener.accept().await.expect("accept CLI");
    let open: LocalSessionOpen = read_message(&mut stream).await.expect("session open");
    let (ready, mut session) = accept_local_client(&identity, &open).expect("authenticate CLI");
    write_message(&mut stream, &ready)
        .await
        .expect("session ready");
    let frame: LocalSecureFrame = read_message(&mut stream).await.expect("secure frame");
    let prepare: Value = session.open(&frame).expect("open prepare");
    let nonce = prepare
        .get("nonce")
        .and_then(Value::as_str)
        .expect("prepare nonce");
    assert_eq!(
        prepare.get("protocol"),
        Some(&json!(INJECT_PROVIDER_PROTOCOL))
    );
    assert_eq!(prepare.get("type"), Some(&json!("prepare")));
    let result = json!({
        "protocol": INJECT_PROVIDER_PROTOCOL,
        "type": "prepare.result",
        "nonce": nonce,
        "currentUrl": "https://process.example.test/login",
        "outcome": "ready"
    });
    let frame = session.seal(&result).expect("seal result");
    write_message(&mut stream, &frame)
        .await
        .expect("write result");
}
