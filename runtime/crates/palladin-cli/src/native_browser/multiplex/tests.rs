use super::*;
use crate::native_browser::test_peer::ExtensionPeer;
use crate::native_browser::{ExtensionClient, serve_multiplex_client};
use palladin_browser_bridge::framing::{read_message, write_message};
use palladin_browser_bridge::local_transport::{LocalClientHandshake, LocalSessionReady};
use palladin_browser_bridge::secure_transport::{
    BrowserHostIdentity, INJECT_PROVIDER_PROTOCOL, SecureFrame,
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::net::UnixStream;

fn session_info() -> palladin_browser_bridge::discovery::BrowserSessionInfo {
    palladin_browser_bridge::discovery::BrowserSessionInfo {
        browser_session: "a".repeat(32),
        concurrent: true,
    }
}

async fn local_client(mut stream: UnixStream) -> ExtensionClient {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (open, handshake) = LocalClientHandshake::start(&identity).unwrap();
    write_message(&mut stream, &open).await.unwrap();
    let ready: LocalSessionReady = read_message(&mut stream).await.unwrap();
    ExtensionClient {
        stream,
        session: handshake.finish(&ready).unwrap(),
    }
}

#[tokio::test]
async fn authenticated_status_query_does_not_touch_the_browser_or_consume_operation_capacity() {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (session, _peer) = ExtensionPeer::start(&identity);
    let (connection, _broker) = BrowserConnection::new(session);
    let held: Vec<_> = (0..32).map(|_| connection.operation().unwrap()).collect();
    let (client, local) = UnixStream::pair().unwrap();
    let host = tokio::spawn(async move {
        serve_multiplex_client(local, &identity, &connection, &session_info(), &|_| Ok(())).await
    });
    let mut client = local_client(client).await;
    let nonce = "e".repeat(64);
    let frame = client
        .session
        .seal(
            &json!({"protocol":palladin_browser_bridge::local_transport::LOCAL_TRANSPORT_PROTOCOL,
        "type":"browser.status","nonce":nonce}),
        )
        .unwrap();
    write_message(&mut client.stream, &frame).await.unwrap();
    let response = read_message::<palladin_browser_bridge::local_transport::LocalSecureFrame>(
        &mut client.stream,
    )
    .await;
    assert!(
        response.is_ok(),
        "status must answer without starting a browser operation"
    );
    let response: Value = client.session.open(&response.unwrap()).unwrap();
    assert_eq!(response["type"], "browser.status.result");
    assert_eq!(response["nonce"], nonce);
    assert_eq!(response["session"]["concurrent"], true);
    assert!(
        response["session"]["browserSession"]
            .as_str()
            .is_some_and(palladin_browser_bridge::routing::valid_browser_session_id)
    );
    host.await.unwrap().unwrap();
    drop(held);
}

#[tokio::test]
async fn operation_capacity_is_released_only_after_authenticated_close_acknowledgement() {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (session, peer) = ExtensionPeer::start(&identity);
    let (connection, broker) = BrowserConnection::new(session);
    let mut operations: Vec<_> = (0..32).map(|_| connection.operation().unwrap()).collect();
    assert!(
        connection.operation().is_err(),
        "active operations must be bounded"
    );
    drop(operations.pop());
    assert!(
        connection.operation().is_err(),
        "unacknowledged cleanup still owns capacity"
    );
    let (host, mut browser) = tokio::io::duplex(65536);
    let task = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(host);
        broker.run(&mut input, &mut output).await
    });
    let frame: SecureFrame = read_message(&mut browser).await.unwrap();
    let close = peer.open(&frame, 0);
    assert_eq!(close["type"], "operation.close");
    write_message(
        &mut browser,
        &peer.seal(
            json!({"protocol":INJECT_PROVIDER_PROTOCOL,
        "type":"operation.closed", "operationId":close["operationId"]}),
            0,
        ),
    )
    .await
    .unwrap();
    let replacement = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(operation) = connection.operation() {
                break operation;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(connection.operation().is_err());
    connection.stop();
    task.await.unwrap().unwrap();
    drop(replacement);
}

#[tokio::test(start_paused = true)]
async fn missing_close_acknowledgement_terminates_the_stale_channel_without_replay() {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (session, peer) = ExtensionPeer::start(&identity);
    let (connection, broker) = BrowserConnection::new(session);
    drop(connection.operation().unwrap());
    let (host, mut browser) = tokio::io::duplex(65536);
    let task = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(host);
        broker.run(&mut input, &mut output).await
    });
    let frame: SecureFrame = read_message(&mut browser).await.unwrap();
    assert_eq!(peer.open(&frame, 0)["type"], "operation.close");
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;
    assert!(
        task.is_finished(),
        "a missing close acknowledgement must not retain state forever"
    );
    assert!(task.await.unwrap().is_err());
    assert!(connection.operation().is_err());
    use tokio::io::AsyncReadExt;
    let mut next = [0_u8; 1];
    assert_eq!(
        browser.read(&mut next).await.unwrap(),
        0,
        "no operation is replayed during cleanup"
    );
}

#[tokio::test]
async fn two_authenticated_local_clients_prepare_independently_on_one_browser_connection() {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (session, peer) = ExtensionPeer::start(&identity);
    let (connection, broker) = BrowserConnection::new(session);
    let (host, mut browser) = tokio::io::duplex(65536);
    let broker_task = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(host);
        broker.run(&mut input, &mut output).await
    });
    let mut servers = Vec::new();
    let mut clients = Vec::new();
    for tab in [7, 8] {
        let (client, local) = UnixStream::pair().unwrap();
        let connection = connection.clone();
        servers.push(tokio::spawn(async move {
            let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
            serve_multiplex_client(local, &identity, &connection, &session_info(), &|_| Ok(()))
                .await
        }));
        clients.push(tokio::spawn(async move {
            let mut client = local_client(client).await;
            let prepared = client
                .prepare(
                    &format!("{tab:064x}"),
                    Some(tab),
                    Some("https://example.test/login"),
                )
                .await
                .unwrap();
            assert_eq!(prepared.outcome, "ready");
            client
        }));
    }
    let mut requests = Vec::new();
    for sequence in 0..2 {
        let frame: SecureFrame =
            tokio::time::timeout(Duration::from_secs(1), read_message(&mut browser))
                .await
                .unwrap()
                .unwrap();
        requests.push(peer.open(&frame, sequence));
    }
    for (sequence, tab) in [8, 7].into_iter().enumerate() {
        let request = requests
            .iter()
            .find(|request| request["request"]["targetTabId"] == tab)
            .unwrap();
        write_message(&mut browser, &peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result",
            "operationId":request["operationId"],"response":{"protocol":INJECT_PROVIDER_PROTOCOL,"type":"prepare.result",
            "nonce":request["request"]["nonce"],"currentUrl":"https://example.test/login","outcome":"ready"}}), sequence as u64)).await.unwrap();
        let completed = clients.remove(if tab == 8 { 1 } else { 0 });
        let client = tokio::time::timeout(Duration::from_secs(1), completed)
            .await
            .unwrap()
            .unwrap();
        if tab == 8 {
            assert!(
                !clients[0].is_finished(),
                "the other tab is still awaiting its own response"
            );
        }
        drop(client);
    }
    for server in servers {
        assert!(
            tokio::time::timeout(Duration::from_secs(1), server)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
    connection.stop();
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn disconnected_local_client_closes_only_its_operation_without_waiting_for_browser_reply() {
    canceled_operation_keeps_other_operations_available(true).await;
}

#[tokio::test]
async fn canceled_operation_accepts_close_ack_without_a_result() {
    canceled_operation_keeps_other_operations_available(false).await;
}

async fn canceled_operation_keeps_other_operations_available(send_result: bool) {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (session, peer) = ExtensionPeer::start(&identity);
    let (connection, broker) = BrowserConnection::new(session);
    let (host, mut browser) = tokio::io::duplex(65536);
    let broker_task = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(host);
        broker.run(&mut input, &mut output).await
    });
    let (client, local) = UnixStream::pair().unwrap();
    let host_connection = connection.clone();
    let mut serving = tokio::spawn(async move {
        serve_multiplex_client(local, &identity, &host_connection, &session_info(), &|_| {
            Ok(())
        })
        .await
    });
    let client = tokio::spawn(async move {
        let mut client = local_client(client).await;
        client
            .prepare(&"a".repeat(64), Some(7), Some("https://example.test/login"))
            .await
    });
    let prepare: SecureFrame = read_message(&mut browser).await.unwrap();
    let prepare = peer.open(&prepare, 0);
    client.abort();
    assert!(matches!(client.await, Err(error) if error.is_cancelled()));
    let result = tokio::time::timeout(Duration::from_millis(100), &mut serving).await;
    assert!(
        result.is_ok(),
        "local cancellation must not wait for the browser timeout"
    );
    let closed: SecureFrame = read_message(&mut browser).await.unwrap();
    assert_eq!(peer.open(&closed, 1)["operationId"], prepare["operationId"]);
    let late = peer.seal(
        json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result",
        "operationId":prepare["operationId"],"response":{"outcome":"provider-unavailable"}}),
        0,
    );
    if send_result {
        write_message(&mut browser, &late).await.unwrap();
    }
    let sequence = u64::from(send_result);
    let closed = peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.closed","operationId":prepare["operationId"]}), sequence);
    write_message(&mut browser, &closed).await.unwrap();
    let other = connection.operation().unwrap();
    let pending = other.enqueue(&json!({"type":"prepare"}), None).unwrap();
    let frame: SecureFrame = read_message(&mut browser).await.unwrap();
    let request = peer.open(&frame, 2);
    write_message(
        &mut browser,
        &peer.seal(
            json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result",
        "operationId":request["operationId"],"response":{"outcome":"ready"}}),
            sequence + 1,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        pending
            .receive::<Value>(Duration::from_secs(1))
            .await
            .unwrap()["outcome"],
        "ready"
    );
    connection.stop();
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn authenticated_out_of_order_replies_reach_only_their_operation() {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (session, peer) = ExtensionPeer::start(&identity);
    let (connection, broker) = BrowserConnection::new(session);
    let (host, mut browser) = tokio::io::duplex(65536);
    let task = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(host);
        broker.run(&mut input, &mut output).await
    });
    let first = connection.operation().unwrap();
    let second = connection.operation().unwrap();
    let a = first
        .enqueue(&json!({"type":"prepare", "nonce":"first"}), None)
        .unwrap();
    let b = second
        .enqueue(&json!({"type":"prepare", "nonce":"second"}), None)
        .unwrap();
    let wire_a: SecureFrame = read_message(&mut browser).await.unwrap();
    let wire_b: SecureFrame = read_message(&mut browser).await.unwrap();
    let request_a = peer.open(&wire_a, 0);
    let request_b = peer.open(&wire_b, 1);
    assert_eq!(request_a["type"], "operation.request");
    assert_ne!(request_a["operationId"], request_b["operationId"]);
    for (sequence, request) in [request_b, request_a].into_iter().enumerate() {
        let frame = peer.seal(json!({"protocol":INJECT_PROVIDER_PROTOCOL, "type":"operation.result",
            "operationId":request["operationId"], "response":{"nonce":request["request"]["nonce"]}}), sequence as u64);
        write_message(&mut browser, &frame).await.unwrap();
    }
    assert_eq!(
        b.receive::<Value>(Duration::from_secs(1)).await.unwrap()["nonce"],
        "second"
    );
    assert_eq!(
        a.receive::<Value>(Duration::from_secs(1)).await.unwrap()["nonce"],
        "first"
    );
    connection.stop();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn expired_queued_request_is_not_sent_and_does_not_consume_a_secure_sequence() {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (session, peer) = ExtensionPeer::start(&identity);
    let (connection, broker) = BrowserConnection::new(session);
    let expired = connection.operation().unwrap();
    let live = connection.operation().unwrap();
    let deadline = (super::super::monotonic_now_ns().unwrap() - 1).to_string();
    let rejected = expired
        .enqueue(
            &json!({"type":"inject","values":[{"value":"synthetic-only"}]}),
            Some(&deadline),
        )
        .unwrap();
    let accepted = live.enqueue(&json!({"type":"prepare"}), None).unwrap();
    let (host, mut browser) = tokio::io::duplex(65536);
    let task = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(host);
        broker.run(&mut input, &mut output).await
    });
    let frame: SecureFrame = read_message(&mut browser).await.unwrap();
    let request = peer.open(&frame, 0);
    assert_eq!(request["request"]["type"], "prepare");
    assert!(matches!(
        rejected.receive::<Value>(Duration::from_secs(1)).await,
        Err(NativeBrowserError::AuthorizationExpired)
    ));
    write_message(
        &mut browser,
        &peer.seal(
            json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result",
        "operationId":request["operationId"],"response":{"outcome":"ready"}}),
            0,
        ),
    )
    .await
    .unwrap();
    // EOF must not overtake the authenticated response that preceded it.
    drop(browser);
    assert_eq!(
        accepted
            .receive::<Value>(Duration::from_secs(1))
            .await
            .unwrap()["outcome"],
        "ready"
    );
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn wrong_operation_correlation_fails_closed_without_delivering_a_response() {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (session, peer) = ExtensionPeer::start(&identity);
    let (connection, broker) = BrowserConnection::new(session);
    let operation = connection.operation().unwrap();
    let pending = operation.enqueue(&json!({"type":"prepare"}), None).unwrap();
    let (host, mut browser) = tokio::io::duplex(65536);
    let task = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(host);
        broker.run(&mut input, &mut output).await
    });
    let _: SecureFrame = read_message(&mut browser).await.unwrap();
    write_message(
        &mut browser,
        &peer.seal(
            json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result",
        "operationId":"not-the-requested-operation","response":{"outcome":"ready"}}),
            0,
        ),
    )
    .await
    .unwrap();
    assert!(
        pending
            .receive::<Value>(Duration::from_secs(1))
            .await
            .is_err()
    );
    assert!(matches!(
        task.await.unwrap(),
        Err(NativeBrowserError::InvalidMessage)
    ));
}

#[tokio::test]
async fn authenticated_target_probe_returns_without_entering_the_credential_flow() {
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    let (session, peer) = ExtensionPeer::start(&identity);
    let (connection, broker) = BrowserConnection::new(session);
    let (host, mut browser) = tokio::io::duplex(65536);
    let broker_task = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(host);
        broker.run(&mut input, &mut output).await
    });
    let (client, local) = UnixStream::pair().unwrap();
    let local_connection = connection.clone();
    let local_task = tokio::spawn(async move {
        serve_multiplex_client(
            local,
            &identity,
            &local_connection,
            &session_info(),
            &|_| Ok(()),
        )
        .await
    });
    let local = async {
        let mut client = local_client(client).await;
        let request = json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"target.probe","nonce":"e".repeat(64),
            "targetTabId":7,"targetUrl":"https://example.test/login"});
        let frame = client.session.seal(&request).unwrap();
        write_message(&mut client.stream, &frame).await.unwrap();
        let frame = read_message(&mut client.stream).await.unwrap();
        let response: Value = client.session.open(&frame).unwrap();
        assert_eq!(response["type"], "target.probe.result");
        assert_eq!(response["nonce"], request["nonce"]);
        assert_eq!(response["outcome"], "match");
    };
    let browser = async {
        let frame: SecureFrame = read_message(&mut browser).await.unwrap();
        let envelope = peer.open(&frame, 0);
        assert_eq!(envelope["request"]["type"], "target.probe");
        let reply = json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"operation.result",
            "operationId":envelope["operationId"],"response":{"protocol":INJECT_PROVIDER_PROTOCOL,
            "type":"target.probe.result","nonce":envelope["request"]["nonce"],"outcome":"match"}});
        write_message(&mut browser, &peer.seal(reply, 0))
            .await
            .unwrap();
        let frame: SecureFrame = read_message(&mut browser).await.unwrap();
        let closed = peer.open(&frame, 1);
        assert_eq!(closed["type"], "operation.close");
        write_message(
            &mut browser,
            &peer.seal(
                json!({"protocol":INJECT_PROVIDER_PROTOCOL,
            "type":"operation.closed","operationId":closed["operationId"]}),
                1,
            ),
        )
        .await
        .unwrap();
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(local, browser);
    })
    .await
    .unwrap();
    local_task.await.unwrap().unwrap();
    connection.stop();
    broker_task.await.unwrap().unwrap();
}
