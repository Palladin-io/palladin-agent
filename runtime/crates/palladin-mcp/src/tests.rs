use std::sync::Arc;
use std::time::Duration;

use rmcp::ServiceExt;
use serde_json::Value;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

use super::{
    ApplicationFuture, BoundedLineReader, ExecInput, ExecToolResult, GetInput, InjectInput,
    MAX_BATCH_ITEMS, MAX_FRAME_BYTES, McpApplication, PalladinMcpServer, ProtocolBridgeState,
    ReportStaleInput, SearchInput, ToolOutcome, collect_batch_response, load_tools, parse_input,
    prepare_incoming_message, pretty_result, serve_io, validate_get, validate_search, wait_options,
};

#[derive(Clone, Default)]
struct FakeApplication {
    calls: Arc<Mutex<Vec<String>>>,
}

impl McpApplication for FakeApplication {
    fn search<'a>(
        &'a self,
        input: SearchInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move {
            self.calls.lock().await.push("search".to_owned());
            ToolOutcome::success(
                serde_json::to_string_pretty(
                    &json!({"items": [], "nextCursor": null, "query": input.query}),
                )
                .expect("json"),
            )
        })
    }

    fn get<'a>(
        &'a self,
        _input: GetInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move {
            self.calls.lock().await.push("get".to_owned());
            ToolOutcome::success("synthetic-get")
        })
    }

    fn exec<'a>(
        &'a self,
        _input: ExecInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move { ToolOutcome::success("synthetic-exec") })
    }

    fn inject<'a>(
        &'a self,
        _input: InjectInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move { ToolOutcome::success("synthetic-inject") })
    }

    fn report_stale<'a>(
        &'a self,
        _input: ReportStaleInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move { ToolOutcome::success("synthetic-report") })
    }
}

#[test]
fn frozen_contract_exposes_exactly_five_legacy_tools() {
    let tools = load_tools().expect("contract");
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>(),
        vec![
            "search_entries",
            "get_credential",
            "exec_with_credential",
            "inject_credential",
            "report_credential_stale",
        ]
    );
    for tool in tools {
        assert!(tool.description.is_some());
        assert_eq!(tool.input_schema.get("type"), Some(&json!("object")));
    }
}

#[test]
fn dependency_tracing_is_compiled_out_for_secret_bearing_protocol_messages() {
    assert_eq!(
        tracing::level_filters::STATIC_MAX_LEVEL,
        tracing::level_filters::LevelFilter::OFF
    );
}

#[test]
fn mcp_wait_is_one_shot_unless_explicitly_requested() {
    let default = wait_options(None, None, None, None).expect("default");
    assert_eq!(default.wait_ms, Some(0));
    let explicit = wait_options(Some("30s"), None, Some("10s"), None).expect("explicit");
    assert_eq!(explicit.wait_ms, Some(30_000));
    assert_eq!(explicit.poll_ms, Some(10_000));
    let no_wait = wait_options(Some("30s"), Some(true), None, None).expect("no wait");
    assert_eq!(no_wait.wait_ms, Some(0));
    assert!(wait_options(Some("6m"), None, None, None).is_err());
    assert!(wait_options(Some(&"1".repeat(33)), None, None, None).is_err());
}

#[test]
fn tool_arguments_fail_closed_on_unknown_fields_and_invalid_wait_options() {
    assert!(
        parse_input::<GetInput>(json!({
            "vaultId": "vault-fixture",
            "entryId": "entry-fixture",
            "unexpected": "ignored-by-default-serde"
        }))
        .is_err()
    );
    let invalid_wait = parse_input::<GetInput>(json!({
        "vaultId": "vault-fixture",
        "entryId": "entry-fixture",
        "wait": "forever"
    }))
    .expect("shape is valid");
    assert!(validate_get(&invalid_wait).is_err());

    let unicode_query = SearchInput {
        query: "ż".repeat(512),
        cursor: None,
        page_size: None,
    };
    assert!(validate_search(&unicode_query).is_ok());
}

#[tokio::test]
async fn bounded_reader_rejects_oversized_frames_and_nul() {
    let (mut writer, reader) = tokio::io::duplex(MAX_FRAME_BYTES + 32);
    let task = tokio::spawn(async move {
        writer
            .write_all(&vec![b'x'; MAX_FRAME_BYTES + 1])
            .await
            .expect("write");
    });
    let mut reader = BoundedLineReader::new(reader, MAX_FRAME_BYTES);
    let mut bytes = Vec::new();
    assert!(reader.read_to_end(&mut bytes).await.is_err());
    task.await.expect("task");

    let (mut writer, reader) = tokio::io::duplex(16);
    writer.write_all(b"{}\0\n").await.expect("write");
    drop(writer);
    let mut reader = BoundedLineReader::new(reader, MAX_FRAME_BYTES);
    let mut bytes = Vec::new();
    assert!(reader.read_to_end(&mut bytes).await.is_err());
}

#[test]
fn server_constructs_from_frozen_contract() {
    PalladinMcpServer::new(FakeApplication::default()).expect("server");
}

#[test]
fn legacy_tool_result_shape_omits_false_and_marks_errors_true() {
    let success = serde_json::to_value(ToolOutcome::success("ok").into_mcp()).expect("success");
    assert_eq!(success["content"][0], json!({"type":"text","text":"ok"}));
    assert!(success.get("isError").is_none());

    let error = serde_json::to_value(ToolOutcome::error("failed").into_mcp()).expect("error");
    assert_eq!(error["content"][0], json!({"type":"text","text":"failed"}));
    assert_eq!(error["isError"], true);
}

#[test]
fn exec_result_contains_only_status_and_a_fixed_withheld_marker() {
    let outcome = pretty_result(&ExecToolResult {
        exit_code: 23,
        output: "withheld",
        note: "synthetic safe note",
    });
    assert!(!outcome.is_error);
    let result: Value = serde_json::from_str(&outcome.text).expect("exec result JSON");
    assert_eq!(
        result,
        json!({
            "exitCode": 23,
            "output": "withheld",
            "note": "synthetic safe note"
        })
    );
    assert!(result.get("stdout").is_none());
    assert!(result.get("stderr").is_none());
}

#[tokio::test]
async fn declared_protocol_versions_complete_the_raw_stdio_lifecycle() {
    for (client, protocol) in [
        ("Claude Code", "2024-11-05"),
        ("Codex", "2025-03-26"),
        ("MCP stable", "2025-06-18"),
        ("Cursor", "2025-11-25"),
    ] {
        let application = FakeApplication::default();
        let calls = application.calls.clone();
        let server = PalladinMcpServer::new(application).expect("server");
        let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
        let (server_read, server_write) = tokio::io::split(server_stream);
        let server_task = tokio::spawn(serve_io(server, server_read, server_write));

        let (client_read, mut client_write) = tokio::io::split(client_stream);
        let mut client_read = BufReader::new(client_read);
        send(
            &mut client_write,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": protocol,
                    "capabilities": {},
                    "clientInfo": {"name": client, "version": "synthetic"}
                }
            }),
        )
        .await;
        let initialized = receive(&mut client_read).await;
        assert_eq!(initialized["id"], 1);
        assert_eq!(initialized["result"]["protocolVersion"], protocol);
        assert_eq!(
            initialized["result"]["serverInfo"]["name"],
            "Palladin Agents"
        );

        send(
            &mut client_write,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await;
        send(
            &mut client_write,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        )
        .await;
        let listed = receive(&mut client_read).await;
        assert_eq!(listed["id"], 2);
        assert_eq!(
            listed["result"]["tools"].as_array().expect("tools").len(),
            5
        );

        send(
            &mut client_write,
            &json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"tools/call",
                "params":{"name":"search_entries","arguments":{"query":"fixture"}}
            }),
        )
        .await;
        let called = receive(&mut client_read).await;
        assert_eq!(called["id"], 3);
        assert!(
            called["result"]["content"][0]["text"]
                .as_str()
                .expect("text")
                .contains("fixture")
        );
        assert_eq!(calls.lock().await.as_slice(), ["search"]);

        client_write
            .shutdown()
            .await
            .expect("shutdown client input");
        drop(client_write);
        server_task
            .await
            .expect("server task")
            .expect("serve protocol");
    }
}

#[tokio::test]
async fn protocol_2025_03_accepts_json_rpc_request_batches() {
    let server = PalladinMcpServer::new(FakeApplication::default()).expect("server");
    let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let server_task = tokio::spawn(serve_io(server, server_read, server_write));
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut client_read = BufReader::new(client_read);

    send(
        &mut client_write,
        &json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{
                "protocolVersion":"2025-03-26",
                "capabilities":{},
                "clientInfo":{"name":"batch-fixture","version":"synthetic"}
            }
        }),
    )
    .await;
    assert_eq!(
        receive(&mut client_read).await["result"]["protocolVersion"],
        "2025-03-26"
    );
    send(
        &mut client_write,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    send(
        &mut client_write,
        &json!([
            {"jsonrpc":"2.0","id":2,"method":"ping","params":{}},
            {"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}
        ]),
    )
    .await;
    let response_batch = receive(&mut client_read).await;
    let responses = response_batch
        .as_array()
        .expect("one JSON-RPC response batch");
    assert_eq!(responses.len(), 2);
    let mut ids = [
        responses[0]["id"].as_i64().expect("first id"),
        responses[1]["id"].as_i64().expect("second id"),
    ];
    ids.sort_unstable();
    assert_eq!(ids, [2, 3]);

    client_write.shutdown().await.expect("shutdown input");
    drop(client_write);
    server_task
        .await
        .expect("server task")
        .expect("serve batch");
}

#[tokio::test]
async fn protocol_negotiation_falls_back_for_versions_outside_the_frozen_contract() {
    let server = PalladinMcpServer::new(FakeApplication::default()).expect("server");
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let server_task = tokio::spawn(serve_io(server, server_read, server_write));
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut client_read = BufReader::new(client_read);

    send(
        &mut client_write,
        &json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{
                "protocolVersion":"2026-07-28",
                "capabilities":{},
                "clientInfo":{"name":"future-draft","version":"synthetic"}
            }
        }),
    )
    .await;
    let initialized = receive(&mut client_read).await;
    assert_eq!(initialized["id"], 1);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    client_write.shutdown().await.expect("shutdown input");
    drop(client_write);
    server_task
        .await
        .expect("server task")
        .expect("serve fallback protocol");
}

#[test]
fn batch_bridge_is_version_aware_and_bounds_fan_out() {
    let uninitialized = Arc::new(std::sync::Mutex::new(ProtocolBridgeState::default()));
    assert!(
        prepare_incoming_message(
            json!([{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}]),
            &uninitialized,
        )
        .is_err()
    );

    let modern = Arc::new(std::sync::Mutex::new(ProtocolBridgeState::default()));
    prepare_incoming_message(
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{"protocolVersion":"2025-11-25"}
        }),
        &modern,
    )
    .expect("modern initialize");
    assert!(
        prepare_incoming_message(json!([{"jsonrpc":"2.0","id":2,"method":"ping"}]), &modern,)
            .is_err()
    );

    let legacy_batch = Arc::new(std::sync::Mutex::new(ProtocolBridgeState::default()));
    prepare_incoming_message(
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{"protocolVersion":"2025-03-26"}
        }),
        &legacy_batch,
    )
    .expect("batch initialize");
    let oversized = Value::Array(
        (0..=MAX_BATCH_ITEMS)
            .map(|id| json!({"jsonrpc":"2.0","id":id,"method":"ping"}))
            .collect(),
    );
    assert!(prepare_incoming_message(oversized, &legacy_batch).is_err());

    let malformed = Arc::new(std::sync::Mutex::new(ProtocolBridgeState::default()));
    prepare_incoming_message(
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{"protocolVersion":"2025-03-26"}
        }),
        &malformed,
    )
    .expect("batch initialize");
    assert!(
        prepare_incoming_message(json!([{"jsonrpc":"2.0","id":2,"method":42}]), &malformed,)
            .is_err()
    );
    let malformed_state = malformed.lock().expect("state");
    assert!(malformed_state.request_batches.is_empty());
    assert!(malformed_state.pending_batches.is_empty());
}

#[test]
fn batch_cancellation_releases_sibling_responses_and_state() {
    let state = Arc::new(std::sync::Mutex::new(ProtocolBridgeState::default()));
    prepare_incoming_message(
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{"protocolVersion":"2025-03-26"}
        }),
        &state,
    )
    .expect("batch initialize");
    let prepared = prepare_incoming_message(
        json!([
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}},
            {"jsonrpc":"2.0","id":3,"method":"ping","params":{}}
        ]),
        &state,
    )
    .expect("request batch");
    let get_internal_id = prepared.messages[0]["id"].clone();
    let ping_internal_id = prepared.messages[1]["id"].clone();
    assert_ne!(get_internal_id, 2);
    assert_ne!(ping_internal_id, 3);
    assert!(
        collect_batch_response(
            json!({"jsonrpc":"2.0","id":ping_internal_id,"result":{}}),
            &state
        )
        .is_none()
    );
    let cancellation = prepare_incoming_message(
        json!({
            "jsonrpc":"2.0",
            "method":"notifications/cancelled",
            "params":{"requestId":2}
        }),
        &state,
    )
    .expect("batch cancellation");
    assert!(cancellation.messages.is_empty());
    assert!(cancellation.ready_batches.is_empty());
    let response = collect_batch_response(
        json!({"jsonrpc":"2.0","id":get_internal_id,"result":{}}),
        &state,
    )
    .expect("remaining response batch");
    assert_eq!(response.as_array().expect("response batch").len(), 1);
    assert_eq!(response[0]["id"], 3);
    let state = state.lock().expect("state");
    assert!(state.request_batches.is_empty());
    assert!(state.external_batch_requests.is_empty());
    assert!(state.pending_batches.is_empty());
    assert!(
        state
            .batch_cancellations
            .lock()
            .expect("cancellations")
            .is_empty()
    );
}

#[test]
fn repeated_batch_cancellation_cleans_state_and_allows_external_id_reuse() {
    let state = Arc::new(std::sync::Mutex::new(ProtocolBridgeState::default()));
    prepare_incoming_message(
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{"protocolVersion":"2025-03-26"}
        }),
        &state,
    )
    .expect("batch initialize");

    for _ in 0..100 {
        let prepared =
            prepare_incoming_message(json!([{"jsonrpc":"2.0","id":7,"method":"ping"}]), &state)
                .expect("reused external ID after cleanup");
        let internal_id = prepared.messages[0]["id"].clone();
        let cancellation = prepare_incoming_message(
            json!({
                "jsonrpc":"2.0",
                "method":"notifications/cancelled",
                "params":{"requestId":7}
            }),
            &state,
        )
        .expect("cancellation");
        assert!(cancellation.messages.is_empty());
        assert!(
            collect_batch_response(
                json!({"jsonrpc":"2.0","id":internal_id,"result":{}}),
                &state,
            )
            .is_none()
        );
        let state = state.lock().expect("state");
        assert!(state.request_batches.is_empty());
        assert!(state.external_batch_requests.is_empty());
        assert!(state.pending_batches.is_empty());
        assert!(
            state
                .batch_cancellations
                .lock()
                .expect("cancellations")
                .is_empty()
        );
    }

    assert!(
        prepare_incoming_message(
            json!({
                "jsonrpc":"2.0",
                "id":"palladin-internal-batch:0",
                "method":"ping"
            }),
            &state,
        )
        .is_err()
    );
}

#[test]
fn forged_internal_cancellation_is_consumed_without_bypassing_bridge_cleanup() {
    let state = Arc::new(std::sync::Mutex::new(ProtocolBridgeState::default()));
    prepare_incoming_message(
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{"protocolVersion":"2025-03-26"}
        }),
        &state,
    )
    .expect("batch initialize");
    let prepared =
        prepare_incoming_message(json!([{"jsonrpc":"2.0","id":7,"method":"ping"}]), &state)
            .expect("request batch");
    let internal_id = prepared.messages[0]["id"].clone();

    let forged = prepare_incoming_message(
        json!({
            "jsonrpc":"2.0",
            "method":"notifications/cancelled",
            "params":{"requestId":internal_id}
        }),
        &state,
    )
    .expect("reserved cancellation is safely consumed");
    assert!(forged.messages.is_empty());
    {
        let state = state.lock().expect("state");
        let internal_key = serde_json::to_string(&internal_id).expect("internal key");
        assert!(
            !state
                .request_batches
                .get(&internal_key)
                .expect("tracked request")
                .cancellation
                .is_cancelled()
        );
    }

    let legitimate = prepare_incoming_message(
        json!({
            "jsonrpc":"2.0",
            "method":"notifications/cancelled",
            "params":{"requestId":7}
        }),
        &state,
    )
    .expect("legitimate cancellation");
    assert!(legitimate.messages.is_empty());
    assert!(
        collect_batch_response(
            json!({"jsonrpc":"2.0","id":internal_id,"result":{}}),
            &state,
        )
        .is_none()
    );
    let state = state.lock().expect("state");
    assert!(state.request_batches.is_empty());
    assert!(state.external_batch_requests.is_empty());
    assert!(state.pending_batches.is_empty());
    assert!(
        state
            .batch_cancellations
            .lock()
            .expect("cancellations")
            .is_empty()
    );
}

#[derive(Clone)]
struct CancelApplication {
    cancelled: Arc<Mutex<bool>>,
}

impl McpApplication for CancelApplication {
    fn search<'a>(
        &'a self,
        _input: SearchInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async { ToolOutcome::success("unused") })
    }

    fn get<'a>(
        &'a self,
        _input: GetInput,
        cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move {
            cancellation.cancelled().await;
            *self.cancelled.lock().await = true;
            ToolOutcome::error("cancelled")
        })
    }

    fn report_stale<'a>(
        &'a self,
        _input: ReportStaleInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async { ToolOutcome::success("unused") })
    }
}

#[tokio::test]
async fn cancellation_stops_a_tool_and_suppresses_its_late_response() {
    let cancelled = Arc::new(Mutex::new(false));
    let server = PalladinMcpServer::new(CancelApplication {
        cancelled: cancelled.clone(),
    })
    .expect("server");
    let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let server_task = tokio::spawn(async move {
        let running = server
            .serve((
                BoundedLineReader::new(server_read, MAX_FRAME_BYTES),
                server_write,
            ))
            .await
            .expect("initialize");
        running.waiting().await.expect("serve");
    });
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut client_read = BufReader::new(client_read);
    send(
        &mut client_write,
        &json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cancel-test","version":"1"}}
        }),
    )
    .await;
    receive(&mut client_read).await;
    send(
        &mut client_write,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    send(
        &mut client_write,
        &json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"get_credential","arguments":{"vaultId":"vault","entryId":"entry","noWait":true}}
        }),
    )
    .await;
    send(
        &mut client_write,
        &json!({
            "jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":2,"reason":"synthetic cancellation"}
        }),
    )
    .await;
    send(
        &mut client_write,
        &json!({"jsonrpc":"2.0","id":3,"method":"ping"}),
    )
    .await;
    let response = receive(&mut client_read).await;
    assert_eq!(
        response["id"], 3,
        "cancelled request must not emit a response"
    );
    for _ in 0..50 {
        if *cancelled.lock().await {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(*cancelled.lock().await);
    client_write
        .shutdown()
        .await
        .expect("shutdown client input");
    drop(client_write);
    server_task.await.expect("server task");
}

#[tokio::test]
async fn cancellation_inside_a_2025_03_batch_emits_the_remaining_response_array() {
    let cancelled = Arc::new(Mutex::new(false));
    let server = PalladinMcpServer::new(CancelApplication {
        cancelled: cancelled.clone(),
    })
    .expect("server");
    let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let server_task = tokio::spawn(serve_io(server, server_read, server_write));
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut client_read = BufReader::new(client_read);
    send(
        &mut client_write,
        &json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"batch-cancel-test","version":"1"}}
        }),
    )
    .await;
    receive(&mut client_read).await;
    send(
        &mut client_write,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    send(
        &mut client_write,
        &json!([
            {
                "jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"get_credential","arguments":{"vaultId":"vault","entryId":"entry","noWait":true}}
            },
            {
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"search_entries","arguments":{"query":"fixture"}}
            }
        ]),
    )
    .await;
    send(
        &mut client_write,
        &json!({
            "jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":2,"reason":"synthetic batch cancellation"}
        }),
    )
    .await;
    let response_batch = receive(&mut client_read).await;
    let responses = response_batch.as_array().expect("response batch");
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], 3);
    for _ in 0..50 {
        if *cancelled.lock().await {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(*cancelled.lock().await);
    client_write.shutdown().await.expect("shutdown input");
    drop(client_write);
    server_task
        .await
        .expect("server task")
        .expect("serve batch cancellation");
}

#[derive(Clone)]
struct LateApplication {
    started: Arc<Notify>,
    release: Arc<Notify>,
    completed: Arc<Notify>,
}

impl McpApplication for LateApplication {
    fn search<'a>(
        &'a self,
        _input: SearchInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async { ToolOutcome::success("search-result") })
    }

    fn get<'a>(
        &'a self,
        _input: GetInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move {
            self.started.notify_one();
            self.release.notified().await;
            self.completed.notify_one();
            ToolOutcome::success("late-get-result")
        })
    }

    fn report_stale<'a>(
        &'a self,
        _input: ReportStaleInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async { ToolOutcome::success("unused") })
    }
}

#[tokio::test]
async fn late_response_after_batch_cancellation_never_escapes_as_a_standalone_frame() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let completed = Arc::new(Notify::new());
    let server = PalladinMcpServer::new(LateApplication {
        started: started.clone(),
        release: release.clone(),
        completed: completed.clone(),
    })
    .expect("server");
    let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
    let (server_read, server_write) = tokio::io::split(server_stream);
    let server_task = tokio::spawn(serve_io(server, server_read, server_write));
    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut client_read = BufReader::new(client_read);
    send(
        &mut client_write,
        &json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"late-batch-test","version":"1"}}
        }),
    )
    .await;
    receive(&mut client_read).await;
    send(
        &mut client_write,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    send(
        &mut client_write,
        &json!([
            {
                "jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"get_credential","arguments":{"vaultId":"vault","entryId":"entry","noWait":true}}
            },
            {
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"search_entries","arguments":{"query":"fixture"}}
            }
        ]),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("get started");
    send(
        &mut client_write,
        &json!({
            "jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":2,"reason":"synthetic late completion"}
        }),
    )
    .await;
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), completed.notified())
        .await
        .expect("late get completed");
    let response_batch = receive(&mut client_read).await;
    let responses = response_batch.as_array().expect("response batch");
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], 3);
    send(
        &mut client_write,
        &json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
    )
    .await;
    let response = receive(&mut client_read).await;
    assert_eq!(
        response["id"], 2,
        "cancelled external ID must be reusable after deterministic cleanup"
    );

    client_write.shutdown().await.expect("shutdown input");
    drop(client_write);
    server_task
        .await
        .expect("server task")
        .expect("serve late batch cancellation");
}

async fn send(writer: &mut (impl AsyncWrite + Unpin), value: &Value) {
    let mut bytes = serde_json::to_vec(value).expect("serialize");
    bytes.push(b'\n');
    writer.write_all(&bytes).await.expect("write request");
    writer.flush().await.expect("flush request");
}

async fn receive(reader: &mut BufReader<impl AsyncRead + Unpin>) -> Value {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
        .await
        .expect("response timeout")
        .expect("read response");
    assert!(line.ends_with('\n'));
    serde_json::from_str(&line).expect("every stdout line is one JSON-RPC message")
}
