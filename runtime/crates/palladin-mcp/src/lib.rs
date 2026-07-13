#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use palladin_api::{
    ApiError, CredentialAccess, CredentialMethod, ReportCredentialStaleInput, StaleReasonCode,
};
use palladin_credential::access::access_message;
use palladin_credential::fields::{
    FieldSelector, ResolvedField, redact_totp_secrets, resolve_field,
};
use palladin_credential::secret::parse_secret;
use palladin_credential::wait::{ProgressMode, WaitOptions, heartbeat_line, parse_duration};
use palladin_runtime::{
    CredentialDelivery, CredentialDeliveryRequest, CredentialExecOutcome, CredentialExecRequest,
    OperatorOutput, RuntimeError, RuntimeSession,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler, ServiceExt};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_PARALLEL_REQUESTS: usize = 8;
const MAX_PARALLEL_SECRET_OPERATIONS: usize = 1;
const MAX_MCP_WAIT_MS: u64 = 300_000;
const MAX_BATCH_ITEMS: usize = 32;
const MAX_PENDING_BATCHES: usize = 8;
const MAX_PENDING_BATCH_REQUESTS: usize = 64;
const INTERNAL_BATCH_ID_PREFIX: &str = "palladin-internal-batch:";
const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";
const UNSUPPORTED_VERSION_SENTINEL: &str = "palladin-unsupported-version";
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 4] =
    ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
const GET_EXPOSURE_WARNING: &str = "Note: this secret is now in the Agent's context. On a hosted LLM it may leave your machine. Prefer palladin exec or palladin inject to avoid exposing it.";
const CONTRACT_JSON: &str = include_str!("../../../contracts/v1/mcp-tools.json");

type ApplicationFuture<'a> = Pin<Box<dyn Future<Output = ToolOutcome> + Send + 'a>>;

pub trait McpApplication: Send + Sync + 'static {
    fn search<'a>(
        &'a self,
        input: SearchInput,
        cancellation: CancellationToken,
    ) -> ApplicationFuture<'a>;

    fn get<'a>(&'a self, input: GetInput, cancellation: CancellationToken)
    -> ApplicationFuture<'a>;

    fn exec<'a>(
        &'a self,
        _input: ExecInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async {
            ToolOutcome::error(
                "Native exec is not available in this runtime build. Update Palladin Runtime after the reviewed process-isolation component is installed.",
            )
        })
    }

    fn inject<'a>(
        &'a self,
        _input: InjectInput,
        _cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async {
            ToolOutcome::error(
                "Native browser injection is not available in this runtime build. Update Palladin Runtime after the reviewed browser boundary is installed.",
            )
        })
    }

    fn report_stale<'a>(
        &'a self,
        input: ReportStaleInput,
        cancellation: CancellationToken,
    ) -> ApplicationFuture<'a>;
}

#[derive(Clone)]
pub struct NativeApplication {
    session: Arc<RuntimeSession>,
}

impl NativeApplication {
    #[must_use]
    pub fn new(session: RuntimeSession) -> Self {
        Self {
            session: Arc::new(session),
        }
    }
}

impl McpApplication for NativeApplication {
    fn search<'a>(
        &'a self,
        input: SearchInput,
        cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move {
            let result = tokio::select! {
                () = cancellation.cancelled() => return ToolOutcome::error("Search was cancelled."),
                result = self.session.search_entries(
                    input.query.trim(),
                    input.cursor.as_deref(),
                    input.page_size,
                ) => result,
            };
            match result {
                Ok(result) => pretty_result(&result),
                Err(error) => runtime_failure(&error),
            }
        })
    }

    fn get<'a>(
        &'a self,
        input: GetInput,
        cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move {
            let wait = match input.wait_options() {
                Ok(wait) => wait,
                Err(message) => return ToolOutcome::error(message),
            };
            let progress = wait.progress.unwrap_or(ProgressMode::Plain);
            let delivery = self
                .session
                .deliver_for_get(
                    CredentialDeliveryRequest {
                        vault_id: input.vault_id.trim(),
                        entry_id: input.entry_id.trim(),
                        reason: input.reason.as_deref(),
                        wait,
                    },
                    &cancellation,
                    move |heartbeat| {
                        if let Some(line) = heartbeat_line(progress, &heartbeat) {
                            eprint!("{line}");
                        }
                    },
                )
                .await;
            match delivery {
                Ok(CredentialDelivery::Granted(credential)) => {
                    let selector = FieldSelector {
                        field: input.field,
                        field_id: input.field_id,
                    };
                    if selector.field.is_some() || selector.field_id.is_some() {
                        let parsed =
                            match parse_secret(credential.expose_for_authorized_operation()) {
                                Ok(parsed) => parsed,
                                Err(_) => {
                                    return ToolOutcome::error(
                                        "The credential payload is invalid.",
                                    );
                                }
                            };
                        let selected = match resolve_field(&parsed, &selector) {
                            Ok(selected) => selected,
                            Err(error) => return ToolOutcome::error(error.to_string()),
                        };
                        match selected {
                            ResolvedField::Value {
                                label: field,
                                value,
                                ..
                            } => pretty_result(&FieldValueResult {
                                access: "granted",
                                entry_id: &credential.entry_id,
                                label: &credential.label,
                                field: &field,
                                value: value.expose_secret(),
                            }),
                            ResolvedField::Totp {
                                label: field,
                                code,
                                expires_in,
                            } => pretty_result(&TotpResult {
                                access: "granted",
                                entry_id: &credential.entry_id,
                                label: &credential.label,
                                field: &field,
                                code: code.expose_secret(),
                                expires_in,
                            }),
                        }
                    } else {
                        let unix_seconds =
                            u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
                                .unwrap_or(0);
                        let secret = match redact_totp_secrets(
                            credential.expose_for_authorized_operation(),
                            unix_seconds,
                        ) {
                            Ok(secret) => secret,
                            Err(_) => {
                                return ToolOutcome::error("The credential payload is invalid.");
                            }
                        };
                        pretty_result(&FullCredentialResult {
                            access: "granted",
                            entry_id: &credential.entry_id,
                            label: &credential.label,
                            secret: secret.expose_secret(),
                            warning: GET_EXPOSURE_WARNING,
                        })
                    }
                }
                Ok(CredentialDelivery::NotGranted(access)) => {
                    let message = access_message(&access, CredentialMethod::Get)
                        .unwrap_or_else(|| "Credential access is unavailable.".to_owned());
                    pretty_result(&AccessResult {
                        access: access_name(&access),
                        message: &message,
                    })
                }
                Err(error) => runtime_failure(&error),
            }
        })
    }

    fn exec<'a>(
        &'a self,
        input: ExecInput,
        cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move {
            let wait = match input.wait_options() {
                Ok(wait) => wait,
                Err(message) => return ToolOutcome::error(message),
            };
            let progress = wait.progress.unwrap_or(ProgressMode::Plain);
            let execution = self
                .session
                .execute_with_credential(
                    CredentialExecRequest {
                        delivery: CredentialDeliveryRequest {
                            vault_id: input.vault_id.trim(),
                            entry_id: input.entry_id.trim(),
                            reason: input.reason.as_deref(),
                            wait,
                        },
                        command: input.command.as_deref(),
                        env_mappings: &[],
                        output: OperatorOutput::Discard,
                    },
                    &cancellation,
                    move |heartbeat| {
                        if let Some(line) = heartbeat_line(progress, &heartbeat) {
                            eprint!("{line}");
                        }
                    },
                )
                .await;
            match execution {
                Ok(CredentialExecOutcome::Completed(result)) => pretty_result(&ExecToolResult {
                    exit_code: result.exit_code,
                    output: "withheld",
                    note: if result.cancelled {
                        "The command was cancelled and its process group was terminated. Command output was discarded and was not logged."
                    } else {
                        "Command stdout and stderr were discarded and withheld from the model. Output was not persisted because transformed secrets cannot be safely masked. Judge success from the exit code."
                    },
                }),
                Ok(CredentialExecOutcome::NotGranted(access)) => {
                    let message = access_message(&access, CredentialMethod::Exec)
                        .unwrap_or_else(|| "Credential access is unavailable.".to_owned());
                    pretty_result(&AccessResult {
                        access: access_name(&access),
                        message: &message,
                    })
                }
                Err(error) => exec_failure(&error),
            }
        })
    }

    fn report_stale<'a>(
        &'a self,
        input: ReportStaleInput,
        cancellation: CancellationToken,
    ) -> ApplicationFuture<'a> {
        Box::pin(async move {
            let request = ReportCredentialStaleInput {
                vault_id: input.vault_id.trim().to_owned(),
                entry_id: input.entry_id.trim().to_owned(),
                code: input.code.unwrap_or_default().into(),
                note: input
                    .note
                    .map(|note| note.trim().to_owned())
                    .filter(|note| !note.is_empty()),
            };
            let result = tokio::select! {
                () = cancellation.cancelled() => return ToolOutcome::error("Stale-credential report was cancelled."),
                result = self.session.report_credential_stale(&request) => result,
            };
            match result {
                Ok(()) => ToolOutcome::success(
                    "Reported the credential as not working - the vault owners have been notified to rotate it.",
                ),
                Err(error) => runtime_failure(&error),
            }
        })
    }
}

#[derive(Clone)]
pub struct PalladinMcpServer<A: McpApplication> {
    application: Arc<A>,
    tools: Arc<Vec<Tool>>,
    global_limit: Arc<Semaphore>,
    secret_limit: Arc<Semaphore>,
    batch_cancellations: Arc<Mutex<HashMap<String, CancellationToken>>>,
    next_internal_request_id: Arc<AtomicU64>,
}

impl<A: McpApplication> PalladinMcpServer<A> {
    pub fn new(application: A) -> Result<Self, ContractError> {
        Ok(Self {
            application: Arc::new(application),
            tools: Arc::new(load_tools()?),
            global_limit: Arc::new(Semaphore::new(MAX_PARALLEL_REQUESTS)),
            secret_limit: Arc::new(Semaphore::new(MAX_PARALLEL_SECRET_OPERATIONS)),
            batch_cancellations: Arc::new(Mutex::new(HashMap::new())),
            next_internal_request_id: Arc::new(AtomicU64::new(0)),
        })
    }

    async fn invoke(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let _global = self
            .global_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| McpError::internal_error("Server request limit reached", None))?;
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let cancellation = serde_json::to_value(&context.id)
            .ok()
            .and_then(|id| request_id_key(&id).ok())
            .and_then(|id| {
                self.batch_cancellations
                    .lock()
                    .ok()
                    .and_then(|tokens| tokens.get(&id).cloned())
            })
            .unwrap_or_else(|| context.ct.clone());
        let outcome = match request.name.as_ref() {
            "search_entries" => {
                let input = parse_input::<SearchInput>(arguments)?;
                validate_search(&input)?;
                self.application.search(input, cancellation).await
            }
            "get_credential" => {
                let input = parse_input::<GetInput>(arguments)?;
                validate_get(&input)?;
                let _secret = self.secret_limit.clone().try_acquire_owned().map_err(|_| {
                    McpError::internal_error("Another credential operation is in progress", None)
                })?;
                self.application.get(input, cancellation).await
            }
            "exec_with_credential" => {
                let input = parse_input::<ExecInput>(arguments)?;
                validate_exec(&input)?;
                let _secret = self.secret_limit.clone().try_acquire_owned().map_err(|_| {
                    McpError::internal_error("Another credential operation is in progress", None)
                })?;
                self.application.exec(input, cancellation).await
            }
            "inject_credential" => {
                let input = parse_input::<InjectInput>(arguments)?;
                validate_inject(&input)?;
                let _secret = self.secret_limit.clone().try_acquire_owned().map_err(|_| {
                    McpError::internal_error("Another credential operation is in progress", None)
                })?;
                self.application.inject(input, cancellation).await
            }
            "report_credential_stale" => {
                let input = parse_input::<ReportStaleInput>(arguments)?;
                validate_report(&input)?;
                self.application.report_stale(input, cancellation).await
            }
            _ => {
                return Err(McpError::invalid_params("Unknown tool", None));
            }
        };
        Ok(outcome.into_mcp())
    }
}

impl<A: McpApplication> ServerHandler for PalladinMcpServer<A> {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(
                Implementation::new("Palladin Agents", env!("CARGO_PKG_VERSION"))
                    .with_title("Palladin Agent Runtime")
                    .with_description("Zero-knowledge credential tools for AI Agents"),
            )
            .with_instructions(
                "Prefer exec_with_credential or inject_credential. Use get_credential only when plaintext must enter the model context.",
            )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        let tools = self.tools.as_ref().clone();
        async move {
            Ok(ListToolsResult {
                tools,
                ..ListToolsResult::default()
            })
        }
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools.iter().find(|tool| tool.name == name).cloned()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.invoke(request, context).await
    }
}

pub async fn serve_stdio<A: McpApplication>(
    server: PalladinMcpServer<A>,
) -> Result<(), McpServeError> {
    serve_io(server, tokio::io::stdin(), tokio::io::stdout()).await
}

async fn serve_io<A, R, W>(
    server: PalladinMcpServer<A>,
    reader: R,
    writer: W,
) -> Result<(), McpServeError>
where
    A: McpApplication,
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let state = Arc::new(Mutex::new(ProtocolBridgeState::new(
        server.batch_cancellations.clone(),
        server.next_internal_request_id.clone(),
    )));
    let (ready_batch_sender, ready_batch_receiver) = mpsc::channel(MAX_PENDING_BATCHES);
    let (normalized_reader, normalized_writer) = tokio::io::duplex(64 * 1024);
    let (server_output_reader, server_output_writer) = tokio::io::duplex(64 * 1024);
    let mut input_bridge = tokio::spawn(normalize_incoming_messages(
        reader,
        normalized_writer,
        Arc::clone(&state),
        ready_batch_sender,
    ));
    let mut output_bridge = tokio::spawn(normalize_outgoing_messages(
        server_output_reader,
        writer,
        state,
        ready_batch_receiver,
    ));
    let service = match server
        .serve((normalized_reader, server_output_writer))
        .await
    {
        Ok(service) => service,
        Err(_) => {
            input_bridge.abort();
            output_bridge.abort();
            return Err(McpServeError::Initialization);
        }
    };
    service
        .waiting()
        .await
        .map_err(|_| McpServeError::Transport)?;
    finish_bridge(&mut input_bridge).await?;
    finish_bridge(&mut output_bridge).await
}

async fn finish_bridge(
    bridge: &mut tokio::task::JoinHandle<io::Result<()>>,
) -> Result<(), McpServeError> {
    match tokio::time::timeout(Duration::from_secs(1), &mut *bridge).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(_))) | Ok(Err(_)) => Err(McpServeError::Transport),
        Err(_) => {
            bridge.abort();
            Err(McpServeError::Transport)
        }
    }
}

async fn normalize_incoming_messages<R, W>(
    reader: R,
    mut writer: W,
    state: Arc<Mutex<ProtocolBridgeState>>,
    ready_batch_sender: mpsc::Sender<Value>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(BoundedLineReader::new(reader, MAX_FRAME_BYTES));
    let mut line = Vec::new();
    loop {
        let count = reader.read_until(b'\n', &mut line).await?;
        if count == 0 {
            break;
        }
        let framed = line.strip_suffix(b"\n").unwrap_or(&line);
        let framed = framed.strip_suffix(b"\r").unwrap_or(framed);
        if framed.is_empty() {
            line.clear();
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(framed) else {
            writer.write_all(framed).await?;
            writer.write_all(b"\n").await?;
            line.clear();
            continue;
        };
        let prepared = prepare_incoming_message(value, &state)?;
        for ready_batch in prepared.ready_batches {
            ready_batch_sender
                .send(ready_batch)
                .await
                .map_err(|_| bridge_state_error())?;
        }
        for message in prepared.messages {
            let message = serde_json::to_vec(&message).map_err(io::Error::other)?;
            writer.write_all(&message).await?;
            writer.write_all(b"\n").await?;
        }
        line.clear();
    }
    writer.shutdown().await
}

async fn normalize_outgoing_messages<R, W>(
    reader: R,
    mut writer: W,
    state: Arc<Mutex<ProtocolBridgeState>>,
    mut ready_batch_receiver: mpsc::Receiver<Value>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(BoundedLineReader::new(reader, MAX_FRAME_BYTES));
    let mut line = Vec::new();
    let mut server_output_closed = false;
    let mut ready_batches_closed = false;
    loop {
        if server_output_closed {
            if ready_batches_closed {
                break;
            }
            match ready_batch_receiver.recv().await {
                Some(ready_batch) => write_json_line(&mut writer, &ready_batch).await?,
                None => ready_batches_closed = true,
            }
            continue;
        }
        tokio::select! {
            ready_batch = ready_batch_receiver.recv(), if !ready_batches_closed => {
                match ready_batch {
                    Some(ready_batch) => write_json_line(&mut writer, &ready_batch).await?,
                    None => ready_batches_closed = true,
                }
            }
            count = reader.read_until(b'\n', &mut line) => {
                if count? == 0 {
                    server_output_closed = true;
                    continue;
                }
                let framed = line.strip_suffix(b"\n").unwrap_or(&line);
                let framed = framed.strip_suffix(b"\r").unwrap_or(framed);
                let message = serde_json::from_slice::<Value>(framed)
                    .map_err(|_| invalid_frame("runtime emitted an invalid MCP frame"))?;
                if let Some(outgoing) = collect_batch_response(message, &state) {
                    write_json_line(&mut writer, &outgoing).await?;
                }
                line.clear();
            }
        }
    }
    writer.shutdown().await
}

async fn write_json_line<W: AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> io::Result<()> {
    let value = serde_json::to_vec(value).map_err(io::Error::other)?;
    writer.write_all(&value).await?;
    writer.write_all(b"\n").await
}

struct ProtocolBridgeState {
    negotiated_version: Option<String>,
    next_batch_id: u64,
    next_internal_request_id: Arc<AtomicU64>,
    request_batches: HashMap<String, TrackedBatchRequest>,
    external_batch_requests: HashMap<String, String>,
    pending_batches: HashMap<u64, PendingBatch>,
    batch_cancellations: Arc<Mutex<HashMap<String, CancellationToken>>>,
}

impl Default for ProtocolBridgeState {
    fn default() -> Self {
        Self::new(
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(AtomicU64::new(0)),
        )
    }
}

impl ProtocolBridgeState {
    fn new(
        batch_cancellations: Arc<Mutex<HashMap<String, CancellationToken>>>,
        next_internal_request_id: Arc<AtomicU64>,
    ) -> Self {
        Self {
            negotiated_version: None,
            next_batch_id: 0,
            next_internal_request_id,
            request_batches: HashMap::new(),
            external_batch_requests: HashMap::new(),
            pending_batches: HashMap::new(),
            batch_cancellations,
        }
    }
}

struct TrackedBatchRequest {
    batch_id: u64,
    external_id: Value,
    external_key: String,
    cancellation: CancellationToken,
}

struct PendingBatch {
    remaining: usize,
    responses: Vec<Value>,
}

struct PreparedIncoming {
    messages: Vec<Value>,
    ready_batches: Vec<Value>,
}

fn prepare_incoming_message(
    mut message: Value,
    state: &Arc<Mutex<ProtocolBridgeState>>,
) -> io::Result<PreparedIncoming> {
    if let Value::Array(mut items) = message {
        let mut state = state.lock().map_err(|_| bridge_state_error())?;
        if state.negotiated_version.as_deref() != Some("2025-03-26") {
            return Err(invalid_frame(
                "JSON-RPC batches are not enabled for this session",
            ));
        }
        if items.is_empty() || items.len() > MAX_BATCH_ITEMS {
            return Err(invalid_frame("JSON-RPC batch size is invalid"));
        }
        for item in &items {
            validate_batch_item(item)?;
        }
        if items.iter().any(|item| {
            item.get("method").and_then(Value::as_str).is_some()
                && item.get("id").is_some_and(has_reserved_request_id)
        }) {
            return Err(invalid_frame("JSON-RPC request ID uses a reserved prefix"));
        }
        let request_ids = items
            .iter()
            .filter(|item| item.get("method").and_then(Value::as_str).is_some())
            .filter_map(|item| item.get("id"))
            .map(request_id_key)
            .collect::<io::Result<Vec<_>>>()?;
        let unique_count = request_ids.iter().collect::<HashSet<_>>().len();
        if unique_count != request_ids.len()
            || request_ids
                .iter()
                .any(|id| state.external_batch_requests.contains_key(id))
            || state.pending_batches.len() >= MAX_PENDING_BATCHES
            || state
                .request_batches
                .len()
                .saturating_add(request_ids.len())
                > MAX_PENDING_BATCH_REQUESTS
        {
            return Err(invalid_frame("JSON-RPC batch request IDs are invalid"));
        }
        if !request_ids.is_empty() {
            let batch_id = state.next_batch_id;
            state.next_batch_id = state.next_batch_id.wrapping_add(1);
            let cancellation_registry = state.batch_cancellations.clone();
            let mut cancellations = cancellation_registry
                .lock()
                .map_err(|_| bridge_state_error())?;
            for item in &mut items {
                if item.get("method").and_then(Value::as_str).is_none() {
                    continue;
                }
                let Some(external_id) = item.get("id").cloned() else {
                    continue;
                };
                let external_key = request_id_key(&external_id)?;
                let internal_sequence = state
                    .next_internal_request_id
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        current.checked_add(1)
                    })
                    .map_err(|_| invalid_frame("internal request ID space is exhausted"))?;
                let internal_id = format!("{INTERNAL_BATCH_ID_PREFIX}{internal_sequence}");
                let internal_value = Value::String(internal_id.clone());
                let internal_key = request_id_key(&internal_value)?;
                *item
                    .get_mut("id")
                    .ok_or_else(|| invalid_frame("JSON-RPC batch request ID is missing"))? =
                    internal_value;
                let cancellation = CancellationToken::new();
                cancellations.insert(internal_key.clone(), cancellation.clone());
                state
                    .external_batch_requests
                    .insert(external_key.clone(), internal_key.clone());
                state.request_batches.insert(
                    internal_key,
                    TrackedBatchRequest {
                        batch_id,
                        external_id,
                        external_key,
                        cancellation,
                    },
                );
            }
            drop(cancellations);
            state.pending_batches.insert(
                batch_id,
                PendingBatch {
                    remaining: unique_count,
                    responses: Vec::with_capacity(unique_count),
                },
            );
        }
        let mut messages = Vec::with_capacity(items.len());
        for item in items {
            if !consume_batch_cancellation(&item, &mut state) {
                messages.push(item);
            }
        }
        return Ok(PreparedIncoming {
            messages,
            ready_batches: Vec::new(),
        });
    }

    if message.get("method").and_then(Value::as_str) == Some("initialize") {
        let requested = message
            .pointer("/params/protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_frame("initialize protocolVersion is missing"))?;
        let supported = SUPPORTED_PROTOCOL_VERSIONS.contains(&requested);
        let negotiated = if supported {
            requested
        } else {
            LATEST_PROTOCOL_VERSION
        };
        let mut state = state.lock().map_err(|_| bridge_state_error())?;
        if state.negotiated_version.is_some() {
            return Err(invalid_frame("initialize may only be sent once"));
        }
        state.negotiated_version = Some(negotiated.to_owned());
        drop(state);
        if !supported {
            *message
                .pointer_mut("/params/protocolVersion")
                .ok_or_else(|| invalid_frame("initialize protocolVersion is missing"))? =
                Value::String(UNSUPPORTED_VERSION_SENTINEL.to_owned());
        }
    }
    if message.get("method").and_then(Value::as_str).is_some()
        && message.get("id").is_some_and(has_reserved_request_id)
    {
        return Err(invalid_frame("JSON-RPC request ID uses a reserved prefix"));
    }
    let consumed = {
        let mut state = state.lock().map_err(|_| bridge_state_error())?;
        consume_batch_cancellation(&message, &mut state)
    };
    Ok(PreparedIncoming {
        messages: (!consumed).then_some(message).into_iter().collect(),
        ready_batches: Vec::new(),
    })
}

fn validate_batch_item(item: &Value) -> io::Result<()> {
    let object = item
        .as_object()
        .ok_or_else(|| invalid_frame("JSON-RPC batch item is invalid"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(invalid_frame("JSON-RPC batch item is invalid"));
    }
    match object.get("method") {
        Some(Value::String(method)) => {
            if method == "initialize" {
                return Err(invalid_frame("initialize cannot be batched"));
            }
            if let Some(id) = object.get("id") {
                request_id_key(id)?;
            }
            if object
                .get("params")
                .is_some_and(|params| !params.is_object() && !params.is_array())
            {
                return Err(invalid_frame("JSON-RPC batch params are invalid"));
            }
        }
        Some(_) => return Err(invalid_frame("JSON-RPC batch method is invalid")),
        None => {
            request_id_key(
                object
                    .get("id")
                    .ok_or_else(|| invalid_frame("JSON-RPC batch response ID is missing"))?,
            )?;
            if object.contains_key("result") == object.contains_key("error") {
                return Err(invalid_frame("JSON-RPC batch response is invalid"));
            }
        }
    }
    Ok(())
}

fn consume_batch_cancellation(message: &Value, state: &mut ProtocolBridgeState) -> bool {
    if message.get("method").and_then(Value::as_str) != Some("notifications/cancelled") {
        return false;
    }
    let Some(id) = message.pointer("/params/requestId") else {
        return false;
    };
    if has_reserved_request_id(id) {
        return true;
    }
    let Ok(id) = request_id_key(id) else {
        return false;
    };
    let Some(internal_id) = state.external_batch_requests.get(&id) else {
        return false;
    };
    if let Some(request) = state.request_batches.get(internal_id) {
        request.cancellation.cancel();
    }
    true
}

fn has_reserved_request_id(id: &Value) -> bool {
    id.as_str()
        .is_some_and(|id| id.starts_with(INTERNAL_BATCH_ID_PREFIX))
}

fn collect_batch_response(
    message: Value,
    state: &Arc<Mutex<ProtocolBridgeState>>,
) -> Option<Value> {
    let id = message.get("id").and_then(|id| request_id_key(id).ok());
    let Some(id) = id else {
        return Some(message);
    };
    let mut state = state.lock().ok()?;
    let Some(request) = state.request_batches.remove(&id) else {
        return Some(message);
    };
    state.external_batch_requests.remove(&request.external_key);
    if let Ok(mut cancellations) = state.batch_cancellations.lock() {
        cancellations.remove(&id);
    }
    let response = if request.cancellation.is_cancelled() {
        None
    } else {
        let mut message = message;
        if let Some(id) = message.get_mut("id") {
            *id = request.external_id;
        }
        Some(message)
    };
    complete_batch_item(&mut state, request.batch_id, response)
}

fn complete_batch_item(
    state: &mut ProtocolBridgeState,
    batch_id: u64,
    response: Option<Value>,
) -> Option<Value> {
    let batch = state.pending_batches.get_mut(&batch_id)?;
    if let Some(response) = response {
        batch.responses.push(response);
    }
    batch.remaining = batch.remaining.saturating_sub(1);
    if batch.remaining != 0 {
        return None;
    }
    let batch = state.pending_batches.remove(&batch_id)?;
    (!batch.responses.is_empty()).then_some(Value::Array(batch.responses))
}

fn request_id_key(id: &Value) -> io::Result<String> {
    if !id.is_string() && id.as_i64().is_none() {
        return Err(invalid_frame("JSON-RPC request ID is invalid"));
    }
    serde_json::to_string(id).map_err(io::Error::other)
}

fn invalid_frame(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn bridge_state_error() -> io::Error {
    io::Error::other("MCP protocol bridge state is unavailable")
}

pub fn native_server(
    session: RuntimeSession,
) -> Result<PalladinMcpServer<NativeApplication>, ContractError> {
    PalladinMcpServer::new(NativeApplication::new(session))
}

pub struct BoundedLineReader<R> {
    inner: R,
    current_line_bytes: usize,
    max_line_bytes: usize,
    pending: [u8; 8192],
    pending_start: usize,
    pending_end: usize,
}

impl<R> BoundedLineReader<R> {
    #[must_use]
    pub fn new(inner: R, max_line_bytes: usize) -> Self {
        Self {
            inner,
            current_line_bytes: 0,
            max_line_bytes,
            pending: [0; 8192],
            pending_start: 0,
            pending_end: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BoundedLineReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.pending_start < this.pending_end {
            copy_pending(this, buffer);
            return Poll::Ready(Ok(()));
        }

        let mut scratch = ReadBuf::new(&mut this.pending);
        match Pin::new(&mut this.inner).poll_read(context, &mut scratch) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let count = scratch.filled().len();
                let mut current_line_bytes = this.current_line_bytes;
                for byte in &this.pending[..count] {
                    if *byte == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "MCP frame contains a NUL byte",
                        )));
                    }
                    if *byte == b'\n' {
                        current_line_bytes = 0;
                    } else {
                        current_line_bytes = current_line_bytes.saturating_add(1);
                        if current_line_bytes > this.max_line_bytes {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "MCP frame exceeds the configured limit",
                            )));
                        }
                    }
                }
                this.current_line_bytes = current_line_bytes;
                this.pending_start = 0;
                this.pending_end = count;
                copy_pending(this, buffer);
                Poll::Ready(Ok(()))
            }
        }
    }
}

fn copy_pending<R>(reader: &mut BoundedLineReader<R>, output: &mut ReadBuf<'_>) {
    let count = output
        .remaining()
        .min(reader.pending_end.saturating_sub(reader.pending_start));
    if count > 0 {
        output.put_slice(&reader.pending[reader.pending_start..reader.pending_start + count]);
        reader.pending_start += count;
        if reader.pending_start == reader.pending_end {
            reader.pending_start = 0;
            reader.pending_end = 0;
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContractFile {
    contract: String,
    version: String,
    status: String,
    supported_protocol_versions: Vec<String>,
    compatibility: ContractCompatibility,
    server: ContractServer,
    tools: Vec<ContractTool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContractCompatibility {
    content_type: String,
    tool_result_json: String,
    mcp_wait_default: String,
    field_selector_precedence: String,
    stdout: String,
    operator_output: String,
}

#[derive(Debug, Deserialize)]
struct ContractServer {
    name: String,
    title: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContractTool {
    name: String,
    description: String,
    required_method: Option<String>,
    input_schema: Map<String, Value>,
}

fn load_tools() -> Result<Vec<Tool>, ContractError> {
    let contract: ContractFile =
        serde_json::from_str(CONTRACT_JSON).map_err(|_| ContractError::Invalid)?;
    if contract.contract != "palladin-agent-mcp-tools"
        || contract.version != "1.0.0"
        || contract.status != "frozen"
        || contract.server.name != "Palladin Agents"
        || contract.server.title != "Palladin Agent Runtime"
        || contract
            .supported_protocol_versions
            .iter()
            .map(String::as_str)
            .ne(SUPPORTED_PROTOCOL_VERSIONS)
        || contract.compatibility.content_type != "text"
        || contract.compatibility.tool_result_json != "pretty"
        || contract.compatibility.mcp_wait_default != "one-shot"
        || contract.compatibility.field_selector_precedence != "fieldId"
        || contract.compatibility.stdout != "json-rpc-only"
        || contract.compatibility.operator_output != "stderr"
    {
        return Err(ContractError::Invalid);
    }
    let expected = [
        ("search_entries", None),
        ("get_credential", Some("Get")),
        ("exec_with_credential", Some("Exec")),
        ("inject_credential", Some("Inject")),
        ("report_credential_stale", None),
    ];
    if contract.tools.len() != expected.len()
        || !contract.tools.iter().zip(expected).all(|(tool, expected)| {
            tool.name == expected.0 && tool.required_method.as_deref() == expected.1
        })
    {
        return Err(ContractError::Invalid);
    }
    Ok(contract
        .tools
        .into_iter()
        .map(|tool| Tool::new(tool.name, tool.description, tool.input_schema))
        .collect())
}

fn parse_input<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, McpError> {
    serde_json::from_value(value)
        .map_err(|_| McpError::invalid_params("Tool arguments are invalid", None))
}

fn valid_required(value: &str, max: usize) -> bool {
    let value = value.trim();
    !value.is_empty() && value.chars().count() <= max
}

fn exceeds_chars(value: &str, max: usize) -> bool {
    value.chars().count() > max
}

fn validate_search(input: &SearchInput) -> Result<(), McpError> {
    let query = input.query.trim();
    let query_chars = query.chars().count();
    if !(2..=512).contains(&query_chars) {
        return Err(McpError::invalid_params(
            "Search query must contain between 2 and 512 bytes",
            None,
        ));
    }
    if input
        .cursor
        .as_ref()
        .is_some_and(|value| exceeds_chars(value, 4096))
        || input
            .page_size
            .is_some_and(|value| !(1..=100).contains(&value))
    {
        return Err(McpError::invalid_params(
            "Search arguments are invalid",
            None,
        ));
    }
    Ok(())
}

fn validate_get(input: &GetInput) -> Result<(), McpError> {
    if !valid_required(&input.vault_id, 256)
        || !valid_required(&input.entry_id, 256)
        || input
            .reason
            .as_ref()
            .is_some_and(|value| exceeds_chars(value, 4096))
        || input
            .field
            .as_ref()
            .is_some_and(|value| exceeds_chars(value, 2048))
        || input
            .field_id
            .as_ref()
            .is_some_and(|value| exceeds_chars(value, 256))
    {
        return Err(McpError::invalid_params(
            "Credential arguments are invalid",
            None,
        ));
    }
    input
        .wait_options()
        .map(|_| ())
        .map_err(|message| McpError::invalid_params(message, None))
}

fn validate_exec(input: &ExecInput) -> Result<(), McpError> {
    if !valid_required(&input.vault_id, 256)
        || !valid_required(&input.entry_id, 256)
        || input
            .reason
            .as_ref()
            .is_some_and(|value| exceeds_chars(value, 4096))
    {
        return Err(McpError::invalid_params("Exec arguments are invalid", None));
    }
    if let Some(command) = &input.command {
        let total = command.iter().map(String::len).sum::<usize>();
        if command.len() > 128
            || total > 65_536
            || command.iter().any(|arg| exceeds_chars(arg, 8192))
        {
            return Err(McpError::invalid_params("Command is too large", None));
        }
    }
    input
        .wait_options()
        .map(|_| ())
        .map_err(|message| McpError::invalid_params(message, None))
}

fn validate_inject(input: &InjectInput) -> Result<(), McpError> {
    if !valid_required(&input.vault_id, 256)
        || !valid_required(&input.entry_id, 256)
        || !valid_required(&input.cdp, 4096)
        || input
            .reason
            .as_ref()
            .is_some_and(|value| exceeds_chars(value, 4096))
        || input
            .page_url
            .as_ref()
            .is_some_and(|value| exceeds_chars(value, 4096))
        || [
            input.username_selector.as_ref(),
            input.password_selector.as_ref(),
            input.submit_selector.as_ref(),
            input.field.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| exceeds_chars(value, 2048))
        || input
            .field_id
            .as_ref()
            .is_some_and(|value| exceeds_chars(value, 256))
    {
        return Err(McpError::invalid_params(
            "Inject arguments are invalid",
            None,
        ));
    }
    if input.fill_only.unwrap_or(false)
        && input.username_selector.is_none()
        && input.password_selector.is_none()
    {
        return Err(McpError::invalid_params(
            "fillOnly requires usernameSelector or passwordSelector",
            None,
        ));
    }
    input
        .wait_options()
        .map(|_| ())
        .map_err(|message| McpError::invalid_params(message, None))
}

fn validate_report(input: &ReportStaleInput) -> Result<(), McpError> {
    if !valid_required(&input.vault_id, 256)
        || !valid_required(&input.entry_id, 256)
        || input
            .note
            .as_ref()
            .is_some_and(|value| exceeds_chars(value, 4096))
    {
        return Err(McpError::invalid_params(
            "Report arguments are invalid",
            None,
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SearchInput {
    pub query: String,
    pub cursor: Option<String>,
    pub page_size: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetInput {
    pub vault_id: String,
    pub entry_id: String,
    pub reason: Option<String>,
    pub field: Option<String>,
    pub field_id: Option<String>,
    pub wait: Option<String>,
    pub no_wait: Option<bool>,
    pub poll_interval: Option<String>,
    pub progress: Option<ProgressInput>,
}

impl GetInput {
    fn wait_options(&self) -> Result<WaitOptions, &'static str> {
        wait_options(
            self.wait.as_deref(),
            self.no_wait,
            self.poll_interval.as_deref(),
            self.progress,
        )
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecInput {
    pub vault_id: String,
    pub entry_id: String,
    pub command: Option<Vec<String>>,
    pub reason: Option<String>,
    pub wait: Option<String>,
    pub no_wait: Option<bool>,
    pub poll_interval: Option<String>,
    pub progress: Option<ProgressInput>,
}

impl ExecInput {
    fn wait_options(&self) -> Result<WaitOptions, &'static str> {
        wait_options(
            self.wait.as_deref(),
            self.no_wait,
            self.poll_interval.as_deref(),
            self.progress,
        )
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InjectInput {
    pub vault_id: String,
    pub entry_id: String,
    pub cdp: String,
    pub reason: Option<String>,
    pub page_url: Option<String>,
    pub username_selector: Option<String>,
    pub password_selector: Option<String>,
    pub submit_selector: Option<String>,
    pub field: Option<String>,
    pub field_id: Option<String>,
    pub fill_only: Option<bool>,
    pub no_submit: Option<bool>,
    pub wait: Option<String>,
    pub no_wait: Option<bool>,
    pub poll_interval: Option<String>,
    pub progress: Option<ProgressInput>,
}

impl InjectInput {
    fn wait_options(&self) -> Result<WaitOptions, &'static str> {
        wait_options(
            self.wait.as_deref(),
            self.no_wait,
            self.poll_interval.as_deref(),
            self.progress,
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleCodeInput {
    LoginRejected,
    AuthFailed,
    #[default]
    Manual,
}

impl From<StaleCodeInput> for StaleReasonCode {
    fn from(value: StaleCodeInput) -> Self {
        match value {
            StaleCodeInput::LoginRejected => Self::LoginRejected,
            StaleCodeInput::AuthFailed => Self::AuthFailed,
            StaleCodeInput::Manual => Self::Manual,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReportStaleInput {
    pub vault_id: String,
    pub entry_id: String,
    pub code: Option<StaleCodeInput>,
    pub note: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProgressInput {
    Plain,
    Json,
    None,
}

impl From<ProgressInput> for ProgressMode {
    fn from(value: ProgressInput) -> Self {
        match value {
            ProgressInput::Plain => Self::Plain,
            ProgressInput::Json => Self::Json,
            ProgressInput::None => Self::None,
        }
    }
}

fn wait_options(
    wait: Option<&str>,
    no_wait: Option<bool>,
    poll_interval: Option<&str>,
    progress: Option<ProgressInput>,
) -> Result<WaitOptions, &'static str> {
    if (!no_wait.unwrap_or(false) && wait.is_some_and(|value| value.chars().count() > 32))
        || poll_interval.is_some_and(|value| value.chars().count() > 32)
    {
        return Err("wait duration is too long");
    }
    let wait_ms = if no_wait.unwrap_or(false) {
        Some(0)
    } else if let Some(wait) = wait {
        let wait_ms = parse_duration(wait).map_err(|_| "wait duration is invalid")?;
        if wait_ms > MAX_MCP_WAIT_MS {
            return Err("wait duration exceeds the five-minute limit");
        }
        Some(wait_ms)
    } else {
        Some(0)
    };
    let poll_ms = poll_interval
        .map(parse_duration)
        .transpose()
        .map_err(|_| "pollInterval duration is invalid")?;
    Ok(WaitOptions {
        wait_ms,
        poll_ms,
        progress: progress.map(Into::into),
    })
}

pub struct ToolOutcome {
    text: String,
    is_error: bool,
}

impl ToolOutcome {
    #[must_use]
    pub fn success(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
        }
    }

    #[must_use]
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }

    fn into_mcp(self) -> CallToolResult {
        let mut result = CallToolResult::default();
        result.content = vec![ContentBlock::text(self.text)];
        result.is_error = self.is_error.then_some(true);
        result
    }
}

fn pretty_result(value: &impl Serialize) -> ToolOutcome {
    match serde_json::to_string_pretty(value) {
        Ok(value) => ToolOutcome::success(value),
        Err(_) => ToolOutcome::error("Palladin could not serialize the tool result."),
    }
}

fn runtime_failure(error: &RuntimeError) -> ToolOutcome {
    let message = match error {
        RuntimeError::WaitCancelled => "Credential request was cancelled.",
        RuntimeError::Api(ApiError::ReasonRequired) => {
            "A reason is required to request this credential."
        }
        RuntimeError::Api(ApiError::Transport) => "Palladin API is unreachable.",
        RuntimeError::Api(ApiError::Http(429)) => "Palladin API rate limit was reached.",
        _ => "Palladin could not complete the request.",
    };
    ToolOutcome::error(message)
}

fn exec_failure(error: &RuntimeError) -> ToolOutcome {
    let message = match error {
        RuntimeError::WaitCancelled => "Credential execution was cancelled.",
        RuntimeError::MissingExecCommand => "No command was provided for this non-Script entry.",
        RuntimeError::CommandProvidedForScript => {
            "This is a Script entry - omit command to run its stored script."
        }
        RuntimeError::EnvironmentMappingForScript => {
            "Script entries define their own credential references."
        }
        RuntimeError::InvalidCredentialPayload => "The credential payload is invalid.",
        RuntimeError::InvalidEnvironmentMapping
        | RuntimeError::InvalidEnvironmentField
        | RuntimeError::Environment(_) => "The credential execution environment is invalid.",
        RuntimeError::ScriptReferenceNotGranted => {
            "A Script entry reference was not granted. Nothing was executed."
        }
        RuntimeError::Exec(palladin_runtime::ExecError::UnsupportedInterpreter) => {
            "The Script entry uses an unsupported interpreter."
        }
        RuntimeError::Exec(palladin_runtime::ExecError::InterpreterUnavailable) => {
            "The Script entry interpreter is not installed in a trusted PATH directory. Nothing was executed."
        }
        RuntimeError::Exec(palladin_runtime::ExecError::ImplicitShellForbidden) => {
            "Windows command scripts require an explicit shell executable."
        }
        RuntimeError::Exec(palladin_runtime::ExecError::MissingCommand)
        | RuntimeError::Exec(palladin_runtime::ExecError::InvalidArgument) => {
            "The command is invalid."
        }
        RuntimeError::Exec(_) => "The command could not be executed safely.",
        _ => return runtime_failure(error),
    };
    ToolOutcome::error(message)
}

fn access_name(access: &CredentialAccess) -> &'static str {
    match access {
        CredentialAccess::Granted { .. } => "granted",
        CredentialAccess::Pending { .. } => "pending",
        CredentialAccess::Denied => "denied",
        CredentialAccess::Revoked => "revoked",
        CredentialAccess::Expired => "expired",
        CredentialAccess::Consumed => "consumed",
        CredentialAccess::MethodNotAllowed => "method-not-allowed",
        CredentialAccess::ScriptExecOnly => "script-exec-only",
        CredentialAccess::Unavailable => "unavailable",
        CredentialAccess::Blocked => "blocked",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessResult<'a> {
    access: &'static str,
    message: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FullCredentialResult<'a> {
    access: &'static str,
    entry_id: &'a str,
    label: &'a str,
    secret: &'a str,
    warning: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldValueResult<'a> {
    access: &'static str,
    entry_id: &'a str,
    label: &'a str,
    field: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TotpResult<'a> {
    access: &'static str,
    entry_id: &'a str,
    label: &'a str,
    field: &'a str,
    code: &'a str,
    expires_in: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecToolResult<'a> {
    exit_code: i32,
    output: &'static str,
    note: &'a str,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ContractError {
    #[error("frozen MCP tool contract is invalid")]
    Invalid,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum McpServeError {
    #[error("MCP initialization failed")]
    Initialization,
    #[error("MCP stdio transport failed")]
    Transport,
}

#[cfg(test)]
mod tests;
