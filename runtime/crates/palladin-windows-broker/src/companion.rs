use std::io::{self, BufRead, IsTerminal, Read};
use std::time::Duration;

use palladin_platform::broker_protocol::{
    BrokerFrame, ClientFrame, ConsentChallenge, ExecuteRequest, MAX_MCP_MESSAGE_BYTES,
    MAX_STREAM_CHUNK_BYTES, McpConsentResponse, McpMessage, OutputStream, ProtocolError,
    SecureOperation, consent_payload, operation_and_profile, read_frame, request_hash, write_frame,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::mpsc;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType;
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::{Array, HSTRING};
use zeroize::{Zeroize, Zeroizing};

use crate::{PIPE_NAME, WindowsBrokerError, authenticate_connected_server};

const HELLO_KEY_NAME: &str = "Palladin Runtime Consent v1";
const PIPE_CONNECT_ATTEMPTS: usize = 60;
const PIPE_CONNECT_DELAY: Duration = Duration::from_millis(50);
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CHALLENGE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(70);

#[derive(Debug, Error)]
pub enum CompanionError {
    #[error("secure command is not supported")]
    UnsupportedCommand,
    #[error("standard input is too large")]
    InputTooLarge,
    #[error("Palladin Windows service is unavailable")]
    ServiceUnavailable,
    #[error("Palladin Windows service authentication failed")]
    ServiceAuthentication,
    #[error("Windows Hello is unavailable or consent was not granted")]
    HelloUnavailable,
    #[error("Palladin Windows service returned an invalid response")]
    InvalidResponse,
    #[error("Palladin Windows companion transport failed")]
    Transport,
    #[error("Palladin Runtime authentication is required; restart the command")]
    AuthenticationRequired,
    #[error("Windows Hello consent was rejected; retry the command")]
    ConsentInvalid,
    #[error("Windows Hello consent expired; retry the command")]
    ConsentExpired,
    #[error("Windows Hello consent was already used; retry the command")]
    ReplayDetected,
    #[error("Palladin secure session reached its 30-minute limit; restart the command")]
    SessionExpired,
    #[error("this command is forbidden by the secure Windows runtime")]
    OperationForbidden,
    #[error("Palladin Runtime rejected an invalid request; update or repair the installation")]
    InvalidRequest,
    #[error("Palladin Windows worker is unavailable; repair the installation")]
    WorkerUnavailable,
    #[error("could not read the organization API key from the masked prompt")]
    ApiKeyPrompt,
    #[error("--api-key-stdin requires redirected standard input")]
    ApiKeyStdinRequiresRedirect,
    #[error("redirected API key input requires connect --api-key-stdin")]
    RedirectedApiKeyRequiresFlag,
}

impl From<ProtocolError> for CompanionError {
    fn from(_: ProtocolError) -> Self {
        Self::Transport
    }
}

impl From<WindowsBrokerError> for CompanionError {
    fn from(_: WindowsBrokerError) -> Self {
        Self::ServiceAuthentication
    }
}

pub fn run_companion() -> Result<i32, CompanionError> {
    let _apartment = WinRtApartment::initialize()?;
    let mut arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let (operation, agent_id) =
        operation_and_profile(&arguments).map_err(|_| CompanionError::UnsupportedCommand)?;
    let standard_input = prepare_standard_input(operation, &mut arguments)?;
    let request_hash = request_hash(operation, &arguments, &standard_input)
        .map_err(|_| CompanionError::UnsupportedCommand)?;
    let mut request_id = [0_u8; 16];
    getrandom::fill(&mut request_id).map_err(|_| CompanionError::Transport)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CompanionError::Transport)?;
    runtime.block_on(execute(
        request_id,
        operation,
        agent_id,
        arguments,
        standard_input,
        request_hash,
    ))
}

async fn execute(
    request_id: [u8; 16],
    operation: SecureOperation,
    agent_id: String,
    arguments: Vec<String>,
    mut standard_input: Zeroizing<Vec<u8>>,
    expected_request_hash: [u8; 32],
) -> Result<i32, CompanionError> {
    let mut pipe = connect_to_authenticated_service().await?;
    let credential = windows_hello_credential()?;
    let public_key_spki_der = hello_public_key(&credential)?;
    write_client_frame(
        &mut pipe,
        &ClientFrame::RequestChallenge {
            request_id,
            operation,
            agent_id: agent_id.clone(),
            request_hash: expected_request_hash,
            public_key_spki_der,
        },
    )
    .await?;

    let challenge: BrokerFrame =
        tokio::time::timeout(CHALLENGE_RESPONSE_TIMEOUT, read_frame(&mut pipe))
            .await
            .map_err(|_| CompanionError::Transport)??;
    let (nonce, issued_at_unix_ms, expires_at_unix_ms) = match &challenge {
        BrokerFrame::Challenge {
            request_id: challenge_request_id,
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            agent_id: challenge_agent_id,
            operation: challenge_operation,
            request_hash: challenge_request_hash,
        } if *challenge_request_id == request_id
            && challenge_agent_id == &agent_id
            && *challenge_operation == operation
            && *challenge_request_hash == expected_request_hash =>
        {
            (*nonce, *issued_at_unix_ms, *expires_at_unix_ms)
        }
        BrokerFrame::Rejected {
            request_id: response_id,
            code,
        } if response_matches_request(*response_id, request_id) => {
            return Err(rejection_error(*code));
        }
        _ => return Err(CompanionError::InvalidResponse),
    };

    let mut consent = ConsentChallenge {
        nonce,
        issued_at_unix_ms,
        expires_at_unix_ms,
        agent_id: agent_id.clone(),
        operation,
        request_hash: expected_request_hash,
        signature: Vec::new(),
    };
    let mut payload = consent_payload(&consent).map_err(|_| CompanionError::InvalidResponse)?;
    verify_user_context(operation, &agent_id)?;
    consent.signature = hello_sign(&credential, &payload)?;
    payload.zeroize();
    let request = ExecuteRequest {
        request_id,
        operation,
        arguments,
        standard_input: std::mem::take(&mut *standard_input),
        consent,
    };
    write_client_frame(&mut pipe, &ClientFrame::Execute(request)).await?;

    if operation == SecureOperation::McpServe {
        return execute_duplex(pipe, request_id, credential, agent_id).await;
    }

    execute_one_shot(pipe, request_id).await
}

async fn execute_one_shot(
    pipe: NamedPipeClient,
    request_id: [u8; 16],
) -> Result<i32, CompanionError> {
    let (reader, mut writer) = tokio::io::split(pipe);
    let (mut frames, _reader_task) = broker_frame_reader(reader);
    let mut accepted = false;
    let mut next_output_sequence = 0_u64;
    let mut cancel_sent = false;

    loop {
        tokio::select! {
            frame = frames.recv() => {
                let frame = frame.ok_or(CompanionError::Transport)??;
                match &frame {
                    BrokerFrame::Accepted { request_id: response_id }
                        if *response_id == request_id && !accepted => accepted = true,
                    BrokerFrame::Output {
                        request_id: response_id,
                        sequence,
                        stream,
                        bytes,
                    } if *response_id == request_id
                        && accepted
                        && *sequence == next_output_sequence => {
                            next_output_sequence = next_output_sequence
                                .checked_add(1)
                                .ok_or(CompanionError::InvalidResponse)?;
                            relay_output(*stream, bytes).await?;
                        }
                    BrokerFrame::Exited { request_id: response_id, exit_code }
                        if *response_id == request_id && accepted => return Ok(*exit_code),
                    BrokerFrame::Rejected { request_id: response_id, code }
                        if response_matches_request(*response_id, request_id) => {
                            return Err(rejection_error(*code));
                        }
                    _ => return Err(CompanionError::InvalidResponse),
                }
            }
            result = tokio::signal::ctrl_c(), if !cancel_sent => {
                result.map_err(|_| CompanionError::Transport)?;
                write_client_frame(&mut writer, &ClientFrame::Cancel { request_id }).await?;
                cancel_sent = true;
            }
        }
    }
}

async fn execute_duplex(
    pipe: NamedPipeClient,
    request_id: [u8; 16],
    credential: KeyCredential,
    agent_id: String,
) -> Result<i32, CompanionError> {
    let (reader, mut writer) = tokio::io::split(pipe);
    let (mut frames, _reader_task) = broker_frame_reader(reader);
    let mut accepted = false;
    let mut input_closed = false;
    let mut input_eof = false;
    let mut message_in_flight = false;
    let mut cancel_sent = false;
    let mut input_sequence = 0_u64;
    let mut next_output_sequence = 0_u64;
    let mut consent_sequence = 0_u64;
    let mut latest_consent_request_id = None;
    let mut input = tokio::io::stdin();
    let mut buffer = Zeroizing::new([0_u8; MAX_STREAM_CHUNK_BYTES]);
    let mut pending = Zeroizing::new(Vec::new());

    loop {
        if accepted && !message_in_flight && !input_closed && !cancel_sent {
            if let Some(mut bytes) = take_next_mcp_message(&mut pending, input_eof)? {
                write_client_frame(
                    &mut writer,
                    &ClientFrame::McpMessage(McpMessage {
                        request_id,
                        sequence: input_sequence,
                        bytes: std::mem::take(&mut *bytes),
                    }),
                )
                .await?;
                message_in_flight = true;
                continue;
            }
            if input_eof {
                write_client_frame(
                    &mut writer,
                    &ClientFrame::InputClosed {
                        request_id,
                        sequence: input_sequence,
                    },
                )
                .await?;
                input_closed = true;
                continue;
            }
        }
        tokio::select! {
            frame = frames.recv() => {
                let frame = frame.ok_or(CompanionError::Transport)??;
                match &frame {
                    BrokerFrame::Accepted { request_id: response_id }
                        if *response_id == request_id && !accepted => accepted = true,
                    BrokerFrame::Output {
                        request_id: response_id,
                        sequence,
                        stream,
                        bytes,
                    } if *response_id == request_id
                        && accepted
                        && *sequence == next_output_sequence => {
                            next_output_sequence = next_output_sequence
                                .checked_add(1)
                                .ok_or(CompanionError::InvalidResponse)?;
                            relay_output(*stream, bytes).await?;
                        }
                    BrokerFrame::Challenge {
                        request_id: consent_request_id,
                        nonce,
                        issued_at_unix_ms,
                        expires_at_unix_ms,
                        agent_id: challenge_agent_id,
                        operation,
                        request_hash,
                    } if accepted
                        && message_in_flight
                        && challenge_agent_id == &agent_id
                        && matches!(
                            operation,
                            SecureOperation::McpSearchEntries
                                | SecureOperation::McpGetCredential
                                | SecureOperation::McpExecWithCredential
                                | SecureOperation::McpReportCredentialStale
                        ) => {
                            let mut consent = ConsentChallenge {
                                nonce: *nonce,
                                issued_at_unix_ms: *issued_at_unix_ms,
                                expires_at_unix_ms: *expires_at_unix_ms,
                                agent_id: challenge_agent_id.clone(),
                                operation: *operation,
                                request_hash: *request_hash,
                                signature: Vec::new(),
                            };
                            let mut payload = consent_payload(&consent)
                                .map_err(|_| CompanionError::InvalidResponse)?;
                            verify_user_context(*operation, challenge_agent_id)?;
                            consent.signature = hello_sign(&credential, &payload)?;
                            payload.zeroize();
                            write_client_frame(
                                &mut writer,
                                &ClientFrame::AuthorizeMcp(McpConsentResponse {
                                    session_request_id: request_id,
                                    consent_request_id: *consent_request_id,
                                    sequence: consent_sequence,
                                    consent,
                                }),
                            )
                            .await?;
                            latest_consent_request_id = Some(*consent_request_id);
                            consent_sequence = consent_sequence
                                .checked_add(1)
                                .ok_or(CompanionError::InvalidResponse)?;
                        }
                    BrokerFrame::McpMessageAccepted {
                        request_id: response_id,
                        sequence,
                    } if *response_id == request_id
                        && message_in_flight
                        && *sequence == input_sequence => {
                            input_sequence = input_sequence
                                .checked_add(1)
                                .ok_or(CompanionError::InvalidResponse)?;
                            message_in_flight = false;
                        }
                    BrokerFrame::Exited { request_id: response_id, exit_code }
                        if *response_id == request_id && accepted => return Ok(*exit_code),
                    BrokerFrame::Rejected { request_id: response_id, code }
                        if response_matches_request(*response_id, request_id)
                            || *response_id == latest_consent_request_id => {
                            return Err(rejection_error(*code));
                        }
                    _ => return Err(CompanionError::InvalidResponse),
                }
            }
            read = input.read(&mut buffer[..]), if accepted
                && !input_closed
                && !input_eof
                && !message_in_flight
                && !cancel_sent => {
                let read = read.map_err(|_| CompanionError::Transport)?;
                if read == 0 {
                    input_eof = true;
                } else {
                    pending.extend_from_slice(&buffer[..read]);
                    buffer[..read].zeroize();
                    validate_pending_mcp_message(&pending)?;
                }
            }
            result = tokio::signal::ctrl_c(), if !cancel_sent => {
                result.map_err(|_| CompanionError::Transport)?;
                write_client_frame(&mut writer, &ClientFrame::Cancel { request_id }).await?;
                cancel_sent = true;
            }
        }
    }
}

fn take_next_mcp_message(
    pending: &mut Vec<u8>,
    input_eof: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, CompanionError> {
    if let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
        if newline == 0 || newline > MAX_MCP_MESSAGE_BYTES {
            return Err(CompanionError::InputTooLarge);
        }
        let mut bytes = Zeroizing::new(pending.drain(..=newline).collect::<Vec<_>>());
        if bytes.pop() != Some(b'\n') {
            return Err(CompanionError::InvalidResponse);
        }
        return Ok(Some(bytes));
    }
    validate_pending_mcp_message(pending)?;
    if input_eof && !pending.is_empty() {
        return Ok(Some(Zeroizing::new(std::mem::take(pending))));
    }
    Ok(None)
}

fn validate_pending_mcp_message(pending: &[u8]) -> Result<(), CompanionError> {
    match pending.iter().position(|byte| *byte == b'\n') {
        Some(newline) if newline > MAX_MCP_MESSAGE_BYTES => Err(CompanionError::InputTooLarge),
        None if pending.len() > MAX_MCP_MESSAGE_BYTES => Err(CompanionError::InputTooLarge),
        _ => Ok(()),
    }
}

fn broker_frame_reader<R>(
    mut reader: R,
) -> (
    mpsc::Receiver<Result<BrokerFrame, ProtocolError>>,
    AbortTask<()>,
)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        loop {
            let frame = read_frame::<_, BrokerFrame>(&mut reader).await;
            let terminal = frame.is_err();
            if sender.send(frame).await.is_err() || terminal {
                return;
            }
        }
    });
    (receiver, AbortTask(task))
}

struct AbortTask<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn relay_output(stream: OutputStream, bytes: &[u8]) -> Result<(), CompanionError> {
    tokio::time::timeout(CLIENT_WRITE_TIMEOUT, async {
        match stream {
            OutputStream::StandardOutput => {
                let mut output = tokio::io::stdout();
                output
                    .write_all(bytes)
                    .await
                    .map_err(|_| CompanionError::Transport)?;
                output.flush().await.map_err(|_| CompanionError::Transport)
            }
            OutputStream::StandardError => {
                let mut output = tokio::io::stderr();
                output
                    .write_all(bytes)
                    .await
                    .map_err(|_| CompanionError::Transport)?;
                output.flush().await.map_err(|_| CompanionError::Transport)
            }
        }
    })
    .await
    .map_err(|_| CompanionError::Transport)?
}

async fn write_client_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &ClientFrame,
) -> Result<(), ProtocolError> {
    tokio::time::timeout(CLIENT_WRITE_TIMEOUT, write_frame(writer, frame))
        .await
        .map_err(|_| {
            ProtocolError::Transport(io::Error::new(
                io::ErrorKind::TimedOut,
                "companion IPC write timed out",
            ))
        })?
}

fn response_matches_request(response_id: Option<[u8; 16]>, request_id: [u8; 16]) -> bool {
    response_id.is_none_or(|response_id| response_id == request_id)
}

fn rejection_error(code: palladin_platform::broker_protocol::RejectionCode) -> CompanionError {
    use palladin_platform::broker_protocol::RejectionCode;
    match code {
        RejectionCode::AuthenticationRequired => CompanionError::AuthenticationRequired,
        RejectionCode::ConsentInvalid => CompanionError::ConsentInvalid,
        RejectionCode::ConsentExpired => CompanionError::ConsentExpired,
        RejectionCode::ReplayDetected => CompanionError::ReplayDetected,
        RejectionCode::SessionExpired => CompanionError::SessionExpired,
        RejectionCode::OperationForbidden => CompanionError::OperationForbidden,
        RejectionCode::InvalidRequest => CompanionError::InvalidRequest,
        RejectionCode::WorkerUnavailable => CompanionError::WorkerUnavailable,
    }
}

async fn connect_to_authenticated_service() -> Result<NamedPipeClient, CompanionError> {
    for attempt in 0..PIPE_CONNECT_ATTEMPTS {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(pipe) => {
                authenticate_connected_server(&pipe)?;
                return Ok(pipe);
            }
            Err(_) if attempt + 1 < PIPE_CONNECT_ATTEMPTS => {
                tokio::time::sleep(PIPE_CONNECT_DELAY).await;
            }
            Err(_) => break,
        }
    }
    Err(CompanionError::ServiceUnavailable)
}

fn prepare_standard_input(
    operation: SecureOperation,
    arguments: &mut Vec<String>,
) -> Result<Zeroizing<Vec<u8>>, CompanionError> {
    let uses_api_key_stdin = arguments
        .iter()
        .any(|argument| argument == "--api-key-stdin");
    if uses_api_key_stdin && operation != SecureOperation::Connect {
        return Err(CompanionError::OperationForbidden);
    }
    match standard_input_plan(
        operation,
        uses_api_key_stdin,
        std::io::stdin().is_terminal(),
    ) {
        StandardInputPlan::Prompt => {
            let mut secret = Zeroizing::new(
                rpassword::prompt_password("Organization API key: ")
                    .map_err(|_| CompanionError::ApiKeyPrompt)?,
            );
            if !secret.starts_with("pl_") || secret.len() > 4096 {
                return Err(CompanionError::ApiKeyPrompt);
            }
            arguments.push("--api-key-stdin".to_owned());
            let bytes = Zeroizing::new(secret.as_bytes().to_vec());
            secret.zeroize();
            Ok(bytes)
        }
        StandardInputPlan::ReadRedirected => read_bounded_standard_input(),
        StandardInputPlan::Duplex => Ok(Zeroizing::new(Vec::new())),
        StandardInputPlan::Empty => Ok(Zeroizing::new(Vec::new())),
        StandardInputPlan::RejectFlagRequiresRedirect => {
            Err(CompanionError::ApiKeyStdinRequiresRedirect)
        }
        StandardInputPlan::RejectRedirectRequiresFlag => {
            Err(CompanionError::RedirectedApiKeyRequiresFlag)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StandardInputPlan {
    Prompt,
    ReadRedirected,
    Duplex,
    Empty,
    RejectFlagRequiresRedirect,
    RejectRedirectRequiresFlag,
}

fn standard_input_plan(
    operation: SecureOperation,
    uses_api_key_stdin: bool,
    terminal: bool,
) -> StandardInputPlan {
    match (operation, uses_api_key_stdin, terminal) {
        (SecureOperation::McpServe, false, _) => StandardInputPlan::Duplex,
        (SecureOperation::McpServe, true, _) => StandardInputPlan::Empty,
        (SecureOperation::Connect, false, true) => StandardInputPlan::Prompt,
        (SecureOperation::Connect, true, false) => StandardInputPlan::ReadRedirected,
        (SecureOperation::Connect, true, true) => StandardInputPlan::RejectFlagRequiresRedirect,
        (SecureOperation::Connect, false, false) => StandardInputPlan::RejectRedirectRequiresFlag,
        (_, _, true) => StandardInputPlan::Empty,
        (_, _, false) => StandardInputPlan::Empty,
    }
}

fn read_bounded_standard_input() -> Result<Zeroizing<Vec<u8>>, CompanionError> {
    let mut input = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .take(4097)
        .read_line(&mut input)
        .map_err(|_| CompanionError::Transport)?;
    if input.len() > 4096 {
        return Err(CompanionError::InputTooLarge);
    }
    Ok(Zeroizing::new(input.as_bytes().to_vec()))
}

fn windows_hello_credential() -> Result<KeyCredential, CompanionError> {
    if !KeyCredentialManager::IsSupportedAsync()
        .and_then(|operation| operation.join())
        .map_err(|_| CompanionError::HelloUnavailable)?
    {
        return Err(CompanionError::HelloUnavailable);
    }
    let name = HSTRING::from(HELLO_KEY_NAME);
    let opened = KeyCredentialManager::OpenAsync(&name)
        .and_then(|operation| operation.join())
        .map_err(|_| CompanionError::HelloUnavailable)?;
    match opened
        .Status()
        .map_err(|_| CompanionError::HelloUnavailable)?
    {
        KeyCredentialStatus::Success => opened
            .Credential()
            .map_err(|_| CompanionError::HelloUnavailable),
        KeyCredentialStatus::NotFound => create_windows_hello_credential(&name),
        _ => Err(CompanionError::HelloUnavailable),
    }
}

fn create_windows_hello_credential(name: &HSTRING) -> Result<KeyCredential, CompanionError> {
    let created =
        KeyCredentialManager::RequestCreateAsync(name, KeyCredentialCreationOption::FailIfExists)
            .and_then(|operation| operation.join())
            .map_err(|_| CompanionError::HelloUnavailable)?;
    match created
        .Status()
        .map_err(|_| CompanionError::HelloUnavailable)?
    {
        KeyCredentialStatus::Success => created
            .Credential()
            .map_err(|_| CompanionError::HelloUnavailable),
        KeyCredentialStatus::CredentialAlreadyExists => KeyCredentialManager::OpenAsync(name)
            .and_then(|operation| operation.join())
            .and_then(|result| {
                if result.Status()? == KeyCredentialStatus::Success {
                    result.Credential()
                } else {
                    Err(windows::core::Error::empty())
                }
            })
            .map_err(|_| CompanionError::HelloUnavailable),
        _ => Err(CompanionError::HelloUnavailable),
    }
}

fn hello_public_key(credential: &KeyCredential) -> Result<Vec<u8>, CompanionError> {
    let buffer = credential
        .RetrievePublicKeyWithBlobType(CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo)
        .map_err(|_| CompanionError::HelloUnavailable)?;
    buffer_to_vec(&buffer)
}

fn hello_sign(credential: &KeyCredential, payload: &[u8]) -> Result<Vec<u8>, CompanionError> {
    let buffer = CryptographicBuffer::CreateFromByteArray(payload)
        .map_err(|_| CompanionError::HelloUnavailable)?;
    let result = credential
        .RequestSignAsync(&buffer)
        .and_then(|operation| operation.join())
        .map_err(|_| CompanionError::HelloUnavailable)?;
    if result
        .Status()
        .map_err(|_| CompanionError::HelloUnavailable)?
        != KeyCredentialStatus::Success
    {
        return Err(CompanionError::HelloUnavailable);
    }
    buffer_to_vec(
        &result
            .Result()
            .map_err(|_| CompanionError::HelloUnavailable)?,
    )
}

fn verify_user_context(operation: SecureOperation, agent_id: &str) -> Result<(), CompanionError> {
    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|operation| operation.join())
        .map_err(|_| CompanionError::HelloUnavailable)?;
    if availability != UserConsentVerifierAvailability::Available {
        return Err(CompanionError::HelloUnavailable);
    }
    let message = HSTRING::from(format!(
        "Palladin: authorize {} for profile {}",
        operation_display_name(operation),
        safe_profile_hint(agent_id),
    ));
    let result = UserConsentVerifier::RequestVerificationAsync(&message)
        .and_then(|operation| operation.join())
        .map_err(|_| CompanionError::HelloUnavailable)?;
    if result != UserConsentVerificationResult::Verified {
        return Err(CompanionError::HelloUnavailable);
    }
    Ok(())
}

const fn operation_display_name(operation: SecureOperation) -> &'static str {
    match operation {
        SecureOperation::Init => "initialize Agent identity",
        SecureOperation::Doctor => "inspect runtime diagnostics",
        SecureOperation::Connect => "connect organization credential",
        SecureOperation::Status => "read Agent status",
        SecureOperation::Disconnect => "disconnect Agent profile",
        SecureOperation::Search => "search vault metadata",
        SecureOperation::Get => "release credential",
        SecureOperation::ReportStale => "report stale credential",
        SecureOperation::McpServe => "open MCP transport",
        SecureOperation::McpSearchEntries => "search vault metadata through MCP",
        SecureOperation::McpGetCredential => "release credential through MCP",
        SecureOperation::McpExecWithCredential => "execute with credential through MCP",
        SecureOperation::McpReportCredentialStale => "report stale credential through MCP",
        SecureOperation::Agents => "manage Agent profiles",
        SecureOperation::Security => "manage runtime security",
        SecureOperation::Purge => "purge Agent profile",
    }
}

fn safe_profile_hint(agent_id: &str) -> String {
    let sanitized = agent_id
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .collect::<String>();
    if sanitized.is_empty() {
        return "selected".to_owned();
    }
    if sanitized.len() <= 32 {
        return sanitized;
    }
    format!("{}…{}", &sanitized[..16], &sanitized[sanitized.len() - 8..])
}

fn buffer_to_vec(buffer: &windows::Storage::Streams::IBuffer) -> Result<Vec<u8>, CompanionError> {
    let mut output = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buffer, &mut output)
        .map_err(|_| CompanionError::HelloUnavailable)?;
    Ok(output.as_slice().to_vec())
}

struct WinRtApartment;

impl WinRtApartment {
    fn initialize() -> Result<Self, CompanionError> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }
            .map(|()| Self)
            .map_err(|_| CompanionError::HelloUnavailable)
    }
}

impl Drop for WinRtApartment {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

#[cfg(test)]
mod tests {
    use palladin_platform::broker_protocol::{
        MAX_MCP_MESSAGE_BYTES, RejectionCode, SecureOperation,
    };

    use super::{
        CompanionError, StandardInputPlan, operation_display_name, rejection_error,
        response_matches_request, safe_profile_hint, standard_input_plan, take_next_mcp_message,
    };

    #[test]
    fn rejection_codes_are_actionable() {
        assert!(
            rejection_error(RejectionCode::ConsentExpired)
                .to_string()
                .contains("retry")
        );
        assert!(
            rejection_error(RejectionCode::WorkerUnavailable)
                .to_string()
                .contains("repair")
        );
        assert!(
            rejection_error(RejectionCode::OperationForbidden)
                .to_string()
                .contains("forbidden")
        );
        assert!(
            rejection_error(RejectionCode::SessionExpired)
                .to_string()
                .contains("30-minute")
        );
    }

    #[test]
    fn pre_request_rejection_without_id_is_mapped_to_the_active_request() {
        assert!(response_matches_request(None, [7; 16]));
        assert!(response_matches_request(Some([7; 16]), [7; 16]));
        assert!(!response_matches_request(Some([8; 16]), [7; 16]));
    }

    #[test]
    fn terminal_connect_uses_masked_prompt_and_never_argv_value() {
        assert_eq!(
            standard_input_plan(SecureOperation::Connect, false, true),
            StandardInputPlan::Prompt
        );
        assert_eq!(
            standard_input_plan(SecureOperation::Connect, true, true),
            StandardInputPlan::RejectFlagRequiresRedirect
        );
    }

    #[test]
    fn redirected_connect_requires_explicit_stdin_flag() {
        assert_eq!(
            standard_input_plan(SecureOperation::Connect, true, false),
            StandardInputPlan::ReadRedirected
        );
        assert_eq!(
            standard_input_plan(SecureOperation::Connect, false, false),
            StandardInputPlan::RejectRedirectRequiresFlag
        );
    }

    #[test]
    fn only_connect_or_mcp_serve_ever_read_standard_input() {
        assert_eq!(
            standard_input_plan(SecureOperation::Status, false, false),
            StandardInputPlan::Empty
        );
        assert_eq!(
            standard_input_plan(SecureOperation::McpServe, false, false),
            StandardInputPlan::Duplex
        );
        assert_eq!(
            standard_input_plan(SecureOperation::McpServe, false, true),
            StandardInputPlan::Duplex
        );
    }

    #[tokio::test]
    async fn fragmented_broker_frame_has_one_non_cancelled_reader_owner() {
        use palladin_platform::broker_protocol::{BrokerFrame, write_frame};
        use tokio::io::AsyncWriteExt as _;

        let (reader, mut writer) = tokio::io::duplex(256);
        let (mut frames, _reader_task) = super::broker_frame_reader(reader);
        let mut encoded = Vec::new();
        write_frame(
            &mut encoded,
            &BrokerFrame::Accepted {
                request_id: [4; 16],
            },
        )
        .await
        .expect("encode");
        for byte in encoded {
            writer.write_all(&[byte]).await.expect("fragment");
            tokio::task::yield_now().await;
        }
        let frame = frames
            .recv()
            .await
            .expect("reader")
            .expect("complete frame");
        assert!(matches!(
            frame,
            BrokerFrame::Accepted { request_id } if request_id == [4; 16]
        ));
    }

    #[test]
    fn mcp_messages_are_framed_one_at_a_time_and_wait_for_ack() {
        let mut pending = br#"{"id":1}
{"id":2}
"#
        .to_vec();
        let first = take_next_mcp_message(&mut pending, false)
            .expect("first")
            .expect("first message");
        assert_eq!(&*first, br#"{"id":1}"#);
        assert_eq!(
            pending,
            br#"{"id":2}
"#
        );
        let second = take_next_mcp_message(&mut pending, false)
            .expect("second")
            .expect("second message");
        assert_eq!(&*second, br#"{"id":2}"#);
        assert!(pending.is_empty());
    }

    #[test]
    fn final_mcp_message_without_newline_is_released_only_after_eof() {
        let mut pending = br#"{"id":1}"#.to_vec();
        assert!(
            take_next_mcp_message(&mut pending, false)
                .expect("pending")
                .is_none()
        );
        let message = take_next_mcp_message(&mut pending, true)
            .expect("eof")
            .expect("message");
        assert_eq!(&*message, br#"{"id":1}"#);
        assert!(pending.is_empty());
    }

    #[test]
    fn oversized_or_empty_mcp_lines_fail_closed() {
        let mut oversized = vec![b'a'; MAX_MCP_MESSAGE_BYTES + 1];
        assert!(matches!(
            take_next_mcp_message(&mut oversized, false),
            Err(CompanionError::InputTooLarge)
        ));
        let mut empty = b"\n".to_vec();
        assert!(matches!(
            take_next_mcp_message(&mut empty, false),
            Err(CompanionError::InputTooLarge)
        ));
    }

    #[test]
    fn consent_context_is_fixed_and_never_renders_control_text() {
        assert_eq!(
            operation_display_name(SecureOperation::McpGetCredential),
            "release credential through MCP"
        );
        assert_eq!(
            safe_profile_hint("build\n\u{202e}attacker"),
            "buildattacker"
        );
        let long = safe_profile_hint("abcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(long, "abcdefghijklmnop…23456789");
    }
}
