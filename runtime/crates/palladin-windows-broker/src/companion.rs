use std::io::{IsTerminal, Read, Write};
use std::time::Duration;

use palladin_platform::broker_protocol::{
    BrokerFrame, ClientFrame, ConsentChallenge, ExecuteRequest, MAX_FRAME_BYTES, OutputStream,
    ProtocolError, SecureOperation, consent_payload, operation_and_profile, read_frame,
    request_hash, write_frame,
};
use thiserror::Error;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType;
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::{Array, HSTRING};
use zeroize::Zeroize;

use crate::{PIPE_NAME, WindowsBrokerError, authenticate_connected_server};

const HELLO_KEY_NAME: &str = "Palladin Runtime Consent v1";
const PIPE_CONNECT_ATTEMPTS: usize = 60;
const PIPE_CONNECT_DELAY: Duration = Duration::from_millis(50);

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
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let (operation, agent_id) =
        operation_and_profile(&arguments).map_err(|_| CompanionError::UnsupportedCommand)?;
    let standard_input = read_bounded_standard_input()?;
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
    standard_input: Vec<u8>,
    expected_request_hash: [u8; 32],
) -> Result<i32, CompanionError> {
    let mut pipe = connect_to_authenticated_service().await?;
    let credential = windows_hello_credential()?;
    let public_key_spki_der = hello_public_key(&credential)?;
    write_frame(
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

    let challenge: BrokerFrame = read_frame(&mut pipe).await?;
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
        _ => return Err(CompanionError::InvalidResponse),
    };

    let mut consent = ConsentChallenge {
        nonce,
        issued_at_unix_ms,
        expires_at_unix_ms,
        agent_id,
        operation,
        request_hash: expected_request_hash,
        signature: Vec::new(),
    };
    let mut payload = consent_payload(&consent).map_err(|_| CompanionError::InvalidResponse)?;
    consent.signature = hello_sign(&credential, &payload)?;
    payload.zeroize();
    let request = ExecuteRequest {
        request_id,
        operation,
        arguments,
        standard_input,
        consent,
    };
    write_frame(&mut pipe, &ClientFrame::Execute(request)).await?;

    loop {
        let frame = read_frame::<_, BrokerFrame>(&mut pipe).await?;
        match &frame {
            BrokerFrame::Accepted {
                request_id: response_id,
            } if *response_id == request_id => {}
            BrokerFrame::Output {
                request_id: response_id,
                stream,
                bytes,
            } if *response_id == request_id => match stream {
                OutputStream::StandardOutput => std::io::stdout()
                    .write_all(bytes)
                    .map_err(|_| CompanionError::Transport)?,
                OutputStream::StandardError => std::io::stderr()
                    .write_all(bytes)
                    .map_err(|_| CompanionError::Transport)?,
            },
            BrokerFrame::Exited {
                request_id: response_id,
                exit_code,
            } if *response_id == request_id => return Ok(*exit_code),
            BrokerFrame::Rejected {
                request_id: Some(response_id),
                ..
            } if *response_id == request_id => return Ok(1),
            _ => return Err(CompanionError::InvalidResponse),
        }
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

fn read_bounded_standard_input() -> Result<Vec<u8>, CompanionError> {
    if std::io::stdin().is_terminal() {
        return Ok(Vec::new());
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take((MAX_FRAME_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| CompanionError::Transport)?;
    if input.len() > MAX_FRAME_BYTES {
        input.zeroize();
        return Err(CompanionError::InputTooLarge);
    }
    Ok(input)
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
