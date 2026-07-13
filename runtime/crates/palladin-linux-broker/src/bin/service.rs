#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use palladin_linux_broker::peer::{authenticate_peer, prepare_principal_profile_root};
use palladin_linux_broker::protocol::{
    ClientFrame, MAX_STREAM_CHUNK_BYTES, OutputStream, PROTOCOL_VERSION, RejectionCode,
    ServerFrame, read_frame, validate_arguments, write_frame,
};
use palladin_linux_broker::{SOCKET_PATH, STATE_ROOT, SYSTEM_WORKER};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, Semaphore, mpsc};

const START_TIMEOUT: Duration = Duration::from_secs(10);
const LONG_SESSION_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);
const ADMIN_OPERATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_CONCURRENT_SESSIONS: usize = 32;
const MAX_SESSIONS_PER_UID: usize = 4;
const MAX_SESSION_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> ExitCode {
    palladin_core::panic::install_redacted_panic_hook();
    if let Err(error) = run().await {
        eprintln!("Error: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), ServiceError> {
    attest_service_environment()?;
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false).map_err(|_| ServiceError::Identity)?;
    let listener = create_listener(Path::new(SOCKET_PATH))?;
    let sessions = Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS));
    let per_uid = Arc::new(Mutex::new(HashMap::<u32, Arc<Semaphore>>::new()));
    loop {
        let (stream, _) = listener.accept().await.map_err(|_| ServiceError::Socket)?;
        let Ok(permit) = Arc::clone(&sessions).try_acquire_owned() else {
            reject(stream, None, RejectionCode::Busy).await;
            continue;
        };
        let per_uid = Arc::clone(&per_uid);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle(stream, per_uid).await {
                let _ = error;
            }
        });
    }
}

async fn handle(
    mut stream: UnixStream,
    per_uid: Arc<Mutex<HashMap<u32, Arc<Semaphore>>>>,
) -> Result<(), ServiceError> {
    let peer = match authenticate_peer(&stream) {
        Ok(peer) => peer,
        Err(_) => {
            reject(stream, None, RejectionCode::UnauthorizedPeer).await;
            return Ok(());
        }
    };
    let quota = {
        let mut quotas = per_uid.lock().await;
        Arc::clone(
            quotas
                .entry(peer.uid)
                .or_insert_with(|| Arc::new(Semaphore::new(MAX_SESSIONS_PER_UID))),
        )
    };
    let Ok(_uid_permit) = quota.try_acquire_owned() else {
        reject(stream, None, RejectionCode::Busy).await;
        return Ok(());
    };
    let mut frame = match tokio::time::timeout(
        START_TIMEOUT,
        read_frame::<_, ClientFrame>(&mut stream),
    )
    .await
    {
        Ok(Ok(frame)) => frame,
        _ => {
            reject(stream, None, RejectionCode::InvalidRequest).await;
            return Ok(());
        }
    };
    let (version, request_id, mut arguments) = match &mut frame {
        ClientFrame::Start {
            version,
            request_id,
            arguments,
            ..
        } => (*version, *request_id, std::mem::take(arguments)),
        _ => {
            reject(stream, None, RejectionCode::InvalidRequest).await;
            return Ok(());
        }
    };
    if version != PROTOCOL_VERSION {
        reject(stream, Some(request_id), RejectionCode::UnsupportedVersion).await;
        return Ok(());
    }
    if validate_arguments(&arguments).is_err()
        || validate_operation(&arguments).is_err()
        || contains_profile_selector(&arguments)
    {
        reject(stream, Some(request_id), RejectionCode::InvalidRequest).await;
        return Ok(());
    }
    let session_timeout = operation_timeout(&arguments);
    if arguments.first().map(String::as_str) == Some("connect") {
        arguments.push("--host".to_owned());
        arguments.push(peer.host);
    }
    arguments.insert(0, peer.profile);
    arguments.insert(0, "--id".to_owned());

    let state_root = Path::new(STATE_ROOT);
    let profile_root = match prepare_principal_profile_root(state_root, &peer.principal_id) {
        Ok(root) => root,
        Err(_) => {
            reject(stream, Some(request_id), RejectionCode::Unavailable).await;
            return Ok(());
        }
    };
    let mut child = match spawn_worker(&arguments, &profile_root) {
        Ok(child) => child,
        Err(_) => {
            reject(stream, Some(request_id), RejectionCode::Unavailable).await;
            return Ok(());
        }
    };
    write_frame(&mut stream, &ServerFrame::Accepted { request_id })
        .await
        .map_err(|_| ServiceError::Protocol)?;
    match tokio::time::timeout(
        session_timeout,
        proxy_worker(stream, &mut child, request_id),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            let _ = child.kill().await;
            Err(ServiceError::Timeout)
        }
    }
}

fn spawn_worker(arguments: &[String], profile_root: &Path) -> Result<Child, ServiceError> {
    validate_root_owned_executable(Path::new(SYSTEM_WORKER))?;
    let mut process = Command::new(SYSTEM_WORKER);
    process
        .args(arguments)
        .env_clear()
        .env("HOME", profile_root)
        .env("USER", "palladin-runtime")
        .env("LOGNAME", "palladin-runtime")
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("PALLADIN_LINUX_HARDENED", "1")
        .env("PALLADIN_LINUX_BROKER_ROOT", profile_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    process.spawn().map_err(|_| ServiceError::Worker)
}

async fn proxy_worker(
    stream: UnixStream,
    child: &mut Child,
    request_id: [u8; 16],
) -> Result<(), ServiceError> {
    let mut child_input = child.stdin.take().ok_or(ServiceError::Worker)?;
    let child_output = child.stdout.take().ok_or(ServiceError::Worker)?;
    let child_error = child.stderr.take().ok_or(ServiceError::Worker)?;
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let output_bytes = Arc::new(AtomicUsize::new(0));
    let (failure_sender, mut failure_receiver) = mpsc::channel(2);
    let stdout_task = spawn_output_task(
        child_output,
        Arc::clone(&writer),
        Arc::clone(&output_bytes),
        failure_sender.clone(),
        request_id,
        OutputStream::Stdout,
    );
    let stderr_task = spawn_output_task(
        child_error,
        Arc::clone(&writer),
        Arc::clone(&output_bytes),
        failure_sender,
        request_id,
        OutputStream::Stderr,
    );
    let mut input_task: tokio::task::JoinHandle<Result<(), ServiceError>> =
        tokio::spawn(async move {
            let mut expected_sequence = 0_u64;
            let mut input_closed = false;
            loop {
                let frame: ClientFrame = read_frame(&mut reader)
                    .await
                    .map_err(|_| ServiceError::Cancelled)?;
                match &frame {
                    ClientFrame::Input {
                        request_id: received,
                        sequence,
                        bytes,
                    } if !input_closed
                        && *received == request_id
                        && *sequence == expected_sequence =>
                    {
                        tokio::time::timeout(IO_TIMEOUT, child_input.write_all(bytes))
                            .await
                            .map_err(|_| ServiceError::Timeout)?
                            .map_err(|_| ServiceError::Worker)?;
                        expected_sequence = expected_sequence
                            .checked_add(1)
                            .ok_or(ServiceError::Protocol)?;
                    }
                    ClientFrame::InputClosed {
                        request_id: received,
                        sequence,
                    } if !input_closed
                        && *received == request_id
                        && *sequence == expected_sequence =>
                    {
                        tokio::time::timeout(IO_TIMEOUT, child_input.shutdown())
                            .await
                            .map_err(|_| ServiceError::Timeout)?
                            .map_err(|_| ServiceError::Worker)?;
                        input_closed = true;
                    }
                    ClientFrame::Cancel {
                        request_id: received,
                    } if *received == request_id => {
                        return Err(ServiceError::Cancelled);
                    }
                    _ => return Err(ServiceError::Protocol),
                }
            }
        });

    let status = tokio::select! {
        result = child.wait() => result.map_err(|_| ServiceError::Worker)?,
        result = &mut input_task => {
            let _ = child.kill().await;
            return match result {
                Ok(Err(error)) => Err(error),
                _ => Err(ServiceError::Cancelled),
            };
        }
        failure = failure_receiver.recv() => {
            let _ = child.kill().await;
            return Err(failure.unwrap_or(ServiceError::Output));
        }
    };
    input_task.abort();
    let outputs = tokio::time::timeout(IO_TIMEOUT, async {
        let stdout = stdout_task.await.map_err(|_| ServiceError::Output)?;
        let stderr = stderr_task.await.map_err(|_| ServiceError::Output)?;
        stdout?;
        stderr
    })
    .await
    .map_err(|_| ServiceError::Timeout)?;
    outputs?;
    let code = status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1);
    tokio::time::timeout(IO_TIMEOUT, async {
        write_frame(
            &mut *writer.lock().await,
            &ServerFrame::Exited { request_id, code },
        )
        .await
    })
    .await
    .map_err(|_| ServiceError::Timeout)?
    .map_err(|_| ServiceError::Protocol)
}

fn spawn_output_task<R: AsyncRead + Unpin + Send + 'static>(
    reader: R,
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    output_bytes: Arc<AtomicUsize>,
    failure_sender: mpsc::Sender<ServiceError>,
    request_id: [u8; 16],
    stream: OutputStream,
) -> tokio::task::JoinHandle<Result<(), ServiceError>> {
    tokio::spawn(async move {
        let result = copy_output(reader, writer, output_bytes, request_id, stream).await;
        if result.is_err() {
            let _ = failure_sender.send(ServiceError::Output).await;
        }
        result
    })
}

async fn copy_output<R: AsyncRead + Unpin>(
    mut reader: R,
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    output_bytes: Arc<AtomicUsize>,
    request_id: [u8; 16],
    stream: OutputStream,
) -> Result<(), ServiceError> {
    let mut sequence = 0_u64;
    loop {
        let mut bytes = vec![0_u8; MAX_STREAM_CHUNK_BYTES];
        let count = reader
            .read(&mut bytes)
            .await
            .map_err(|_| ServiceError::Worker)?;
        bytes.truncate(count);
        if count == 0 {
            return Ok(());
        }
        let previous = output_bytes.fetch_add(count, Ordering::AcqRel);
        if previous
            .checked_add(count)
            .is_none_or(|total| total > MAX_SESSION_OUTPUT_BYTES)
        {
            return Err(ServiceError::OutputLimit);
        }
        tokio::time::timeout(IO_TIMEOUT, async {
            write_frame(
                &mut *writer.lock().await,
                &ServerFrame::Output {
                    request_id,
                    stream,
                    sequence,
                    bytes,
                },
            )
            .await
        })
        .await
        .map_err(|_| ServiceError::Timeout)?
        .map_err(|_| ServiceError::Protocol)?;
        sequence = sequence.checked_add(1).ok_or(ServiceError::Protocol)?;
    }
}

async fn reject(mut stream: UnixStream, request_id: Option<[u8; 16]>, code: RejectionCode) {
    let _ = write_frame(&mut stream, &ServerFrame::Rejected { request_id, code }).await;
}

fn create_listener(path: &Path) -> Result<UnixListener, ServiceError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
        {
            return Err(ServiceError::Socket);
        }
        fs::remove_file(path).map_err(|_| ServiceError::Socket)?;
    }
    let listener = UnixListener::bind(path).map_err(|_| ServiceError::Socket)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
        .map_err(|_| ServiceError::Socket)?;
    Ok(listener)
}

fn attest_service_environment() -> Result<(), ServiceError> {
    if nix::unistd::geteuid().is_root() || nix::unistd::geteuid() != nix::unistd::getuid() {
        return Err(ServiceError::Identity);
    }
    validate_root_owned_executable(Path::new(palladin_linux_broker::SYSTEM_SERVICE))?;
    let root = Path::new(STATE_ROOT);
    let metadata = fs::symlink_metadata(root).map_err(|_| ServiceError::State)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ServiceError::State);
    }
    Ok(())
}

fn validate_root_owned_executable(path: &Path) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ServiceError::Installation)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.nlink() != 1
    {
        return Err(ServiceError::Installation);
    }
    Ok(())
}

fn contains_profile_selector(arguments: &[String]) -> bool {
    arguments
        .iter()
        .any(|argument| argument == "--id" || argument.starts_with("--id="))
}

fn validate_operation(arguments: &[String]) -> Result<(), ServiceError> {
    let operation = arguments.first().map(String::as_str);
    match operation {
        Some("init" | "doctor" | "status") if arguments.len() == 1 => Ok(()),
        Some("connect")
            if arguments
                .iter()
                .any(|argument| argument == "--api-key-stdin") =>
        {
            Ok(())
        }
        Some("search" | "get" | "retrieve" | "exec" | "report-stale") => Ok(()),
        Some("mcp") if arguments.len() == 2 && arguments[1] == "serve" => Ok(()),
        Some("agents") if arguments.len() == 2 && arguments[1] == "list" => Ok(()),
        Some("security") if arguments.len() == 2 && arguments[1] == "upgrade" => Ok(()),
        _ => Err(ServiceError::Operation),
    }
}

fn operation_timeout(arguments: &[String]) -> Duration {
    match arguments.first().map(String::as_str) {
        Some("mcp") => LONG_SESSION_TIMEOUT,
        Some("search" | "get" | "retrieve" | "exec" | "report-stale") => OPERATION_TIMEOUT,
        _ => ADMIN_OPERATION_TIMEOUT,
    }
}

#[derive(Debug, Error)]
enum ServiceError {
    #[error("the Linux broker installation is invalid")]
    Installation,
    #[error("the Linux broker must run only as its dedicated non-root UID")]
    Identity,
    #[error("the Linux broker state permissions are invalid")]
    State,
    #[error("the Linux broker socket is unavailable")]
    Socket,
    #[error("the Linux broker protocol failed")]
    Protocol,
    #[error("the Linux broker worker failed")]
    Worker,
    #[error("the Linux broker output transport failed")]
    Output,
    #[error("the Linux broker session output limit was exceeded")]
    OutputLimit,
    #[error("the requested operation is not allowed")]
    Operation,
    #[error("the Linux broker session timed out")]
    Timeout,
    #[error("the Linux broker session was cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::validate_operation;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn hardened_profile_management_cannot_rebind_the_root_mapping() {
        for denied in [
            args(&["agents", "create", "replacement"]),
            args(&["agents", "delete", "production"]),
            args(&["agents", "rename", "production", "replacement"]),
            args(&["purge", "--confirm"]),
            args(&["init", "--force"]),
        ] {
            assert!(validate_operation(&denied).is_err());
        }
        assert!(validate_operation(&args(&["agents", "list"])).is_ok());
    }

    #[test]
    fn hardened_connect_requires_the_bounded_secret_input_mode() {
        assert!(validate_operation(&args(&["connect"])).is_err());
        assert!(validate_operation(&args(&["connect", "--api-key-stdin"])).is_ok());
    }
}
