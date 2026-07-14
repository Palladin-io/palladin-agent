#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::Arc;

use command_group::{AsyncCommandGroup, AsyncGroupChild};
use palladin_linux_executor::{
    ExecutorFrame, ExecutorOutput, INSTALL_MARKER, MAX_FRAME_BYTES, MAX_OUTPUT_BYTES,
    SYSTEM_EXECUTOR, decode_request, parse_install_identity,
};
use palladin_windows_executor::{ExecutorRequest, SecretVariable};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

type PreparedRequest = (
    PathBuf,
    Vec<String>,
    Vec<SecretVariable>,
    Option<tempfile::TempDir>,
);

#[tokio::main]
async fn main() -> ExitCode {
    palladin_core::panic::install_redacted_panic_hook();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ExecutorServiceError> {
    let broker_uid = attest_executor()?;
    authenticate_broker_peer(broker_uid)?;
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false).map_err(|_| ExecutorServiceError::Identity)?;
    let mut input = tokio::io::stdin();
    let length = tokio::time::timeout(std::time::Duration::from_secs(10), input.read_u32())
        .await
        .map_err(|_| ExecutorServiceError::Timeout)?
        .map_err(|_| ExecutorServiceError::Protocol)? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ExecutorServiceError::Protocol);
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        input.read_exact(payload.as_mut()),
    )
    .await
    .map_err(|_| ExecutorServiceError::Timeout)?
    .map_err(|_| ExecutorServiceError::Protocol)?;
    let request = decode_request(&payload).map_err(|_| ExecutorServiceError::Protocol)?;
    payload.zeroize();
    execute(input, tokio::io::stdout(), request).await
}

async fn execute<R, W>(
    mut connection_input: R,
    connection_output: W,
    request: ExecutorRequest,
) -> Result<(), ExecutorServiceError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (program, arguments, environment, temporary) = prepare_request(request)?;
    let mut process = Command::new(program);
    process
        .args(arguments)
        .env_clear()
        .envs(base_environment())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for variable in &environment {
        process.env(variable.name(), variable.value());
    }
    let mut child = process
        .group()
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ExecutorServiceError::Spawn)?;
    drop(process);
    drop(environment);
    let stdout = child
        .inner()
        .stdout
        .take()
        .ok_or(ExecutorServiceError::Spawn)?;
    let stderr = child
        .inner()
        .stderr
        .take()
        .ok_or(ExecutorServiceError::Spawn)?;
    let writer = Arc::new(Mutex::new(connection_output));
    let out = tokio::spawn(copy_output(
        stdout,
        Arc::clone(&writer),
        ExecutorOutput::Stdout,
    ));
    let err = tokio::spawn(copy_output(
        stderr,
        Arc::clone(&writer),
        ExecutorOutput::Stderr,
    ));
    let status = tokio::select! {
        status = wait_for_group(&mut child) => status?,
        disconnected = connection_input.read_u8() => {
            let _ = disconnected;
            let _ = child.kill().await;
            return Err(ExecutorServiceError::Cancelled);
        }
    };
    let output_result = out.await.map_err(|_| ExecutorServiceError::Output)?;
    let error_result = err.await.map_err(|_| ExecutorServiceError::Output)?;
    output_result?;
    error_result?;
    drop(temporary);
    write_frame(
        &mut *writer.lock().await,
        &ExecutorFrame::Exited {
            code: status.code().unwrap_or(1),
        },
    )
    .await
}

fn prepare_request(mut request: ExecutorRequest) -> Result<PreparedRequest, ExecutorServiceError> {
    match &mut request {
        ExecutorRequest::Command {
            command,
            environment,
        } => {
            let (program, arguments) = command
                .split_first()
                .ok_or(ExecutorServiceError::Protocol)?;
            validate_program(program)?;
            let program = PathBuf::from(program);
            let arguments = arguments.to_vec();
            let environment = std::mem::take(environment);
            command.clear();
            Ok((program, arguments, environment, None))
        }
        ExecutorRequest::Script {
            interpreter,
            script,
            environment,
        } => {
            validate_program_path(interpreter)?;
            let directory = tempfile::Builder::new()
                .prefix("palladin-script-")
                .tempdir()
                .map_err(|_| ExecutorServiceError::Temporary)?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                .map_err(|_| ExecutorServiceError::Temporary)?;
            let path = directory.path().join("script");
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|_| ExecutorServiceError::Temporary)?;
            file.write_all(script.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| ExecutorServiceError::Temporary)?;
            script.zeroize();
            let interpreter = std::mem::take(interpreter);
            let environment = std::mem::take(environment);
            Ok((
                interpreter,
                vec![path.to_string_lossy().into_owned()],
                environment,
                Some(directory),
            ))
        }
    }
}

fn validate_program(program: &str) -> Result<(), ExecutorServiceError> {
    if program.trim().is_empty() || program.contains('\0') {
        return Err(ExecutorServiceError::Protocol);
    }
    if Path::new(program).is_absolute() {
        validate_program_path(Path::new(program))?;
    }
    Ok(())
}

fn validate_program_path(program: &Path) -> Result<(), ExecutorServiceError> {
    let canonical = fs::canonicalize(program).map_err(|_| ExecutorServiceError::Executable)?;
    let metadata = fs::metadata(&canonical).map_err(|_| ExecutorServiceError::Executable)?;
    if !canonical.is_absolute() || !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(ExecutorServiceError::Executable);
    }
    Ok(())
}

async fn copy_output<R, W>(
    mut reader: R,
    writer: Arc<Mutex<W>>,
    stream: ExecutorOutput,
) -> Result<(), ExecutorServiceError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut sequence = 0_u64;
    loop {
        let mut bytes = vec![0_u8; MAX_OUTPUT_BYTES];
        let count = reader
            .read(&mut bytes)
            .await
            .map_err(|_| ExecutorServiceError::Output)?;
        bytes.truncate(count);
        if count == 0 {
            return Ok(());
        }
        write_frame(
            &mut *writer.lock().await,
            &ExecutorFrame::Output {
                stream,
                sequence,
                bytes,
            },
        )
        .await?;
        sequence = sequence
            .checked_add(1)
            .ok_or(ExecutorServiceError::Protocol)?;
    }
}

async fn wait_for_group(
    child: &mut AsyncGroupChild,
) -> Result<std::process::ExitStatus, ExecutorServiceError> {
    loop {
        if let Some(status) = child.try_wait().map_err(|_| ExecutorServiceError::Wait)? {
            return Ok(status);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &ExecutorFrame,
) -> Result<(), ExecutorServiceError> {
    let bytes =
        Zeroizing::new(serde_json::to_vec(frame).map_err(|_| ExecutorServiceError::Protocol)?);
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ExecutorServiceError::Protocol);
    }
    writer
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| ExecutorServiceError::Output)?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| ExecutorServiceError::Output)?;
    writer
        .flush()
        .await
        .map_err(|_| ExecutorServiceError::Output)
}

fn attest_executor() -> Result<u32, ExecutorServiceError> {
    if nix::unistd::geteuid().is_root() || nix::unistd::geteuid() != nix::unistd::getuid() {
        return Err(ExecutorServiceError::Identity);
    }
    let executable =
        fs::canonicalize(std::env::current_exe().map_err(|_| ExecutorServiceError::Installation)?)
            .map_err(|_| ExecutorServiceError::Installation)?;
    if executable != Path::new(SYSTEM_EXECUTOR) {
        return Err(ExecutorServiceError::Installation);
    }
    let metadata =
        fs::symlink_metadata(&executable).map_err(|_| ExecutorServiceError::Installation)?;
    if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 || metadata.nlink() != 1 {
        return Err(ExecutorServiceError::Installation);
    }
    let marker =
        fs::read_to_string(INSTALL_MARKER).map_err(|_| ExecutorServiceError::Installation)?;
    let (broker_uid, _, _) =
        parse_install_identity(&marker).ok_or(ExecutorServiceError::Installation)?;
    if broker_uid == nix::unistd::geteuid().as_raw() {
        return Err(ExecutorServiceError::Identity);
    }
    Ok(broker_uid)
}

fn authenticate_broker_peer(expected_uid: u32) -> Result<(), ExecutorServiceError> {
    #[cfg(target_os = "linux")]
    {
        let credentials = nix::sys::socket::getsockopt(
            &std::io::stdin(),
            nix::sys::socket::sockopt::PeerCredentials,
        )
        .map_err(|_| ExecutorServiceError::PeerIdentity)?;
        authorize_broker_uid(credentials.uid(), expected_uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = expected_uid;
        Err(ExecutorServiceError::PeerIdentity)
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn authorize_broker_uid(peer_uid: u32, expected_uid: u32) -> Result<(), ExecutorServiceError> {
    if peer_uid == 0 || peer_uid != expected_uid {
        return Err(ExecutorServiceError::PeerIdentity);
    }
    Ok(())
}

fn base_environment() -> BTreeMap<OsString, OsString> {
    [
        (
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        ("HOME", "/nonexistent"),
        ("USER", "palladin-executor"),
        ("LOGNAME", "palladin-executor"),
    ]
    .into_iter()
    .map(|(name, value)| (OsString::from(name), OsString::from(value)))
    .collect()
}

#[derive(Debug, Error)]
enum ExecutorServiceError {
    #[error("the Linux executor installation is invalid")]
    Installation,
    #[error("the Linux executor identity is invalid")]
    Identity,
    #[error("the Linux executor request did not originate from the broker UID")]
    PeerIdentity,
    #[error("the Linux executor protocol failed")]
    Protocol,
    #[error("the requested executable is unavailable")]
    Executable,
    #[error("the Linux executor could not start the process")]
    Spawn,
    #[error("the Linux executor could not collect process status")]
    Wait,
    #[error("the Linux executor output failed")]
    Output,
    #[error("the Linux executor temporary script failed")]
    Temporary,
    #[error("the Linux executor client disconnected")]
    Cancelled,
    #[error("the Linux executor request timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::{ExecutorServiceError, authorize_broker_uid};

    #[test]
    fn only_the_installed_non_root_broker_uid_is_authorized() {
        assert!(authorize_broker_uid(981, 981).is_ok());
        assert!(matches!(
            authorize_broker_uid(0, 981),
            Err(ExecutorServiceError::PeerIdentity)
        ));
        assert!(matches!(
            authorize_broker_uid(982, 981),
            Err(ExecutorServiceError::PeerIdentity)
        ));
    }
}
