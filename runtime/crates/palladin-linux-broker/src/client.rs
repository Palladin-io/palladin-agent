use std::fs;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
use std::io::IsTerminal;
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};

#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::fcntl::{FcntlArg, SealFlag, fcntl};
#[cfg(target_os = "linux")]
use nix::sys::memfd::{MFdFlags, memfd_create};
#[cfg(target_os = "linux")]
use nix::sys::stat::{Mode, fchmod};

use crate::peer::{PeerError, load_authorized_principal};
use crate::protocol::{
    ClientFrame, MAX_STREAM_CHUNK_BYTES, OutputStream, PROTOCOL_VERSION, RELEASE_VERSION,
    RejectionCode, SOURCE_SHA, ServerFrame, read_frame, validate_arguments, write_frame,
};
use crate::{INSTALL_MARKER, SOCKET_PATH, SYSTEM_CLIENT};

const SAFE_CLIENT_ENVIRONMENT: &[&str] = &[
    "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ",
];
#[cfg(target_os = "linux")]
const SAFE_CONVENIENCE_WORKER_ENVIRONMENT: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "PATH",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "COLORTERM",
    "TZ",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
];
#[cfg(target_os = "linux")]
const POLICY_ENVELOPE_ENVIRONMENT: &str = "PALLADIN_VERSION_POLICY_ENVELOPE_BASE64";

pub async fn run(arguments: Vec<String>) -> Result<ExitCode, ClientError> {
    validate_arguments(&arguments).map_err(|_| ClientError::InvalidArguments)?;
    let current = current_executable()?;
    let mapping = load_authorized_principal(Path::new("/etc/palladin/agents.d"), current_uid());
    let tier = select_tier(
        current == Path::new(SYSTEM_CLIENT),
        &mapping,
        current_process_is_in_broker_group()?,
    );
    match tier {
        RuntimeTier::Hardened => run_hardened(arguments, current).await,
        RuntimeTier::Convenience => run_convenience(arguments).await,
    }
}

async fn run_hardened(
    mut arguments: Vec<String>,
    current: PathBuf,
) -> Result<ExitCode, ClientError> {
    let expected_broker_uid = load_install_marker(Path::new(INSTALL_MARKER))?;
    if current != Path::new(SYSTEM_CLIENT) {
        validate_root_owned_executable(Path::new(SYSTEM_CLIENT))?;
        let status = Command::new(SYSTEM_CLIENT)
            .args(arguments)
            .env_clear()
            .envs(safe_client_environment())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .map_err(|_| ClientError::Installation)?;
        return Ok(exit_code(status.code()));
    }

    validate_root_owned_executable(Path::new(SYSTEM_CLIENT))?;
    let input = prepare_input(&mut arguments).await?;
    let stream = UnixStream::connect(SOCKET_PATH)
        .await
        .map_err(|_| ClientError::BrokerUnavailable)?;
    authenticate_broker(&stream, expected_broker_uid)?;
    proxy(stream, arguments, input).await
}

async fn run_convenience(arguments: Vec<String>) -> Result<ExitCode, ClientError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        Err(ClientError::ConvenienceUnavailable)
    }
    #[cfg(target_os = "linux")]
    {
        let worker = convenience_worker()?;
        let (sealed_worker, worker_sha256) = seal_worker_image(&worker)?;
        palladin_runtime::version_policy::verify_environment_policy_for_worker_hash(
            env!("CARGO_PKG_VERSION"),
            &worker_sha256,
        )
        .map_err(|_| ClientError::ConvenienceUnavailable)?;
        let policy_envelope = std::env::var(POLICY_ENVELOPE_ENVIRONMENT)
            .map_err(|_| ClientError::ConvenienceUnavailable)?;
        let executable = format!("/proc/self/fd/{}", sealed_worker.as_raw_fd());
        let status = Command::new(executable)
            .args(arguments)
            .env_clear()
            .envs(safe_convenience_worker_environment())
            .env(POLICY_ENVELOPE_ENVIRONMENT, policy_envelope)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .map_err(|_| ClientError::ConvenienceUnavailable)?;
        Ok(exit_code(status.code()))
    }
}

async fn proxy(
    stream: UnixStream,
    arguments: Vec<String>,
    input: ClientInput,
) -> Result<ExitCode, ClientError> {
    let mut request_id = [0_u8; 16];
    getrandom::fill(&mut request_id).map_err(|_| ClientError::BrokerProtocol)?;
    let (mut reader, mut writer) = stream.into_split();
    write_frame(
        &mut writer,
        &ClientFrame::Start {
            version: PROTOCOL_VERSION,
            release_version: RELEASE_VERSION.to_owned(),
            source_sha: SOURCE_SHA.to_owned(),
            request_id,
            arguments,
            interactive: std::io::stdin().is_terminal(),
        },
    )
    .await
    .map_err(|_| ClientError::BrokerProtocol)?;

    let input_task = match input {
        ClientInput::Closed => {
            send_input_closed(&mut writer, request_id, 0).await?;
            None
        }
        ClientInput::Secret(bytes) => {
            write_frame(
                &mut writer,
                &ClientFrame::Input {
                    request_id,
                    sequence: 0,
                    bytes: bytes.to_vec(),
                },
            )
            .await
            .map_err(|_| ClientError::BrokerProtocol)?;
            send_input_closed(&mut writer, request_id, 1).await?;
            None
        }
        ClientInput::Stream => Some(tokio::spawn(async move {
            let mut input = tokio::io::stdin();
            let mut sequence = 0_u64;
            loop {
                let mut bytes = vec![0_u8; MAX_STREAM_CHUNK_BYTES];
                let count = input
                    .read(&mut bytes)
                    .await
                    .map_err(|_| ClientError::BrokerProtocol)?;
                bytes.truncate(count);
                if count == 0 {
                    return send_input_closed(&mut writer, request_id, sequence).await;
                }
                write_frame(
                    &mut writer,
                    &ClientFrame::Input {
                        request_id,
                        sequence,
                        bytes,
                    },
                )
                .await
                .map_err(|_| ClientError::BrokerProtocol)?;
                sequence = sequence.checked_add(1).ok_or(ClientError::BrokerProtocol)?;
            }
        })),
    };

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    loop {
        let frame: ServerFrame = read_frame(&mut reader)
            .await
            .map_err(|_| ClientError::BrokerProtocol)?;
        match &frame {
            ServerFrame::Accepted {
                request_id: received,
            } if *received == request_id => {}
            ServerFrame::Output {
                request_id: received,
                stream,
                bytes,
                ..
            } if *received == request_id => match stream {
                OutputStream::Stdout => stdout
                    .write_all(bytes)
                    .await
                    .map_err(|_| ClientError::BrokerProtocol)?,
                OutputStream::Stderr => stderr
                    .write_all(bytes)
                    .await
                    .map_err(|_| ClientError::BrokerProtocol)?,
            },
            ServerFrame::Exited {
                request_id: received,
                code,
            } if *received == request_id => {
                abort_input_task(&input_task);
                return Ok(ExitCode::from(*code));
            }
            ServerFrame::Rejected { code, .. } => {
                abort_input_task(&input_task);
                return Err(ClientError::Rejected(*code));
            }
            _ => {
                abort_input_task(&input_task);
                return Err(ClientError::BrokerProtocol);
            }
        }
    }
}

async fn send_input_closed(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    request_id: [u8; 16],
    sequence: u64,
) -> Result<(), ClientError> {
    write_frame(
        writer,
        &ClientFrame::InputClosed {
            request_id,
            sequence,
        },
    )
    .await
    .map_err(|_| ClientError::BrokerProtocol)
}

fn abort_input_task(task: &Option<tokio::task::JoinHandle<Result<(), ClientError>>>) {
    if let Some(task) = task {
        task.abort();
    }
}

async fn prepare_input(arguments: &mut Vec<String>) -> Result<ClientInput, ClientError> {
    if arguments.first().map(String::as_str) == Some("connect") {
        let from_stdin = arguments
            .iter()
            .any(|argument| argument == "--api-key-stdin");
        if from_stdin && std::io::stdin().is_terminal() {
            return Err(ClientError::ApiKeyInput);
        }
        let mut bytes = if from_stdin {
            let mut input = Vec::new();
            tokio::io::stdin()
                .take(4097)
                .read_to_end(&mut input)
                .await
                .map_err(|_| ClientError::ApiKeyInput)?;
            Zeroizing::new(input)
        } else if std::io::stdin().is_terminal() {
            let value = rpassword::prompt_password("Organization API key: ")
                .map_err(|_| ClientError::ApiKeyInput)?;
            arguments.push("--api-key-stdin".to_owned());
            Zeroizing::new(value.into_bytes())
        } else {
            return Err(ClientError::ApiKeyInput);
        };
        if bytes.len() > 4096 {
            return Err(ClientError::ApiKeyInput);
        }
        if !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        return Ok(ClientInput::Secret(bytes));
    }
    if arguments.len() == 2 && arguments[0] == "mcp" && arguments[1] == "serve" {
        return Ok(ClientInput::Stream);
    }
    Ok(ClientInput::Closed)
}

fn authenticate_broker(stream: &UnixStream, expected_uid: u32) -> Result<(), ClientError> {
    let credentials = stream
        .peer_cred()
        .map_err(|_| ClientError::BrokerIdentity)?;
    if credentials.uid() != expected_uid {
        return Err(ClientError::BrokerIdentity);
    }
    let socket = fs::symlink_metadata(SOCKET_PATH).map_err(|_| ClientError::BrokerIdentity)?;
    if !socket.file_type().is_socket()
        || socket.file_type().is_symlink()
        || socket.uid() != expected_uid
        || socket.permissions().mode() & 0o777 != 0o660
    {
        return Err(ClientError::BrokerIdentity);
    }
    Ok(())
}

fn load_install_marker(path: &Path) -> Result<u32, ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ClientError::Installation)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != 0o644
        || metadata.nlink() != 1
    {
        return Err(ClientError::Installation);
    }
    let value = fs::read_to_string(path).map_err(|_| ClientError::Installation)?;
    let (uid, _, _) =
        palladin_linux_executor::parse_install_identity(&value).ok_or(ClientError::Installation)?;
    Ok(uid)
}

fn current_executable() -> Result<PathBuf, ClientError> {
    fs::canonicalize(std::env::current_exe().map_err(|_| ClientError::Installation)?)
        .map_err(|_| ClientError::Installation)
}

fn current_process_is_in_broker_group() -> Result<bool, ClientError> {
    #[cfg(target_os = "linux")]
    {
        let Some(group) = nix::unistd::Group::from_name("palladin-runtime")
            .map_err(|_| ClientError::AuthorizationConfiguration)?
        else {
            return Ok(false);
        };
        if nix::unistd::getgid() == group.gid || nix::unistd::getegid() == group.gid {
            return Ok(true);
        }
        nix::unistd::getgroups()
            .map(|groups| groups.contains(&group.gid))
            .map_err(|_| ClientError::AuthorizationConfiguration)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(false)
    }
}

fn select_tier<T>(
    is_system_client: bool,
    mapping: &Result<T, PeerError>,
    broker_group_member: bool,
) -> RuntimeTier {
    if is_system_client || mapping.is_ok() {
        return RuntimeTier::Hardened;
    }
    if matches!(mapping, Err(PeerError::UnauthorizedUid)) && !broker_group_member {
        RuntimeTier::Convenience
    } else {
        RuntimeTier::Hardened
    }
}

#[cfg(target_os = "linux")]
fn convenience_worker() -> Result<PathBuf, ClientError> {
    let executable = current_executable()?;
    let parent = executable.parent().ok_or(ClientError::Installation)?;
    Ok(parent.join("palladin-worker"))
}

#[cfg(target_os = "linux")]
fn seal_worker_image(path: &Path) -> Result<(File, String), ClientError> {
    const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
    const MFD_EXEC: u32 = 0x0010;

    let mut source_options = OpenOptions::new();
    source_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut source = source_options
        .open(path)
        .map_err(|_| ClientError::ConvenienceUnavailable)?;
    let source_metadata = source
        .metadata()
        .map_err(|_| ClientError::ConvenienceUnavailable)?;
    if !source_metadata.file_type().is_file()
        || source_metadata.permissions().mode() & 0o022 != 0
        || source_metadata.permissions().mode() & 0o111 == 0
        || source_metadata.nlink() != 1
        || source_metadata.len() == 0
        || source_metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(ClientError::ConvenienceUnavailable);
    }

    let base_flags = MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING;
    // Linux 6.3+ can require MFD_EXEC. Older kernels reject the flag and keep
    // executable memfds as their default, so retry only on EINVAL.
    let exec_flags = base_flags | MFdFlags::from_bits_retain(MFD_EXEC);
    let descriptor = match memfd_create("palladin-worker", exec_flags) {
        Err(Errno::EINVAL) => memfd_create("palladin-worker", base_flags),
        result => result,
    }
    .map_err(|_| ClientError::ConvenienceUnavailable)?;
    let mut sealed = File::from(descriptor);

    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| ClientError::ConvenienceUnavailable)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .filter(|total| *total <= MAX_EXECUTABLE_BYTES)
            .ok_or(ClientError::ConvenienceUnavailable)?;
        hasher.update(&buffer[..read]);
        sealed
            .write_all(&buffer[..read])
            .map_err(|_| ClientError::ConvenienceUnavailable)?;
    }
    if copied != source_metadata.len() {
        return Err(ClientError::ConvenienceUnavailable);
    }
    fchmod(&sealed, Mode::S_IRUSR | Mode::S_IXUSR)
        .map_err(|_| ClientError::ConvenienceUnavailable)?;
    let seals = SealFlag::F_SEAL_SEAL
        | SealFlag::F_SEAL_SHRINK
        | SealFlag::F_SEAL_GROW
        | SealFlag::F_SEAL_WRITE;
    fcntl(&sealed, FcntlArg::F_ADD_SEALS(seals))
        .map_err(|_| ClientError::ConvenienceUnavailable)?;
    sealed
        .seek(SeekFrom::Start(0))
        .map_err(|_| ClientError::ConvenienceUnavailable)?;
    Ok((sealed, format!("{:x}", hasher.finalize())))
}

fn validate_root_owned_executable(path: &Path) -> Result<(), ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ClientError::Installation)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.nlink() != 1
    {
        return Err(ClientError::Installation);
    }
    Ok(())
}

fn safe_client_environment() -> Vec<(String, String)> {
    selected_environment(SAFE_CLIENT_ENVIRONMENT, |name| std::env::var(name))
}

#[cfg(target_os = "linux")]
fn safe_convenience_worker_environment() -> Vec<(String, String)> {
    selected_environment(SAFE_CONVENIENCE_WORKER_ENVIRONMENT, |name| {
        std::env::var(name)
    })
}

fn selected_environment(
    allowed: &[&str],
    mut value: impl FnMut(&str) -> Result<String, std::env::VarError>,
) -> Vec<(String, String)> {
    allowed
        .iter()
        .filter_map(|name| value(name).ok().map(|value| ((*name).to_owned(), value)))
        .collect()
}

fn current_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

fn exit_code(code: Option<i32>) -> ExitCode {
    ExitCode::from(code.and_then(|code| u8::try_from(code).ok()).unwrap_or(1))
}

enum ClientInput {
    Closed,
    Secret(Zeroizing<Vec<u8>>),
    Stream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeTier {
    Convenience,
    Hardened,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Palladin command arguments are invalid")]
    InvalidArguments,
    #[error("the dedicated Agent UID authorization is invalid or revoked")]
    AuthorizationConfiguration,
    #[error("the Linux Hardened installation is missing or has unsafe permissions")]
    Installation,
    #[error(
        "the Linux Hardened broker is unavailable; no Convenience fallback is allowed for this dedicated Agent UID"
    )]
    BrokerUnavailable,
    #[error("the Linux Hardened broker identity is invalid")]
    BrokerIdentity,
    #[error("the Linux Hardened broker protocol failed")]
    BrokerProtocol,
    #[error("the Linux Hardened broker rejected the operation: {0:?}")]
    Rejected(RejectionCode),
    #[error("the Linux Convenience runtime is unavailable")]
    ConvenienceUnavailable,
    #[error(
        "Hardened connect requires a masked terminal prompt or a protected pipe with --api-key-stdin"
    )]
    ApiKeyInput,
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_os = "linux")]
    use super::seal_worker_image;
    #[cfg(target_os = "linux")]
    use super::{
        POLICY_ENVELOPE_ENVIRONMENT, SAFE_CONVENIENCE_WORKER_ENVIRONMENT, selected_environment,
    };
    use super::{RuntimeTier, select_tier};
    use crate::peer::PeerError;
    #[cfg(target_os = "linux")]
    use nix::fcntl::{FcntlArg, SealFlag, fcntl};
    #[cfg(target_os = "linux")]
    use tokio::process::Command;

    #[test]
    fn system_client_never_downgrades_when_mapping_is_missing() {
        let mapping: Result<(), PeerError> = Err(PeerError::UnauthorizedUid);
        assert_eq!(select_tier(true, &mapping, false), RuntimeTier::Hardened);
    }

    #[test]
    fn designated_or_revoked_uid_never_downgrades() {
        let missing: Result<(), PeerError> = Err(PeerError::UnauthorizedUid);
        let revoked: Result<(), PeerError> = Err(PeerError::RevokedUid);
        assert_eq!(select_tier(false, &missing, true), RuntimeTier::Hardened);
        assert_eq!(select_tier(false, &revoked, false), RuntimeTier::Hardened);
    }

    #[test]
    fn only_never_designated_npm_client_uses_convenience() {
        let mapping: Result<(), PeerError> = Err(PeerError::UnauthorizedUid);
        assert_eq!(
            select_tier(false, &mapping, false),
            RuntimeTier::Convenience
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn convenience_worker_environment_is_a_positive_allowlist() {
        let selected = selected_environment(SAFE_CONVENIENCE_WORKER_ENVIRONMENT, |name| {
            Ok(format!("fixture-{name}"))
        });
        let names = selected
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"PATH"));
        assert!(names.contains(&"XDG_RUNTIME_DIR"));
        assert!(names.contains(&"DBUS_SESSION_BUS_ADDRESS"));
        assert!(!names.contains(&"LD_PRELOAD"));
        assert!(!names.contains(&"LD_LIBRARY_PATH"));
        assert!(!names.contains(&"LD_AUDIT"));
        assert!(!names.contains(&"GLIBC_TUNABLES"));
        assert!(!names.contains(&POLICY_ENVELOPE_ENVIRONMENT));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn convenience_exec_uses_an_immutable_verified_worker_image() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let worker = directory.path().join("palladin-worker");
        let marker = directory.path().join("attacker-ran");
        fs::copy("/usr/bin/true", &worker).expect("copy worker");
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o755)).expect("worker mode");

        let (sealed, hash) = seal_worker_image(&worker).expect("sealed worker");
        assert_eq!(hash.len(), 64);
        let active_seals =
            SealFlag::from_bits_retain(fcntl(&sealed, FcntlArg::F_GET_SEALS).expect("read seals"));
        assert_eq!(
            active_seals
                & (SealFlag::F_SEAL_SEAL
                    | SealFlag::F_SEAL_SHRINK
                    | SealFlag::F_SEAL_GROW
                    | SealFlag::F_SEAL_WRITE),
            SealFlag::F_SEAL_SEAL
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_WRITE
        );

        fs::write(
            &worker,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .expect("replace source bytes in place");
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o755)).expect("attacker mode");

        let status = Command::new(format!("/proc/self/fd/{}", sealed.as_raw_fd()))
            .status()
            .await
            .expect("execute sealed worker");
        assert!(status.success());
        assert!(!marker.exists());
    }
}
