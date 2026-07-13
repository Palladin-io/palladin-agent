#[cfg(not(windows))]
fn main() {
    eprintln!("Error: Palladin Windows service can run only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
mod windows_service_entry {
    use std::ffi::OsString;
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime};

    use palladin_platform::broker_protocol::{
        BrokerFrame, ClientFrame, ExecuteRequest, OutputStream, ProtocolError, RejectionCode,
        ReplayGuard, RsaSha256ConsentVerifier, read_frame, validate_challenge_request, write_frame,
    };
    use palladin_windows_broker::{
        SERVICE_NAME, WindowsBrokerError, attest_service_identity, authenticate_connected_caller,
        broker_profile_root, create_local_pipe, program_data_path, trusted_worker_path,
    };
    use thiserror::Error;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::NamedPipeServer;
    use tokio::process::Command;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::{define_windows_service, service_dispatcher};
    use zeroize::Zeroizing;

    const CONSENT_LIFETIME: Duration = Duration::from_secs(60);
    const CONSENT_CLOCK_SKEW: Duration = Duration::from_secs(5);
    const MAX_WORKER_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
    const OUTPUT_CHUNK_BYTES: usize = 64 * 1024;
    const BROKER_ROOT_ENV: &str = "PALLADIN_BROKER_ROOT";

    #[derive(Debug, Error)]
    enum ServiceError {
        #[error(transparent)]
        Broker(#[from] WindowsBrokerError),
        #[error(transparent)]
        Protocol(#[from] ProtocolError),
        #[error("broker-owned storage is unavailable")]
        Storage(#[from] std::io::Error),
        #[error("broker executable has no trusted installation directory")]
        InstallDirectory,
        #[error("worker output exceeded the broker limit")]
        OutputLimit,
    }

    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        let stopping = Arc::new(AtomicBool::new(false));
        let control_stopping = Arc::clone(&stopping);
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                control_stopping.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(status) = service_control_handler::register(SERVICE_NAME, handler) else {
            return;
        };
        let _ = set_status(
            &status,
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            1,
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build();
        let result = runtime
            .map_err(ServiceError::Storage)
            .and_then(|runtime| runtime.block_on(run_service(&status, stopping)));
        let exit_code = if result.is_ok() { 0 } else { 1 };
        let _ = set_status(
            &status,
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit_code,
        );
    }

    fn set_status(
        handle: &ServiceStatusHandle,
        state: ServiceState,
        controls: ServiceControlAccept,
        exit_code: u32,
    ) -> windows_service::Result<()> {
        handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            exit_code: ServiceExitCode::Win32(exit_code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })
    }

    async fn run_service(
        status: &ServiceStatusHandle,
        stopping: Arc<AtomicBool>,
    ) -> Result<(), ServiceError> {
        attest_service_identity()?;
        let install_root = std::env::current_exe()?
            .parent()
            .map(Path::to_path_buf)
            .ok_or(ServiceError::InstallDirectory)?;
        let worker = trusted_worker_path(&install_root)?;
        let program_data = program_data_path()?;
        set_status(
            status,
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
        )
        .map_err(|_| WindowsBrokerError::OperatingSystem)?;

        let mut first_instance = true;
        let mut connections = tokio::task::JoinSet::new();
        while !stopping.load(Ordering::SeqCst) {
            while connections.try_join_next().is_some() {}
            let pipe = create_local_pipe(first_instance)?;
            first_instance = false;
            let connected = tokio::select! {
                result = pipe.connect() => result.map(|()| true)?,
                () = wait_for_stop(&stopping) => false,
            };
            if !connected {
                break;
            }
            let caller = match authenticate_connected_caller(&pipe) {
                Ok(caller) => caller,
                Err(_) => continue,
            };
            let root = broker_profile_root(&program_data, &caller.user_sid)
                .map_err(|_| WindowsBrokerError::CallerNotAuthorized)?;
            let worker = worker.clone();
            connections.spawn(async move {
                let _ = handle_connection(pipe, root, worker).await;
            });
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }

    async fn wait_for_stop(stopping: &AtomicBool) {
        while !stopping.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn handle_connection(
        mut pipe: NamedPipeServer,
        root: std::path::PathBuf,
        worker: std::path::PathBuf,
    ) -> Result<(), ServiceError> {
        let challenge_request: ClientFrame = read_frame(&mut pipe).await?;
        let ClientFrame::RequestChallenge {
            request_id,
            operation,
            agent_id,
            request_hash,
            public_key_spki_der,
        } = challenge_request
        else {
            reject(&mut pipe, None, RejectionCode::InvalidRequest).await?;
            return Ok(());
        };
        validate_challenge_request(&agent_id, &public_key_spki_der)?;
        prepare_caller_root(&root)?;
        let pin_path = root.join("windows-hello-public-key.spki");
        let is_new_key = verify_existing_pin(&pin_path, &public_key_spki_der)?;
        let verifier =
            RsaSha256ConsentVerifier::from_subject_public_key_info_der(&public_key_spki_der)?;
        let mut guard = ReplayGuard::new(CONSENT_LIFETIME, CONSENT_CLOCK_SKEW);
        let challenge = guard.issue_challenge(
            request_id,
            operation,
            agent_id,
            request_hash,
            SystemTime::now(),
        )?;
        write_frame(&mut pipe, &challenge).await?;

        let execute: ClientFrame = read_frame(&mut pipe).await?;
        let ClientFrame::Execute(mut request) = execute else {
            reject(&mut pipe, Some(request_id), RejectionCode::InvalidRequest).await?;
            return Ok(());
        };
        if let Err(error) = guard.verify_and_record(&request, &verifier, SystemTime::now()) {
            reject(&mut pipe, Some(request_id), rejection_for(&error)).await?;
            return Ok(());
        }
        if is_new_key {
            pin_key_once(&pin_path, &public_key_spki_der)?;
        }
        write_frame(
            &mut pipe,
            &BrokerFrame::Accepted {
                request_id: request.request_id,
            },
        )
        .await?;
        run_worker(&mut pipe, &mut request, &root, &worker).await
    }

    fn prepare_caller_root(root: &Path) -> Result<(), ServiceError> {
        let protected_parent = root.parent().ok_or(ServiceError::InstallDirectory)?;
        if !protected_parent.is_dir() {
            // The installer must pre-create ProgramData\Palladin\Runtime\v1
            // with its protected service-SID DACL. Never reconstruct that
            // hierarchy with inherited ProgramData permissions at runtime.
            return Err(ServiceError::InstallDirectory);
        }
        match fs::create_dir(root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && root.is_dir() => {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn verify_existing_pin(path: &Path, candidate: &[u8]) -> Result<bool, ServiceError> {
        match fs::read(path) {
            Ok(existing) if existing == candidate => Ok(false),
            Ok(_) => Err(ProtocolError::ConsentInvalid.into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }

    fn pin_key_once(path: &Path, key: &[u8]) -> Result<(), ServiceError> {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                file.write_all(key)?;
                file.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_existing_pin(path, key).map(|_| ())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn run_worker(
        pipe: &mut NamedPipeServer,
        request: &mut ExecuteRequest,
        root: &Path,
        worker: &Path,
    ) -> Result<(), ServiceError> {
        let mut child = Command::new(worker)
            .args(&request.arguments)
            .env_clear()
            .env(BROKER_ROOT_ENV, root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = Zeroizing::new(std::mem::take(&mut request.standard_input));
        let mut stdin = child
            .stdin
            .take()
            .ok_or(WindowsBrokerError::OperatingSystem)?;
        let stdin_task = tokio::spawn(async move {
            // `try_write` is not used: shutdown must flush the pipe.
            let result = stdin.write_all(&input).await;
            let shutdown = stdin.shutdown().await;
            result.and(shutdown)
        });
        let stdout = child
            .stdout
            .take()
            .ok_or(WindowsBrokerError::OperatingSystem)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(WindowsBrokerError::OperatingSystem)?;
        let stdout_task = tokio::spawn(read_bounded(stdout));
        let stderr_task = tokio::spawn(read_bounded(stderr));
        let status = child.wait().await?;
        stdin_task
            .await
            .map_err(|_| WindowsBrokerError::OperatingSystem)??;
        let (stdout, stdout_overflow) = stdout_task
            .await
            .map_err(|_| WindowsBrokerError::OperatingSystem)??;
        let (stderr, stderr_overflow) = stderr_task
            .await
            .map_err(|_| WindowsBrokerError::OperatingSystem)??;
        if stdout_overflow || stderr_overflow {
            reject(
                pipe,
                Some(request.request_id),
                RejectionCode::WorkerUnavailable,
            )
            .await?;
            return Err(ServiceError::OutputLimit);
        }
        relay_output(
            pipe,
            request.request_id,
            OutputStream::StandardOutput,
            &stdout,
        )
        .await?;
        relay_output(
            pipe,
            request.request_id,
            OutputStream::StandardError,
            &stderr,
        )
        .await?;
        write_frame(
            pipe,
            &BrokerFrame::Exited {
                request_id: request.request_id,
                exit_code: status.code().unwrap_or(1),
            },
        )
        .await?;
        Ok(())
    }

    async fn read_bounded<R: AsyncRead + Unpin>(
        mut reader: R,
    ) -> std::io::Result<(Zeroizing<Vec<u8>>, bool)> {
        let mut output = Zeroizing::new(Vec::new());
        let mut overflow = false;
        let mut buffer = Zeroizing::new([0_u8; 8192]);
        loop {
            let read = reader.read(&mut buffer[..]).await?;
            if read == 0 {
                break;
            }
            let remaining = MAX_WORKER_OUTPUT_BYTES.saturating_sub(output.len());
            output.extend_from_slice(&buffer[..read.min(remaining)]);
            overflow |= read > remaining;
        }
        Ok((output, overflow))
    }

    async fn relay_output(
        pipe: &mut NamedPipeServer,
        request_id: [u8; 16],
        stream: OutputStream,
        bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        for chunk in bytes.chunks(OUTPUT_CHUNK_BYTES) {
            write_frame(
                &mut *pipe,
                &BrokerFrame::Output {
                    request_id,
                    stream,
                    bytes: chunk.to_vec(),
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn reject(
        pipe: &mut NamedPipeServer,
        request_id: Option<[u8; 16]>,
        code: RejectionCode,
    ) -> Result<(), ProtocolError> {
        write_frame(pipe, &BrokerFrame::Rejected { request_id, code }).await
    }

    fn rejection_for(error: &ProtocolError) -> RejectionCode {
        match error {
            ProtocolError::ConsentExpired => RejectionCode::ConsentExpired,
            ProtocolError::ReplayDetected => RejectionCode::ReplayDetected,
            ProtocolError::OperationForbidden => RejectionCode::OperationForbidden,
            ProtocolError::ConsentInvalid => RejectionCode::ConsentInvalid,
            _ => RejectionCode::InvalidRequest,
        }
    }
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    windows_service_entry::dispatch()
}
