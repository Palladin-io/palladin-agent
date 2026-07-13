#[cfg(not(windows))]
fn main() {
    eprintln!("Error: Palladin Windows service can run only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
mod windows_service_entry {
    use std::ffi::OsString;
    use std::fs::{self, OpenOptions};
    use std::io::{self, Write as _};
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant, SystemTime};

    use palladin_platform::broker_protocol::{
        BrokerFrame, ClientFrame, ExecuteRequest, MAX_STREAM_CHUNK_BYTES, OutputStream,
        ProtocolError, RejectionCode, ReplayGuard, RsaSha256ConsentVerifier, SecureOperation,
        read_frame, validate_challenge_request, write_frame,
    };
    use palladin_windows_broker::{
        SERVICE_NAME, UserSessionLimiter, WindowsBrokerError, attest_service_identity,
        authenticate_connected_caller, broker_profile_root, create_local_pipe, program_data_path,
        trusted_worker_path,
    };
    use thiserror::Error;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::windows::named_pipe::NamedPipeServer;
    use tokio::process::Command;
    use tokio::sync::{Semaphore, mpsc};
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::{define_windows_service, service_dispatcher};
    use zeroize::{Zeroize, Zeroizing};

    const CONSENT_LIFETIME: Duration = Duration::from_secs(60);
    const CONSENT_CLOCK_SKEW: Duration = Duration::from_secs(5);
    const INITIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
    const CONSENT_FRAME_TIMEOUT: Duration = Duration::from_secs(65);
    const MAX_ACTIVE_CONNECTIONS: usize = 8;
    const MAX_ACTIVE_CONNECTIONS_PER_USER: u32 = 2;
    const MAX_CONNECTIONS_PER_USER_WINDOW: u32 = 30;
    const USER_RATE_WINDOW: Duration = Duration::from_secs(60);
    const ONE_SHOT_SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
    const MCP_SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
    const OUTPUT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
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
        #[error("broker client did not complete the protocol in time")]
        ClientTimeout,
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
        let connection_limit = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
        let user_limit = Arc::new(UserSessionLimiter::new(
            USER_RATE_WINDOW,
            MAX_ACTIVE_CONNECTIONS_PER_USER,
            MAX_CONNECTIONS_PER_USER_WINDOW,
        ));
        while !stopping.load(Ordering::SeqCst) {
            while connections.try_join_next().is_some() {}
            let mut pipe = create_local_pipe(first_instance)?;
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
            let user_permit = match user_limit.try_acquire(&caller.user_sid, Instant::now()) {
                Some(permit) => permit,
                None => {
                    let _ = reject(&mut pipe, None, RejectionCode::WorkerUnavailable).await;
                    continue;
                }
            };
            let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let _ = reject(&mut pipe, None, RejectionCode::WorkerUnavailable).await;
                    continue;
                }
            };
            let root = broker_profile_root(&program_data, &caller.user_sid)
                .map_err(|_| WindowsBrokerError::CallerNotAuthorized)?;
            let worker = worker.clone();
            connections.spawn(async move {
                let _permit = permit;
                let _user_permit = user_permit;
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
        let challenge_request: ClientFrame =
            match tokio::time::timeout(INITIAL_FRAME_TIMEOUT, read_frame(&mut pipe)).await {
                Ok(Ok(frame)) => frame,
                Ok(Err(_)) => {
                    reject(&mut pipe, None, RejectionCode::InvalidRequest).await?;
                    return Ok(());
                }
                Err(_) => {
                    reject(&mut pipe, None, RejectionCode::InvalidRequest).await?;
                    return Err(ServiceError::ClientTimeout);
                }
            };
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
        if let Err(error) = validate_challenge_request(&agent_id, &public_key_spki_der) {
            reject(&mut pipe, Some(request_id), rejection_for(&error)).await?;
            return Ok(());
        }
        if let Err(error) = prepare_caller_root(&root) {
            reject(&mut pipe, Some(request_id), rejection_for_service(&error)).await?;
            return Ok(());
        }
        let pin_path = root.join("windows-hello-public-key.spki");
        let is_new_key = match verify_existing_pin(&pin_path, &public_key_spki_der) {
            Ok(is_new_key) => is_new_key,
            Err(error) => {
                reject(&mut pipe, Some(request_id), rejection_for_service(&error)).await?;
                return Ok(());
            }
        };
        let verifier = match RsaSha256ConsentVerifier::from_subject_public_key_info_der(
            &public_key_spki_der,
        ) {
            Ok(verifier) => verifier,
            Err(error) => {
                reject(&mut pipe, Some(request_id), rejection_for(&error)).await?;
                return Ok(());
            }
        };
        let mut guard = ReplayGuard::new(CONSENT_LIFETIME, CONSENT_CLOCK_SKEW);
        let challenge = match guard.issue_challenge(
            request_id,
            operation,
            agent_id,
            request_hash,
            SystemTime::now(),
        ) {
            Ok(challenge) => challenge,
            Err(error) => {
                reject(&mut pipe, Some(request_id), rejection_for(&error)).await?;
                return Ok(());
            }
        };
        write_broker_frame(&mut pipe, &challenge).await?;

        let execute: ClientFrame =
            match tokio::time::timeout(CONSENT_FRAME_TIMEOUT, read_frame(&mut pipe)).await {
                Ok(Ok(frame)) => frame,
                Ok(Err(_)) => {
                    reject(&mut pipe, Some(request_id), RejectionCode::InvalidRequest).await?;
                    return Ok(());
                }
                Err(_) => {
                    reject(&mut pipe, Some(request_id), RejectionCode::ConsentExpired).await?;
                    return Err(ServiceError::ClientTimeout);
                }
            };
        let ClientFrame::Execute(mut request) = execute else {
            reject(&mut pipe, Some(request_id), RejectionCode::InvalidRequest).await?;
            return Ok(());
        };
        if let Err(error) = guard.verify_and_record(&request, &verifier, SystemTime::now()) {
            reject(&mut pipe, Some(request_id), rejection_for(&error)).await?;
            return Ok(());
        }
        if is_new_key && let Err(error) = pin_key_once(&pin_path, &public_key_spki_der) {
            reject(&mut pipe, Some(request_id), rejection_for_service(&error)).await?;
            return Ok(());
        }
        write_broker_frame(
            &mut pipe,
            &BrokerFrame::Accepted {
                request_id: request.request_id,
            },
        )
        .await?;
        let session_timeout = match request.operation {
            palladin_platform::broker_protocol::SecureOperation::McpServe => MCP_SESSION_TIMEOUT,
            _ => ONE_SHOT_SESSION_TIMEOUT,
        };
        run_worker(pipe, &mut request, &root, &worker, session_timeout).await
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
        pipe: NamedPipeServer,
        request: &mut ExecuteRequest,
        root: &Path,
        worker: &Path,
        session_timeout: Duration,
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
        let duplex = request.operation == SecureOperation::McpServe;
        let input = Zeroizing::new(std::mem::take(&mut request.standard_input));
        let mut worker_stdin = child
            .stdin
            .take()
            .ok_or(WindowsBrokerError::OperatingSystem)?;
        if !duplex {
            tokio::time::timeout(OUTPUT_WRITE_TIMEOUT, worker_stdin.write_all(&input))
                .await
                .map_err(|_| ServiceError::ClientTimeout)??;
            tokio::time::timeout(OUTPUT_WRITE_TIMEOUT, worker_stdin.shutdown())
                .await
                .map_err(|_| ServiceError::ClientTimeout)??;
        }
        drop(input);
        let stdout = child
            .stdout
            .take()
            .ok_or(WindowsBrokerError::OperatingSystem)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(WindowsBrokerError::OperatingSystem)?;
        let request_id = request.request_id;
        let (pipe_reader, pipe_writer) = tokio::io::split(pipe);
        let (output_sender, output_receiver) = mpsc::channel(16);
        let (control_sender, mut control_receiver) = mpsc::channel(1);
        let writer_control = control_sender.clone();
        let writer_task = tokio::spawn(write_worker_output(
            pipe_writer,
            request_id,
            output_receiver,
            writer_control,
        ));
        let output_budget = (!duplex).then(|| Arc::new(AtomicUsize::new(0)));
        let stdout_task = tokio::spawn(read_worker_output(
            stdout,
            OutputStream::StandardOutput,
            output_budget.clone(),
            output_sender.clone(),
            control_sender.clone(),
        ));
        let stderr_task = tokio::spawn(read_worker_output(
            stderr,
            OutputStream::StandardError,
            output_budget,
            output_sender.clone(),
            control_sender.clone(),
        ));
        let input_task = tokio::spawn(read_client_input(
            pipe_reader,
            request_id,
            duplex.then_some(worker_stdin),
            control_sender,
        ));

        let mut completion = tokio::select! {
            status = child.wait() => WorkerCompletion::Exited(status?),
            control = control_receiver.recv() => control.unwrap_or(WorkerCompletion::Disconnected),
            () = tokio::time::sleep(session_timeout) => WorkerCompletion::TimedOut,
        };
        let mut exit_code = match &completion {
            WorkerCompletion::Exited(status) => status.code().unwrap_or(1),
            WorkerCompletion::Cancelled => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                130
            }
            WorkerCompletion::Disconnected
            | WorkerCompletion::InvalidRequest
            | WorkerCompletion::WorkerFailed
            | WorkerCompletion::WriterFailed
            | WorkerCompletion::OutputLimit
            | WorkerCompletion::TimedOut => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                1
            }
        };

        input_task.abort();
        stdout_task
            .await
            .map_err(|_| WindowsBrokerError::OperatingSystem)??;
        stderr_task
            .await
            .map_err(|_| WindowsBrokerError::OperatingSystem)??;
        if matches!(completion, WorkerCompletion::Exited(_))
            && let Ok(pending) = control_receiver.try_recv()
        {
            // A final output read can observe the combined limit at the same
            // time as the OS reports process exit. Security failures win that
            // race and must never be rendered as a successful exit.
            if matches!(pending, WorkerCompletion::Cancelled) {
                exit_code = 130;
            }
            completion = pending;
        }

        let terminal_frame = match completion {
            WorkerCompletion::Exited(_) | WorkerCompletion::Cancelled => BrokerFrame::Exited {
                request_id,
                exit_code,
            },
            WorkerCompletion::InvalidRequest => BrokerFrame::Rejected {
                request_id: Some(request_id),
                code: RejectionCode::InvalidRequest,
            },
            WorkerCompletion::TimedOut => BrokerFrame::Rejected {
                request_id: Some(request_id),
                code: RejectionCode::SessionExpired,
            },
            WorkerCompletion::OutputLimit => BrokerFrame::Rejected {
                request_id: Some(request_id),
                code: RejectionCode::WorkerUnavailable,
            },
            WorkerCompletion::WorkerFailed => BrokerFrame::Rejected {
                request_id: Some(request_id),
                code: RejectionCode::WorkerUnavailable,
            },
            WorkerCompletion::Disconnected | WorkerCompletion::WriterFailed => {
                writer_task.abort();
                return Err(ServiceError::ClientTimeout);
            }
        };
        output_sender
            .send(OutboundItem::Frame(terminal_frame))
            .await
            .map_err(|_| {
                WindowsBrokerError::Transport(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "broker output writer stopped",
                ))
            })?;
        drop(output_sender);
        writer_task
            .await
            .map_err(|_| WindowsBrokerError::OperatingSystem)??;
        Ok(())
    }

    enum WorkerCompletion {
        Exited(std::process::ExitStatus),
        Cancelled,
        Disconnected,
        InvalidRequest,
        WorkerFailed,
        WriterFailed,
        OutputLimit,
        TimedOut,
    }

    struct WorkerOutput {
        stream: OutputStream,
        bytes: Vec<u8>,
    }

    impl Drop for WorkerOutput {
        fn drop(&mut self) {
            use zeroize::Zeroize as _;
            self.bytes.zeroize();
        }
    }

    enum OutboundItem {
        Output(WorkerOutput),
        Frame(BrokerFrame),
    }

    async fn read_worker_output<R: AsyncRead + Unpin>(
        mut reader: R,
        stream: OutputStream,
        budget: Option<Arc<AtomicUsize>>,
        sender: mpsc::Sender<OutboundItem>,
        control: mpsc::Sender<WorkerCompletion>,
    ) -> Result<(), ServiceError> {
        let mut buffer = Zeroizing::new([0_u8; OUTPUT_CHUNK_BYTES]);
        loop {
            let read = match reader.read(&mut buffer[..]).await {
                Ok(read) => read,
                Err(_) => {
                    let _ = control.try_send(WorkerCompletion::WorkerFailed);
                    return Ok(());
                }
            };
            if read == 0 {
                return Ok(());
            }
            if budget
                .as_ref()
                .is_some_and(|budget| output_budget_exceeded(budget, read))
            {
                let _ = control.try_send(WorkerCompletion::OutputLimit);
                return Ok(());
            }
            let bytes = buffer[..read].to_vec();
            buffer[..read].zeroize();
            if sender
                .send(OutboundItem::Output(WorkerOutput { stream, bytes }))
                .await
                .is_err()
            {
                return Ok(());
            }
        }
    }

    fn output_budget_exceeded(budget: &AtomicUsize, read: usize) -> bool {
        budget.fetch_add(read, Ordering::AcqRel) > MAX_WORKER_OUTPUT_BYTES.saturating_sub(read)
    }

    async fn write_worker_output<W: AsyncWrite + Unpin>(
        mut writer: W,
        request_id: [u8; 16],
        mut receiver: mpsc::Receiver<OutboundItem>,
        control: mpsc::Sender<WorkerCompletion>,
    ) -> Result<(), ServiceError> {
        let mut sequence = 0_u64;
        while let Some(item) = receiver.recv().await {
            let frame = match item {
                OutboundItem::Output(mut output) => {
                    let bytes = std::mem::take(&mut output.bytes);
                    let frame = BrokerFrame::Output {
                        request_id,
                        sequence,
                        stream: output.stream,
                        bytes,
                    };
                    sequence = sequence
                        .checked_add(1)
                        .ok_or(ProtocolError::InvalidRequest)?;
                    frame
                }
                OutboundItem::Frame(frame) => frame,
            };
            if let Err(error) = write_broker_frame(&mut writer, &frame).await {
                let _ = control.try_send(WorkerCompletion::WriterFailed);
                return Err(error.into());
            }
        }
        Ok(())
    }

    async fn read_client_input<R: AsyncRead + Unpin>(
        mut reader: R,
        request_id: [u8; 16],
        mut worker_stdin: Option<tokio::process::ChildStdin>,
        control: mpsc::Sender<WorkerCompletion>,
    ) {
        let duplex = worker_stdin.is_some();
        let mut expected_sequence = 0_u64;
        loop {
            let frame = match read_frame::<_, ClientFrame>(&mut reader).await {
                Ok(frame) => frame,
                Err(ProtocolError::Transport(_)) => {
                    let _ = control.try_send(WorkerCompletion::Disconnected);
                    return;
                }
                Err(_) => {
                    let _ = control.try_send(WorkerCompletion::InvalidRequest);
                    return;
                }
            };
            match frame {
                ClientFrame::Cancel { request_id: id } if id == request_id => {
                    let _ = control.try_send(WorkerCompletion::Cancelled);
                    return;
                }
                ClientFrame::Input(mut chunk)
                    if duplex
                        && chunk.request_id == request_id
                        && chunk.sequence == expected_sequence
                        && !chunk.bytes.is_empty()
                        && chunk.bytes.len() <= MAX_STREAM_CHUNK_BYTES
                        && worker_stdin.is_some() =>
                {
                    let result = tokio::time::timeout(
                        OUTPUT_WRITE_TIMEOUT,
                        worker_stdin
                            .as_mut()
                            .expect("checked worker stdin")
                            .write_all(&chunk.bytes),
                    )
                    .await;
                    chunk.bytes.zeroize();
                    if !matches!(result, Ok(Ok(()))) {
                        let _ = control.try_send(WorkerCompletion::WorkerFailed);
                        return;
                    }
                    let Some(next) = expected_sequence.checked_add(1) else {
                        let _ = control.try_send(WorkerCompletion::InvalidRequest);
                        return;
                    };
                    expected_sequence = next;
                }
                ClientFrame::InputClosed {
                    request_id: id,
                    sequence,
                } if duplex
                    && id == request_id
                    && sequence == expected_sequence
                    && worker_stdin.is_some() =>
                {
                    if !matches!(
                        tokio::time::timeout(
                            OUTPUT_WRITE_TIMEOUT,
                            worker_stdin
                                .as_mut()
                                .expect("checked worker stdin")
                                .shutdown(),
                        )
                        .await,
                        Ok(Ok(()))
                    ) {
                        let _ = control.try_send(WorkerCompletion::WorkerFailed);
                        return;
                    }
                    worker_stdin = None;
                }
                _ => {
                    let _ = control.try_send(WorkerCompletion::InvalidRequest);
                    return;
                }
            }
        }
    }

    async fn reject(
        pipe: &mut NamedPipeServer,
        request_id: Option<[u8; 16]>,
        code: RejectionCode,
    ) -> Result<(), ProtocolError> {
        write_broker_frame(pipe, &BrokerFrame::Rejected { request_id, code }).await
    }

    async fn write_broker_frame<W: AsyncWrite + Unpin>(
        pipe: &mut W,
        frame: &BrokerFrame,
    ) -> Result<(), ProtocolError> {
        tokio::time::timeout(OUTPUT_WRITE_TIMEOUT, write_frame(pipe, frame))
            .await
            .map_err(|_| {
                ProtocolError::Transport(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "broker output write timed out",
                ))
            })?
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

    fn rejection_for_service(error: &ServiceError) -> RejectionCode {
        match error {
            ServiceError::Protocol(error) => rejection_for(error),
            _ => RejectionCode::WorkerUnavailable,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::atomic::AtomicUsize;

        use palladin_platform::broker_protocol::{
            BrokerFrame, ClientFrame, OutputStream, read_frame, write_frame,
        };
        use tokio::io::AsyncWriteExt;
        use tokio::sync::mpsc;

        use super::{
            MAX_WORKER_OUTPUT_BYTES, MCP_SESSION_TIMEOUT, ONE_SHOT_SESSION_TIMEOUT, OutboundItem,
            WorkerCompletion, WorkerOutput, output_budget_exceeded, read_client_input,
            write_worker_output,
        };

        #[test]
        fn stdout_and_stderr_share_one_output_budget() {
            let budget = AtomicUsize::new(0);
            assert!(!output_budget_exceeded(
                &budget,
                MAX_WORKER_OUTPUT_BYTES / 2
            ));
            assert!(!output_budget_exceeded(
                &budget,
                MAX_WORKER_OUTPUT_BYTES / 2
            ));
            assert!(output_budget_exceeded(&budget, 1));
        }

        #[test]
        fn secure_sessions_have_explicit_absolute_ttls() {
            assert_eq!(ONE_SHOT_SESSION_TIMEOUT.as_secs(), 30 * 60);
            assert_eq!(MCP_SESSION_TIMEOUT.as_secs(), 30 * 60);
        }

        #[tokio::test]
        async fn fragmented_cancel_frame_is_read_by_one_persistent_owner() {
            let request_id = [9; 16];
            let mut encoded = Vec::new();
            write_frame(&mut encoded, &ClientFrame::Cancel { request_id })
                .await
                .expect("encode");
            let (reader, mut writer) = tokio::io::duplex(256);
            let (control, mut events) = mpsc::channel(1);
            let input = tokio::spawn(read_client_input(reader, request_id, None, control));
            for byte in encoded {
                writer.write_all(&[byte]).await.expect("fragment");
                tokio::task::yield_now().await;
            }
            assert!(matches!(
                events.recv().await,
                Some(WorkerCompletion::Cancelled)
            ));
            input.await.expect("input reader");
        }

        #[tokio::test]
        async fn worker_output_is_live_ordered_and_terminal_frame_is_last() {
            let request_id = [5; 16];
            let (writer, mut reader) = tokio::io::duplex(4096);
            let (output, receiver) = mpsc::channel(4);
            let (control, _events) = mpsc::channel(1);
            let task = tokio::spawn(write_worker_output(writer, request_id, receiver, control));
            output
                .send(OutboundItem::Output(WorkerOutput {
                    stream: OutputStream::StandardOutput,
                    bytes: b"first".to_vec(),
                }))
                .await
                .expect("stdout");
            output
                .send(OutboundItem::Output(WorkerOutput {
                    stream: OutputStream::StandardError,
                    bytes: b"second".to_vec(),
                }))
                .await
                .expect("stderr");
            output
                .send(OutboundItem::Frame(BrokerFrame::Exited {
                    request_id,
                    exit_code: 0,
                }))
                .await
                .expect("terminal");
            drop(output);

            let first: BrokerFrame = read_frame(&mut reader).await.expect("first frame");
            let second: BrokerFrame = read_frame(&mut reader).await.expect("second frame");
            let terminal: BrokerFrame = read_frame(&mut reader).await.expect("terminal frame");
            assert!(matches!(
                first,
                BrokerFrame::Output {
                    sequence: 0,
                    stream: OutputStream::StandardOutput,
                    ..
                }
            ));
            assert!(matches!(
                second,
                BrokerFrame::Output {
                    sequence: 1,
                    stream: OutputStream::StandardError,
                    ..
                }
            ));
            assert!(matches!(terminal, BrokerFrame::Exited { exit_code: 0, .. }));
            task.await.expect("writer task").expect("writer");
        }
    }
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    windows_service_entry::dispatch()
}
