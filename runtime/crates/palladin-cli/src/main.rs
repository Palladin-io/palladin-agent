#![forbid(unsafe_code)]

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process::ExitCode;

use clap::Parser;
use palladin_api::{CredentialMethod, ReportCredentialStaleInput, StaleReasonCode};
use palladin_cli::args::{
    AgentsCommand, Cli, Commands, ConnectArgs, ExecArgs, GetArgs, McpCommand, ProgressArg,
    ReportStaleArgs, SearchArgs, SecurityCommand, StaleCodeArg,
};
use palladin_cli::output::{
    CredentialOutput, FieldValueOutput, RenderedOutput, TotpOutput, render_agent_action,
    render_agent_list, render_connect, render_init, render_legacy_cleanup, render_legacy_cutover,
    render_profile_created, render_report_stale, render_search_human, render_security_upgrade,
    render_status,
};
use palladin_cli::{
    CredentialDelivery, CredentialDeliveryRequest, CredentialExecOutcome, CredentialExecRequest,
    OperatorOutput, RuntimeError, RuntimeService, safe_terminal_text,
};
use palladin_core::environment::{EnvironmentReport, EnvironmentRequirement, enforce_environment};
use palladin_core::host::ApiHost;
use palladin_core::legacy_typescript::{LegacyTypeScriptRepository, LegacyTypeScriptStatus};
use palladin_core::panic::install_redacted_panic_hook;
use palladin_core::profiles::ProfileRepository;
use palladin_core::secret::OrganizationApiKey;
use palladin_core::terminal::is_safe_terminal_text;
use palladin_credential::access::{access_message, exit_code_for_access};
use palladin_credential::fields::{FieldSelector, redact_totp_secrets, resolve_field};
use palladin_credential::secret::parse_secret;
use palladin_credential::wait::{
    ProgressMode, WaitOptions, heartbeat_line, parse_duration, signal_cancellation_token,
};
#[cfg(target_os = "linux")]
use palladin_linux_broker::store::LinuxBrokerSecretStore;
use palladin_platform::legacy_typescript_store::{
    LegacyCredentialError, OsLegacyCredentialDeleter, delete_legacy_typescript_credentials,
};
use palladin_platform::secure_store::{
    NativeSecretStore, SecretSlot, SecretStore, StoreError, storage_tier_description,
};
#[cfg(windows)]
use palladin_windows_broker::BrokerSecretStore;
use secrecy::ExposeSecret;
use serde::Serialize;
use zeroize::Zeroizing;

const EXIT_FAILURE: u8 = 1;
const EXIT_UNSAFE_ENVIRONMENT: u8 = 78;
#[cfg(windows)]
const WINDOWS_HARDENED_TIER: &str = "Hardened - restricted LocalService service-SID broker with authenticated AppContainer and Windows Hello consent";
#[cfg(target_os = "linux")]
const LINUX_HARDENED_TIER: &str = "Hardened - dedicated Agent UID, authenticated Unix broker, encrypted broker-owned store, and separate executor UID";
const INJECT_UNAVAILABLE: &str = "browser injection is disabled because an unauthenticated CDP endpoint can spoof the page origin and receive plaintext; Palladin will enable inject only through a reviewed authenticated browser boundary; no profile was opened and no credential was requested";

#[tokio::main]
async fn main() -> ExitCode {
    install_redacted_panic_hook();
    let hardened_worker_root = match hardened_worker_root() {
        Ok(root) => root,
        Err(error) => return fail(&error),
    };
    if argv_contains_api_key() {
        return fail(
            "API keys are forbidden in argv; use a masked prompt or connect --api-key-stdin",
        );
    }
    if deprecated_connect_id_usage() {
        return fail(
            "connect --id no longer sets the backend display name; use connect --name <name>. To select a local profile, place --id <profile> before connect",
        );
    }
    if argv_contains_unsafe_terminal_text() {
        return fail("command-line arguments contain unsupported control characters");
    }
    let environment = EnvironmentReport::inspect_current();
    let cli = Cli::parse();

    if matches!(&cli.command, Commands::Inject(_)) {
        eprintln!("Error: {INJECT_UNAVAILABLE}");
        return ExitCode::from(EXIT_UNSAFE_ENVIRONMENT);
    }

    if enforce_environment(environment_requirement(&cli.command), &environment).is_err() {
        print_unsafe_environment(&environment, matches!(cli.command, Commands::Mcp { .. }));
        return ExitCode::from(EXIT_UNSAFE_ENVIRONMENT);
    }

    if let Commands::VerifyReleasePolicy { policy } = &cli.command {
        return match palladin_runtime::version_policy::verify_release_policy_file(
            policy,
            env!("CARGO_PKG_VERSION"),
        ) {
            Ok(()) => {
                println!("Release policy verified.");
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.to_string()),
        };
    }

    let hardened_runtime = hardened_worker_root.is_some();
    let secret_store = match runtime_secret_store(hardened_worker_root.as_deref()) {
        Ok(store) => store,
        Err(error) => return fail(&error.to_string()),
    };
    let runtime_storage_tier = hardened_tier_description(hardened_worker_root.is_some());

    let root = match hardened_worker_root {
        Some(root) => root,
        None => match palladin_platform::palladin_root() {
            Ok(root) => root,
            Err(error) => return fail(&error.to_string()),
        },
    };
    let repository = match ProfileRepository::new(root) {
        Ok(repository) => repository,
        Err(error) => return fail(&error.to_string()),
    };
    let service = RuntimeService::new(repository, secret_store);

    if !matches!(
        &cli.command,
        Commands::Doctor
            | Commands::Disconnect { .. }
            | Commands::Purge { .. }
            | Commands::Security {
                command: SecurityCommand::LegacyStatus
                    | SecurityCommand::LegacyCutover { .. }
                    | SecurityCommand::LegacyCleanup { .. }
            }
    ) {
        if palladin_runtime::version_policy::system_version_policy_configured() {
            if let Err(error) = service.prepare_empty_state_for_version_policy() {
                return fail(&error.to_string());
            }
            if let Err(error) = service
                .enforce_system_version_policy(env!("CARGO_PKG_VERSION"))
                .await
            {
                return fail(&error.to_string());
            }
        } else if !cfg!(debug_assertions) {
            return fail(&RuntimeError::VersionPolicyNotConfigured.to_string());
        }
    }

    match cli.command {
        Commands::Init { force } => init(&service, cli.id.as_deref(), force, runtime_storage_tier),
        Commands::VerifyReleasePolicy { .. } => unreachable!("release verification exits early"),
        Commands::Doctor => doctor(
            &environment,
            &service,
            runtime_storage_tier,
            hardened_runtime,
        ),
        Commands::Connect(args) => {
            connect(&service, cli.id.as_deref(), args, runtime_storage_tier).await
        }
        Commands::Status => status(&service, cli.id.as_deref(), runtime_storage_tier).await,
        Commands::Disconnect { purge, confirm } => disconnect(
            &service,
            cli.id.as_deref(),
            purge,
            confirm,
            hardened_runtime,
        ),
        Commands::Search(args) => search(&service, cli.id.as_deref(), args).await,
        Commands::Get(args) => get(&service, cli.id.as_deref(), args).await,
        Commands::Exec(args) => exec(&service, cli.id.as_deref(), args).await,
        Commands::Inject(_) => unreachable!("inject exits before identity initialization"),
        Commands::ReportStale(args) => report_stale(&service, cli.id.as_deref(), args).await,
        Commands::Mcp { command } => mcp(&service, cli.id.as_deref(), command).await,
        Commands::Agents { command } => agents(&service, command, runtime_storage_tier),
        Commands::Security { command } => security(
            &service,
            cli.id.as_deref(),
            command,
            runtime_storage_tier,
            hardened_runtime,
        ),
        Commands::Purge { confirm } => purge(&service, confirm, hardened_runtime),
    }
}

enum RuntimeSecretStore {
    Convenience(NativeSecretStore),
    #[cfg(windows)]
    Hardened(BrokerSecretStore),
    #[cfg(target_os = "linux")]
    LinuxHardened(LinuxBrokerSecretStore),
}

impl SecretStore for RuntimeSecretStore {
    fn get(
        &self,
        owner_id: &str,
        slot: SecretSlot,
    ) -> Result<Option<secrecy::SecretSlice<u8>>, StoreError> {
        match self {
            Self::Convenience(store) => store.get(owner_id, slot),
            #[cfg(windows)]
            Self::Hardened(store) => store.get(owner_id, slot),
            #[cfg(target_os = "linux")]
            Self::LinuxHardened(store) => store.get(owner_id, slot),
        }
    }

    fn set(&self, owner_id: &str, slot: SecretSlot, secret: &[u8]) -> Result<(), StoreError> {
        match self {
            Self::Convenience(store) => store.set(owner_id, slot, secret),
            #[cfg(windows)]
            Self::Hardened(store) => store.set(owner_id, slot, secret),
            #[cfg(target_os = "linux")]
            Self::LinuxHardened(store) => store.set(owner_id, slot, secret),
        }
    }

    fn delete(&self, owner_id: &str, slot: SecretSlot) -> Result<(), StoreError> {
        match self {
            Self::Convenience(store) => store.delete(owner_id, slot),
            #[cfg(windows)]
            Self::Hardened(store) => store.delete(owner_id, slot),
            #[cfg(target_os = "linux")]
            Self::LinuxHardened(store) => store.delete(owner_id, slot),
        }
    }
}

#[cfg(windows)]
fn runtime_secret_store(
    hardened_root: Option<&std::path::Path>,
) -> Result<RuntimeSecretStore, StoreError> {
    hardened_root.map_or_else(
        || Ok(RuntimeSecretStore::Convenience(NativeSecretStore::default())),
        |root| BrokerSecretStore::new(root).map(RuntimeSecretStore::Hardened),
    )
}

#[cfg(target_os = "macos")]
fn runtime_secret_store(
    _hardened_root: Option<&std::path::Path>,
) -> Result<RuntimeSecretStore, StoreError> {
    Ok(RuntimeSecretStore::Convenience(NativeSecretStore::default()))
}

#[cfg(target_os = "linux")]
fn runtime_secret_store(
    hardened_root: Option<&std::path::Path>,
) -> Result<RuntimeSecretStore, StoreError> {
    hardened_root.map_or_else(
        || Ok(RuntimeSecretStore::Convenience(NativeSecretStore::default())),
        |root| {
            LinuxBrokerSecretStore::new(
                root,
                std::path::Path::new("/var/lib/palladin-runtime/v1/master.key"),
            )
            .map(RuntimeSecretStore::LinuxHardened)
        },
    )
}

#[cfg(windows)]
fn hardened_windows_worker_root() -> Result<Option<std::path::PathBuf>, String> {
    use std::path::PathBuf;

    let executable = std::env::current_exe()
        .map_err(|_| "the Windows runtime executable path is unavailable".to_owned())?;
    if executable.file_name().and_then(|name| name.to_str()) != Some("palladin-worker.exe") {
        return Ok(None);
    }
    palladin_windows_broker::attest_service_identity().map_err(|error| error.to_string())?;
    let root = std::env::var_os("PALLADIN_BROKER_ROOT")
        .map(PathBuf::from)
        .ok_or_else(|| "the broker-owned runtime root is unavailable".to_owned())?;
    let program_data =
        palladin_windows_broker::program_data_path().map_err(|error| error.to_string())?;
    let caller_sid = root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "the broker-owned runtime root is invalid".to_owned())?;
    let expected = palladin_windows_broker::broker_profile_root(&program_data, caller_sid)
        .map_err(|error| error.to_string())?;
    if root != expected {
        return Err("the broker-owned runtime root is invalid".to_owned());
    }
    Ok(Some(root))
}

fn hardened_worker_root() -> Result<Option<std::path::PathBuf>, String> {
    #[cfg(windows)]
    {
        hardened_windows_worker_root()
    }
    #[cfg(target_os = "linux")]
    {
        hardened_linux_worker_root()
    }
    #[cfg(target_os = "macos")]
    {
        Ok(None)
    }
}

fn hardened_tier_description(hardened: bool) -> &'static str {
    if !hardened {
        return storage_tier_description();
    }
    #[cfg(windows)]
    {
        WINDOWS_HARDENED_TIER
    }
    #[cfg(target_os = "linux")]
    {
        LINUX_HARDENED_TIER
    }
    #[cfg(target_os = "macos")]
    {
        storage_tier_description()
    }
}

#[cfg(target_os = "linux")]
fn hardened_linux_worker_root() -> Result<Option<std::path::PathBuf>, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    if std::env::var_os("PALLADIN_LINUX_HARDENED").is_none() {
        return Ok(None);
    }
    if std::env::var("PALLADIN_LINUX_HARDENED").as_deref() != Ok("1") {
        return Err("the Linux Hardened worker marker is invalid".to_owned());
    }
    let executable = std::fs::canonicalize(
        std::env::current_exe()
            .map_err(|_| "the Linux runtime executable path is unavailable".to_owned())?,
    )
    .map_err(|_| "the Linux runtime executable path is unavailable".to_owned())?;
    if executable != Path::new(palladin_linux_broker::SYSTEM_WORKER) {
        return Err("the Linux Hardened worker executable is invalid".to_owned());
    }
    let executable_metadata = std::fs::symlink_metadata(&executable)
        .map_err(|_| "the Linux Hardened worker executable is unavailable".to_owned())?;
    if executable_metadata.uid() != 0
        || executable_metadata.permissions().mode() & 0o022 != 0
        || executable_metadata.nlink() != 1
    {
        return Err("the Linux Hardened worker executable permissions are invalid".to_owned());
    }
    if nix::unistd::geteuid().is_root() || nix::unistd::geteuid() != nix::unistd::getuid() {
        return Err("the Linux Hardened worker UID is invalid".to_owned());
    }
    // The broker is deliberately non-dumpable, so its child cannot inspect the
    // parent's /proc executable link. The effective UID and broker-owned 0700
    // principal root are the enforceable boundary: a process that already has
    // the broker UID can already read the master key and is in the same trust
    // domain, while every Agent UID fails the ownership check below.
    let root = std::env::var_os("PALLADIN_LINUX_BROKER_ROOT")
        .map(PathBuf::from)
        .ok_or_else(|| "the Linux broker-owned runtime root is unavailable".to_owned())?;
    let principals_root = Path::new(palladin_linux_broker::STATE_ROOT).join("agents");
    let relative = root
        .strip_prefix(&principals_root)
        .map_err(|_| "the Linux broker-owned runtime root is invalid".to_owned())?;
    let valid_principal = relative.to_str().is_some_and(|value| {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if relative.components().count() != 1 || !valid_principal {
        return Err("the Linux broker-owned runtime root is invalid".to_owned());
    }
    let root_metadata = std::fs::symlink_metadata(&root)
        .map_err(|_| "the Linux broker-owned runtime root is unavailable".to_owned())?;
    if !root_metadata.file_type().is_dir()
        || root_metadata.file_type().is_symlink()
        || root_metadata.uid() != nix::unistd::geteuid().as_raw()
        || root_metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err("the Linux broker-owned runtime root permissions are invalid".to_owned());
    }
    Ok(Some(root))
}

const fn environment_requirement(command: &Commands) -> EnvironmentRequirement {
    match command {
        Commands::Doctor
        | Commands::VerifyReleasePolicy { .. }
        | Commands::Security {
            command: SecurityCommand::LegacyStatus,
        } => EnvironmentRequirement::DiagnosticOnly,
        Commands::Init { .. }
        | Commands::Connect(_)
        | Commands::Status
        | Commands::Disconnect { .. }
        | Commands::Search(_)
        | Commands::Get(_)
        | Commands::Exec(_)
        | Commands::Inject(_)
        | Commands::ReportStale(_)
        | Commands::Mcp { .. }
        | Commands::Agents { .. }
        | Commands::Security {
            command:
                SecurityCommand::Upgrade
                | SecurityCommand::LegacyCutover { .. }
                | SecurityCommand::LegacyCleanup { .. },
        }
        | Commands::Purge { .. } => EnvironmentRequirement::Clean,
    }
}

async fn mcp(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    command: McpCommand,
) -> ExitCode {
    match command {
        McpCommand::Serve => {
            let hostname = match operating_system_hostname() {
                Ok(hostname) => hostname,
                Err(error) => return fail(error),
            };
            let session = match service.open_session(profile, &hostname) {
                Ok(session) => session,
                Err(error) => return fail(&error.to_string()),
            };
            let server = match palladin_mcp::native_server(session) {
                Ok(server) => server,
                Err(error) => return fail(&error.to_string()),
            };
            match palladin_mcp::serve_stdio(server).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error.to_string()),
            }
        }
    }
}

fn init(
    service: &RuntimeService<RuntimeSecretStore>,
    profile_name: Option<&str>,
    force: bool,
    runtime_storage_tier: &str,
) -> ExitCode {
    if force {
        return fail(
            "in-place identity rotation is disabled; create a new profile with palladin agents create <name>",
        );
    }
    let registry = match service.registry() {
        Ok(registry) => registry,
        Err(error) => return fail(&error.to_string()),
    };
    let profile_name = profile_name.unwrap_or("default");
    if registry
        .agents
        .iter()
        .any(|profile| profile.name == profile_name)
    {
        let profile = match service.verify_identity(Some(profile_name)) {
            Ok(profile) => profile,
            Err(error) => return fail(&error.to_string()),
        };
        return emit_output(render_init(
            &profile.name,
            runtime_storage_tier,
            true,
            profile.name == registry.default,
        ));
    }
    match service.create_profile(profile_name, None) {
        Ok(profile) => {
            let is_default = profile.name == registry.default || registry.agents.is_empty();
            emit_output(render_init(
                &profile.name,
                runtime_storage_tier,
                false,
                is_default,
            ))
        }
        Err(error) => fail(&error.to_string()),
    }
}

fn doctor(
    environment: &EnvironmentReport,
    service: &RuntimeService<RuntimeSecretStore>,
    runtime_storage_tier: &str,
    hardened_runtime: bool,
) -> ExitCode {
    let platform = palladin_platform::current();
    println!("Palladin Runtime Doctor");
    println!("version: {}", env!("CARGO_PKG_VERSION"));
    println!(
        "platform: {}/{}",
        platform.operating_system, platform.architecture
    );
    println!(
        "standalone-security-tier: {}",
        if runtime_storage_tier.starts_with("Hardened -") {
            "Hardened"
        } else {
            platform.standalone_tier
        }
    );
    println!("storage-boundary: {runtime_storage_tier}");
    println!("hardened-candidate: {}", platform.hardened_candidate);
    println!("identity-opened: no");
    println!("project-runtime-dependencies: disabled");
    println!("palladin-home-override: rejected");
    let legacy_status = if hardened_runtime {
        None
    } else {
        Some(
            LegacyTypeScriptRepository::new(service.repository().root())
                .and_then(|repository| repository.status()),
        )
    };
    match legacy_status {
        None => println!(
            "legacy-typescript: unavailable in hardened worker - inspect the OS-account convenience runtime"
        ),
        Some(Ok(LegacyTypeScriptStatus::Clear)) => println!("legacy-typescript: not-detected"),
        Some(Ok(LegacyTypeScriptStatus::Detected {
            source_directory,
            profiles,
            file_fallback,
        })) => {
            println!(
                "legacy-typescript: detected - root={source_directory}, profiles={profiles}, file-fallback={file_fallback}"
            );
            println!(
                "legacy-keychain: candidate records detected from exact profile metadata - secret bytes were not opened"
            );
            println!(
                "legacy-next: palladin security legacy-cutover --confirm-pre-production-reset"
            );
        }
        Some(Ok(LegacyTypeScriptStatus::CutoverPending(manifest))) => {
            println!(
                "legacy-typescript: cutover-pending - profiles={}, cutover-id={}",
                manifest.profiles.len(),
                manifest.cutover_id
            );
            println!("legacy-next: connect and approve every fresh Agent, then run cleanup");
        }
        Some(Err(error)) => {
            println!("legacy-typescript: indeterminate - {error}");
        }
    }
    let legacy_environment_names = environment
        .dangerous_names()
        .iter()
        .filter(|name| {
            name.starts_with("PALLADIN_PRIVATE_KEY")
                || name.starts_with("PALLADIN_SIGNING_KEY")
                || name.starts_with("CLAW_VAULT_PRIVATE_KEY")
                || name.starts_with("CLAW_VAULT_SIGNING_KEY")
                || matches!(name.as_str(), "PALLADIN_HOME" | "CLAW_VAULT_HOME")
        })
        .cloned()
        .collect::<Vec<_>>();
    if legacy_environment_names.is_empty() {
        println!("legacy-environment: not-detected");
    } else {
        println!(
            "legacy-environment: detected - unset names: {}",
            legacy_environment_names.join(", ")
        );
    }
    println!(
        "cleanup-recovery: {}",
        if service.repository().cleanup_pending() {
            "pending - run any identity command or palladin purge --confirm to retry"
        } else {
            "clear"
        }
    );

    if environment.is_safe() {
        println!("environment: safe");
        ExitCode::SUCCESS
    } else {
        println!("environment: unsafe");
        print_unsafe_environment(environment, false);
        ExitCode::from(EXIT_UNSAFE_ENVIRONMENT)
    }
}

async fn connect(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    args: ConnectArgs,
    runtime_storage_tier: &str,
) -> ExitCode {
    let api_key = match read_api_key(args.api_key_stdin) {
        Ok(api_key) => api_key,
        Err(error) => return fail(&error),
    };
    let host = match ApiHost::parse(&args.host) {
        Ok(host) => host,
        Err(error) => return fail(&error.to_string()),
    };
    let hostname = match hostname::get() {
        Ok(hostname) => hostname.to_string_lossy().into_owned(),
        Err(_) => return fail("the operating-system hostname is unavailable"),
    };
    let outcome = match service
        .connect(
            profile,
            api_key,
            host,
            args.name.as_deref(),
            args.r#type.as_deref(),
            &hostname,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => return fail(&error.to_string()),
    };

    emit_output(render_connect(
        &outcome.registration,
        outcome.config_saved,
        runtime_storage_tier,
    ))
}

async fn status(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    runtime_storage_tier: &str,
) -> ExitCode {
    let hostname = match hostname::get() {
        Ok(hostname) => hostname.to_string_lossy().into_owned(),
        Err(_) => return fail("the operating-system hostname is unavailable"),
    };
    let outcome = match service.status(profile, &hostname).await {
        Ok(outcome) => outcome,
        Err(error) => return fail(&error.to_string()),
    };
    emit_output(render_status(
        &outcome.profile.name,
        &outcome.config.host,
        &outcome.registration,
        runtime_storage_tier,
    ))
}

async fn search(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    args: SearchArgs,
) -> ExitCode {
    let query = args.query.trim();
    if query.chars().count() < 2 {
        return fail("search query must contain at least two characters");
    }
    let hostname = match operating_system_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return fail(error),
    };
    let session = match service.open_session(profile, &hostname) {
        Ok(session) => session,
        Err(error) => return fail(&error.to_string()),
    };
    let result = match session
        .search_entries(query, args.cursor.as_deref(), args.page_size)
        .await
    {
        Ok(result) => result,
        Err(error) => return fail(&error.to_string()),
    };
    if args.json {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        if serde_json::to_writer_pretty(&mut output, &result).is_err()
            || output.write_all(b"\n").is_err()
        {
            return fail("could not write search results to standard output");
        }
        return ExitCode::SUCCESS;
    }
    emit_output(render_search_human(&result))
}

async fn get(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    args: GetArgs,
) -> ExitCode {
    let wait_ms = if args.no_wait {
        Some(0)
    } else {
        match args.wait.as_deref().map(parse_duration).transpose() {
            Ok(value) => value,
            Err(error) => return fail(&error.to_string()),
        }
    };
    let poll_ms = match args
        .poll_interval
        .as_deref()
        .map(parse_duration)
        .transpose()
    {
        Ok(value) => value,
        Err(error) => return fail(&error.to_string()),
    };
    let hostname = match operating_system_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return fail(error),
    };
    let session = match service.open_session(profile, &hostname) {
        Ok(session) => session,
        Err(error) => return fail(&error.to_string()),
    };
    let progress = args.progress.map(|value| match value {
        ProgressArg::Plain => ProgressMode::Plain,
        ProgressArg::Json => ProgressMode::Json,
        ProgressArg::None => ProgressMode::None,
    });
    let wait = WaitOptions {
        wait_ms,
        poll_ms,
        progress,
    };
    let cancellation = signal_cancellation_token();
    let delivery = match session
        .deliver_for_get(
            CredentialDeliveryRequest {
                vault_id: &args.vault_id,
                entry_id: &args.entry_id,
                reason: args.reason.as_deref(),
                wait,
            },
            &cancellation,
            |heartbeat| {
                if let Some(line) = heartbeat_line(progress.unwrap_or_default(), &heartbeat) {
                    eprint!("{line}");
                }
            },
        )
        .await
    {
        Ok(delivery) => delivery,
        Err(error) => return fail(&error.to_string()),
    };
    let credential = match delivery {
        CredentialDelivery::Granted(credential) => credential,
        CredentialDelivery::NotGranted(access) => {
            if let Some(message) = access_message(&access, CredentialMethod::Get) {
                eprintln!("Error: {}", safe_terminal_text(&message));
            }
            return ExitCode::from(exit_code_for_access(&access));
        }
    };
    let selector = FieldSelector {
        field: args.field,
        field_id: args.field_id,
    };
    if selector.field.is_some() || selector.field_id.is_some() {
        let parsed = match parse_secret(credential.expose_for_authorized_operation()) {
            Ok(parsed) => parsed,
            Err(error) => return fail(&error.to_string()),
        };
        let selected = match resolve_field(&parsed, &selector) {
            Ok(selected) => selected,
            Err(error) => return fail(&error.to_string()),
        };
        let result = match &selected {
            palladin_credential::fields::ResolvedField::Value {
                label: field,
                value,
                ..
            } => write_secret_json(&FieldValueOutput {
                entry_id: &credential.entry_id,
                label: &credential.label,
                field,
                value: value.expose_secret(),
            }),
            palladin_credential::fields::ResolvedField::Totp {
                label: field,
                code,
                expires_in,
            } => write_secret_json(&TotpOutput {
                entry_id: &credential.entry_id,
                label: &credential.label,
                field,
                code: code.expose_secret(),
                expires_in: *expires_in,
            }),
        };
        return emit_get_warning(args.quiet, result);
    }
    let unix_seconds = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(0);
    let output =
        match redact_totp_secrets(credential.expose_for_authorized_operation(), unix_seconds) {
            Ok(output) => output,
            Err(error) => return fail(&error.to_string()),
        };
    let result = write_secret_json(&CredentialOutput {
        entry_id: &credential.entry_id,
        label: &credential.label,
        secret: output.expose_secret(),
    });
    emit_get_warning(args.quiet, result)
}

async fn exec(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    args: ExecArgs,
) -> ExitCode {
    let wait_ms = if args.no_wait {
        Some(0)
    } else {
        match args.wait.as_deref().map(parse_duration).transpose() {
            Ok(value) => value,
            Err(error) => return fail(&error.to_string()),
        }
    };
    let poll_ms = match args
        .poll_interval
        .as_deref()
        .map(parse_duration)
        .transpose()
    {
        Ok(value) => value,
        Err(error) => return fail(&error.to_string()),
    };
    let hostname = match operating_system_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return fail(error),
    };
    let session = match service.open_session(profile, &hostname) {
        Ok(session) => session,
        Err(error) => return fail(&error.to_string()),
    };
    let progress = args.progress.map(|value| match value {
        ProgressArg::Plain => ProgressMode::Plain,
        ProgressArg::Json => ProgressMode::Json,
        ProgressArg::None => ProgressMode::None,
    });
    let cancellation = signal_cancellation_token();
    let outcome = session
        .execute_with_credential(
            CredentialExecRequest {
                delivery: CredentialDeliveryRequest {
                    vault_id: &args.vault_id,
                    entry_id: &args.entry_id,
                    reason: args.reason.as_deref(),
                    wait: WaitOptions {
                        wait_ms,
                        poll_ms,
                        progress,
                    },
                },
                command: Some(&args.command),
                env_mappings: &args.env_mappings,
                output: OperatorOutput::Terminal,
            },
            &cancellation,
            |heartbeat| {
                if let Some(line) = heartbeat_line(progress.unwrap_or_default(), &heartbeat) {
                    eprint!("{line}");
                }
            },
        )
        .await;
    match outcome {
        Ok(CredentialExecOutcome::Completed(result)) => {
            if result.cancelled {
                ExitCode::from(130)
            } else {
                ExitCode::from(u8::try_from(result.exit_code).unwrap_or(EXIT_FAILURE))
            }
        }
        Ok(CredentialExecOutcome::NotGranted(access)) => {
            if let Some(message) = access_message(&access, CredentialMethod::Exec) {
                eprintln!("Error: {}", safe_terminal_text(&message));
            }
            ExitCode::from(exit_code_for_access(&access))
        }
        Err(error) => fail(&error.to_string()),
    }
}

async fn report_stale(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    args: ReportStaleArgs,
) -> ExitCode {
    let hostname = match operating_system_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return fail(error),
    };
    let session = match service.open_session(profile, &hostname) {
        Ok(session) => session,
        Err(error) => return fail(&error.to_string()),
    };
    let code = match args.code {
        StaleCodeArg::LoginRejected => StaleReasonCode::LoginRejected,
        StaleCodeArg::AuthFailed => StaleReasonCode::AuthFailed,
        StaleCodeArg::Manual => StaleReasonCode::Manual,
    };
    let note = args.note.and_then(|note| {
        let note = note.trim();
        (!note.is_empty()).then(|| note.to_owned())
    });
    let input = ReportCredentialStaleInput {
        vault_id: args.vault_id.trim().to_owned(),
        entry_id: args.entry_id.trim().to_owned(),
        code,
        note,
    };
    match session.report_credential_stale(&input).await {
        Ok(()) => emit_output(render_report_stale()),
        Err(error) => fail(&error.to_string()),
    }
}

fn agents(
    service: &RuntimeService<RuntimeSecretStore>,
    command: AgentsCommand,
    runtime_storage_tier: &str,
) -> ExitCode {
    match agents_result(service, command, runtime_storage_tier) {
        Ok(output) => emit_output(output),
        Err(error) => fail(&error.to_string()),
    }
}

fn security(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    command: SecurityCommand,
    runtime_storage_tier: &str,
    hardened_runtime: bool,
) -> ExitCode {
    match command {
        SecurityCommand::Upgrade => match service.upgrade_security(profile) {
            Ok(outcome) => emit_output(render_security_upgrade(
                &outcome.profile.name,
                runtime_storage_tier,
                outcome.migrated,
            )),
            Err(error) => fail(&error.to_string()),
        },
        SecurityCommand::LegacyStatus => legacy_status(service, hardened_runtime),
        SecurityCommand::LegacyCutover {
            confirm_pre_production_reset,
        } => {
            if hardened_runtime {
                return fail(
                    "legacy cutover must run in the OS-account convenience runtime before hardened broker enrollment",
                );
            }
            if !cfg!(debug_assertions) {
                return fail("legacy cutover is available only in pre-production/dev builds");
            }
            match service.cutover_legacy_typescript(confirm_pre_production_reset) {
                Ok(outcome) => emit_output(render_legacy_cutover(&outcome)),
                Err(error) => fail(&error.to_string()),
            }
        }
        SecurityCommand::LegacyCleanup {
            cutover_id,
            confirm,
        } => {
            if hardened_runtime {
                return fail(
                    "legacy cleanup must run in the OS-account convenience runtime before hardened broker enrollment",
                );
            }
            if !cfg!(debug_assertions) {
                return fail("legacy cleanup is available only in pre-production/dev builds");
            }
            let deleter = OsLegacyCredentialDeleter;
            match service.cleanup_legacy_typescript(confirm, &cutover_id, |profile| {
                delete_legacy_typescript_credentials(&deleter, profile).map_err(|error| match error
                {
                    LegacyCredentialError::InvalidProfile => StoreError::InvalidOwner,
                    LegacyCredentialError::Unavailable => StoreError::Unavailable,
                })
            }) {
                Ok(outcome) => emit_output(render_legacy_cleanup(&outcome)),
                Err(error) => fail(&error.to_string()),
            }
        }
    }
}

fn legacy_status(service: &RuntimeService<RuntimeSecretStore>, hardened_runtime: bool) -> ExitCode {
    if hardened_runtime {
        return fail(
            "inspect legacy TypeScript state in the OS-account convenience runtime before hardened broker enrollment",
        );
    }
    let repository = match LegacyTypeScriptRepository::new(service.repository().root()) {
        Ok(repository) => repository,
        Err(error) => return fail(&error.to_string()),
    };
    match repository.status() {
        Ok(LegacyTypeScriptStatus::Clear) => {
            println!("Legacy TypeScript state: not detected");
            ExitCode::SUCCESS
        }
        Ok(LegacyTypeScriptStatus::Detected {
            source_directory,
            profiles,
            file_fallback,
        }) => {
            println!("Legacy TypeScript state: detected");
            println!("Root: {source_directory}");
            println!("Profiles: {profiles}");
            println!("Plaintext key fallback: {file_fallback}");
            println!("Next: palladin security legacy-cutover --confirm-pre-production-reset");
            ExitCode::SUCCESS
        }
        Ok(LegacyTypeScriptStatus::CutoverPending(manifest)) => {
            println!("Legacy TypeScript state: cutover pending");
            println!("Profiles: {}", manifest.profiles.len());
            println!("Cutover ID: {}", manifest.cutover_id);
            println!("Next: connect and approve every fresh Agent, then run cleanup.");
            ExitCode::SUCCESS
        }
        Err(error) => fail(&format!(
            "legacy TypeScript state is indeterminate: {error}"
        )),
    }
}

fn agents_result(
    service: &RuntimeService<RuntimeSecretStore>,
    command: AgentsCommand,
    runtime_storage_tier: &str,
) -> Result<RenderedOutput, RuntimeError> {
    match command {
        AgentsCommand::List => {
            let registry = service.registry()?;
            Ok(render_agent_list(&registry))
        }
        AgentsCommand::Create { name, r#type } => {
            let created = service.create_profile(&name, r#type)?;
            Ok(render_profile_created(&created, runtime_storage_tier))
        }
        AgentsCommand::Delete { name } => {
            service.delete_profile(&name)?;
            Ok(render_agent_action("Agent profile deleted", &name))
        }
        AgentsCommand::SetDefault { name } => {
            service.set_default_profile(&name)?;
            Ok(render_agent_action("Default Agent profile", &name))
        }
        AgentsCommand::Rename { old_name, new_name } => {
            service.rename_profile(&old_name, &new_name)?;
            Ok(render_agent_action(
                "Agent profile renamed",
                &format!("{old_name} -> {new_name}"),
            ))
        }
    }
}

fn disconnect(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    purge: bool,
    confirm: bool,
    hardened_runtime: bool,
) -> ExitCode {
    if !purge || !confirm {
        return fail("disconnect requires --purge --confirm and is never run automatically");
    }
    if let Err(error) = ensure_workload_purge_allowed(hardened_runtime) {
        return fail(error);
    }
    match service.purge_profile(profile) {
        Ok(removed) => {
            println!("Local Palladin Agent identity '{}' purged.", removed.name);
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error.to_string()),
    }
}

fn purge(
    service: &RuntimeService<RuntimeSecretStore>,
    confirm: bool,
    hardened_runtime: bool,
) -> ExitCode {
    if !confirm {
        return fail("purge requires --confirm and is never run automatically");
    }
    if let Err(error) = ensure_workload_purge_allowed(hardened_runtime) {
        return fail(error);
    }
    if !hardened_runtime {
        let legacy_status = LegacyTypeScriptRepository::new(service.repository().root())
            .and_then(|repository| repository.status());
        match legacy_status {
            Ok(LegacyTypeScriptStatus::Clear) => {}
            Ok(_) => {
                return fail(
                    "complete or clean up the legacy TypeScript cutover before purging native profiles",
                );
            }
            Err(error) => return fail(&error.to_string()),
        }
    }
    match service.purge() {
        Ok(()) => {
            println!("Native Palladin profiles and secret slots purged.");
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error.to_string()),
    }
}

fn ensure_workload_purge_allowed(hardened_runtime: bool) -> Result<(), &'static str> {
    #[cfg(target_os = "linux")]
    if hardened_runtime {
        return Err(
            "purge is unavailable from a Linux Hardened workload; revoke the dedicated Agent UID through the root-owned administrative helper",
        );
    }
    #[cfg(not(target_os = "linux"))]
    let _ = hardened_runtime;
    Ok(())
}

fn read_api_key(from_stdin: bool) -> Result<OrganizationApiKey, String> {
    let mut value = Zeroizing::new(if from_stdin {
        if io::stdin().is_terminal() {
            return Err(
                "--api-key-stdin requires redirected standard input; use the masked prompt on a terminal"
                    .to_owned(),
            );
        }
        let mut input = Zeroizing::new(String::new());
        io::stdin()
            .lock()
            .take(4097)
            .read_line(&mut input)
            .map_err(|_| "could not read API key from standard input".to_owned())?;
        if input.len() > 4096 {
            return Err("API key input is too long".to_owned());
        }
        std::mem::take(&mut *input)
    } else {
        rpassword::prompt_password("Organization API key: ")
            .map_err(|_| "could not read API key from the masked prompt".to_owned())?
    });
    while value.ends_with(['\r', '\n']) {
        value.pop();
    }
    if !value.starts_with("pl_") {
        return Err("invalid API key - it must start with pl_".to_owned());
    }
    Ok(OrganizationApiKey::new(std::mem::take(&mut *value)))
}

fn argv_contains_api_key() -> bool {
    std::env::args_os()
        .skip(1)
        .any(|argument| os_argument_contains_api_key(&argument))
}

fn deprecated_connect_id_usage() -> bool {
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        let Some(argument) = argument.to_str() else {
            return false;
        };
        if argument == "--id" {
            let _profile_name = arguments.next();
            continue;
        }
        if argument.starts_with("--id=") {
            continue;
        }
        if argument != "connect" {
            return false;
        }
        return arguments.any(|argument| {
            argument
                .to_str()
                .is_some_and(|argument| argument == "--id" || argument.starts_with("--id="))
        });
    }
    false
}

fn argv_contains_unsafe_terminal_text() -> bool {
    std::env::args_os().skip(1).any(|argument| {
        argument
            .to_str()
            .is_none_or(|value| !is_safe_terminal_text(value))
    })
}

#[cfg(unix)]
fn os_argument_contains_api_key(argument: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    argument.as_bytes().windows(3).any(|value| value == b"pl_")
}

#[cfg(windows)]
fn os_argument_contains_api_key(argument: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;

    let value = argument.encode_wide().collect::<Vec<_>>();
    value
        .windows(3)
        .any(|value| value == ['p' as u16, 'l' as u16, '_' as u16])
}

fn fail(message: &str) -> ExitCode {
    eprintln!("Error: {}", safe_terminal_text(message));
    ExitCode::from(EXIT_FAILURE)
}

fn emit_output(output: RenderedOutput) -> ExitCode {
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprint!("{}", output.stderr);
    }
    ExitCode::from(output.exit_code)
}

fn operating_system_hostname() -> Result<String, &'static str> {
    hostname::get()
        .map(|hostname| hostname.to_string_lossy().into_owned())
        .map_err(|_| "the operating-system hostname is unavailable")
}

fn write_secret_json(value: &impl Serialize) -> ExitCode {
    let mut buffer = Zeroizing::new(Vec::new());
    if serde_json::to_writer_pretty(&mut *buffer, value).is_err() {
        return fail("could not serialize the requested credential");
    }
    buffer.push(b'\n');
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if output.write_all(&buffer).is_err() {
        return fail("could not write the requested credential to standard output");
    }
    ExitCode::SUCCESS
}

fn emit_get_warning(quiet: bool, result: ExitCode) -> ExitCode {
    if result == ExitCode::SUCCESS && !quiet {
        eprintln!(
            "Note: this secret is now in the agent's context. On a hosted LLM it may leave your machine. Prefer `palladin exec` when the credential only needs to authenticate a child process. Browser injection is disabled until an authenticated browser boundary is installed."
        );
    }
    result
}

fn print_unsafe_environment(environment: &EnvironmentReport, protocol_stdout: bool) {
    let message = format!(
        "dangerous-variable-names: {}",
        environment.dangerous_names().join(",")
    );
    if protocol_stdout {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }
}
