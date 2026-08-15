#![forbid(unsafe_code)]

#[cfg(any(target_os = "macos", all(test, unix)))]
use std::collections::BTreeMap;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use palladin_api::{
    AgentPairingStatus, ApiError, CredentialMethod, ReportCredentialStaleInput, StaleReasonCode,
};
#[cfg(any(target_os = "macos", all(test, unix)))]
use palladin_browser_bridge::{
    InjectionControl, InjectionCredential, InjectionFormField, InjectionTarget,
};
use palladin_browser_bridge::{InjectionFormDefinition, ProviderId};
use palladin_cli::args::{
    AgentsCommand, BrowserCommand, Cli, Commands, ConnectArgs, ExecArgs, GetArgs, InjectArgs,
    McpCommand, ProgressArg, ReportStaleArgs, SearchArgs, SecurityCommand, StaleCodeArg,
};
use palladin_cli::browser::{PairingBundle, install_manifest, manifest_status, remove_manifest};
#[cfg(target_os = "macos")]
use palladin_cli::native_browser::{
    ExtensionClient, InjectFieldValue, InjectRequest, monotonic_not_after_ns, monotonic_now_ns,
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
#[cfg(any(target_os = "macos", all(test, unix)))]
use palladin_credential::fields::{ResolvedField, ResolvedFieldType};
use palladin_credential::secret::parse_secret;
use palladin_credential::wait::{
    ProgressMode, WaitOptions, heartbeat_line, parse_duration, parse_wait_duration,
    signal_cancellation_token,
};
#[cfg(target_os = "linux")]
use palladin_linux_broker::store::LinuxBrokerSecretStore;
use palladin_platform::legacy_typescript_store::{
    LegacyCredentialError, OsLegacyCredentialDeleter, delete_legacy_typescript_credentials,
};
use palladin_platform::secure_store::{
    AuthorizationPrompt, NativeSecretStore, OperationAuthorization, OperationScope, SecretSlot,
    SecretStore, StoreError, storage_tier_description,
};
use palladin_runtime::{
    CredentialOutputPolicy, InvocationSurface, OperationConnection, OperationDescriptor,
};
#[cfg(windows)]
use palladin_windows_broker::BrokerSecretStore;
use secrecy::ExposeSecret;
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

const EXIT_FAILURE: u8 = 1;
const EXIT_UNSAFE_ENVIRONMENT: u8 = 78;
#[cfg(windows)]
const WINDOWS_HARDENED_TIER: &str = "Hardened - restricted LocalService service-SID broker with authenticated AppContainer and Windows Hello consent";
#[cfg(target_os = "linux")]
const LINUX_HARDENED_TIER: &str = "Hardened - dedicated Agent UID, authenticated Unix broker, encrypted broker-owned store, and separate executor UID";

#[tokio::main]
async fn main() -> ExitCode {
    install_redacted_panic_hook();
    if is_chrome_native_host_invocation() {
        return chrome_native_host_main().await;
    }
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

    if let Commands::Inject(args) = &cli.command
        && inject_uses_deprecated_browser_boundary(args)
    {
        eprintln!(
            "Error: browser injection is disabled because an unauthenticated CDP endpoint can spoof the page origin and receive plaintext; Palladin will enable inject only through a reviewed authenticated browser boundary; no profile was opened and no credential was requested"
        );
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
    let service = Arc::new(RuntimeService::new(repository, secret_store));

    if requires_version_policy(&cli.command) {
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
        Commands::Pair => pair(&service, cli.id.as_deref()).await,
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
        Commands::Inject(args) => inject(&service, cli.id.as_deref(), args).await,
        Commands::Browser { command } => browser(&service, command),
        Commands::ReportStale(args) => report_stale(&service, cli.id.as_deref(), args).await,
        Commands::Mcp { command } => mcp(Arc::clone(&service), cli.id.clone(), command).await,
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

fn is_chrome_native_host_invocation() -> bool {
    #[cfg(target_os = "macos")]
    {
        let mut arguments = std::env::args_os();
        let _executable = arguments.next();
        arguments.next().is_some_and(|argument| {
            argument == palladin_cli::browser::CHROME_EXTENSION_ORIGIN && arguments.next().is_none()
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

async fn chrome_native_host_main() -> ExitCode {
    #[cfg(target_os = "macos")]
    {
        if palladin_platform::authenticate_chrome_native_messaging_parent().is_err() {
            return ExitCode::from(EXIT_UNSAFE_ENVIRONMENT);
        }
        let secret_store = match runtime_secret_store(None) {
            Ok(store) => store,
            Err(_) => return ExitCode::from(EXIT_FAILURE),
        };
        let root = match palladin_platform::palladin_root() {
            Ok(root) => root,
            Err(_) => return ExitCode::from(EXIT_FAILURE),
        };
        let repository = match ProfileRepository::new(root.clone()) {
            Ok(repository) => repository,
            Err(_) => return ExitCode::from(EXIT_FAILURE),
        };
        let service = RuntimeService::new(repository, secret_store);
        if palladin_runtime::version_policy::system_version_policy_configured() {
            if service.prepare_empty_state_for_version_policy().is_err()
                || service
                    .enforce_system_version_policy(env!("CARGO_PKG_VERSION"))
                    .await
                    .is_err()
            {
                return ExitCode::from(EXIT_FAILURE);
            }
        } else if !cfg!(debug_assertions) {
            return ExitCode::from(EXIT_FAILURE);
        }
        let pairing = match service.browser_host_pairing() {
            Ok(pairing) => pairing,
            Err(_) => return ExitCode::from(EXIT_FAILURE),
        };
        return match palladin_cli::native_browser::serve_native_host(
            &root,
            pairing.identity(),
            |max_wait| {
                service
                    .browser_host_lifecycle_guard_within(pairing.lifecycle_token(), max_wait)
                    .map_err(|_| palladin_cli::native_browser::NativeBrowserError::Revoked)
            },
        )
        .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(EXIT_FAILURE),
        };
    }
    #[cfg(not(target_os = "macos"))]
    {
        ExitCode::from(EXIT_UNSAFE_ENVIRONMENT)
    }
}

fn browser(service: &RuntimeService<RuntimeSecretStore>, command: BrowserCommand) -> ExitCode {
    match command {
        BrowserCommand::Install => {
            let provisioning = match service.provision_browser_host_pairing_locked() {
                Ok(pairing) => pairing,
                Err(error) => return fail(&error.to_string()),
            };
            let path = match install_manifest(service.repository().root()) {
                Ok(path) => path,
                Err(error) => return fail(&error.to_string()),
            };
            let bundle = PairingBundle::from_identity(provisioning.identity());
            let encoded = match serde_json::to_string(&bundle) {
                Ok(encoded) => encoded,
                Err(_) => return fail("could not encode the browser pairing bundle"),
            };
            println!("{encoded}");
            eprintln!(
                "Palladin Chrome host installed at {}.\nFingerprint: {}\nPaste the JSON pairing bundle into the Palladin extension and confirm this fingerprint in both surfaces.",
                safe_terminal_text(&path.to_string_lossy()),
                shorten_public_identifier(&provisioning.identity().fingerprint())
            );
            drop(provisioning);
            ExitCode::SUCCESS
        }
        BrowserCommand::Status => {
            let installed = match manifest_status(service.repository().root()) {
                Ok(installed) => installed,
                Err(error) => return fail(&error.to_string()),
            };
            let paired = match service.browser_host_identity() {
                Ok(identity) => {
                    println!(
                        "Chrome host: {}\nPairing identity: paired ({})",
                        if installed {
                            "installed"
                        } else {
                            "not installed"
                        },
                        shorten_public_identifier(&identity.fingerprint())
                    );
                    true
                }
                Err(RuntimeError::BrowserHostNotPaired) => {
                    println!(
                        "Chrome host: {}\nPairing identity: not paired",
                        if installed {
                            "installed"
                        } else {
                            "not installed"
                        }
                    );
                    false
                }
                Err(error) => return fail(&error.to_string()),
            };
            if installed && paired {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EXIT_FAILURE)
            }
        }
        BrowserCommand::Unpair { confirm } => {
            if !confirm {
                return fail("browser unpair requires --confirm");
            }
            let revocation = match service.unpair_browser_host_identity() {
                Ok(revocation) => revocation,
                Err(error) => return fail(&error.to_string()),
            };
            if let Err(error) = remove_manifest(service.repository().root()) {
                return fail(&error.to_string());
            }
            drop(revocation);
            println!("Palladin Chrome host unpaired and its manifest removed.");
            ExitCode::SUCCESS
        }
    }
}

fn shorten_public_identifier(value: &str) -> String {
    if value.len() <= 15 {
        return value.to_owned();
    }
    format!("{}…{}", &value[..8], &value[value.len() - 6..])
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

    fn requires_operation_authorization(&self) -> bool {
        match self {
            Self::Convenience(store) => store.requires_operation_authorization(),
            #[cfg(windows)]
            Self::Hardened(store) => store.requires_operation_authorization(),
            #[cfg(target_os = "linux")]
            Self::LinuxHardened(store) => store.requires_operation_authorization(),
        }
    }

    fn initialize_operation_authorization(&self, identity_id: &str) -> Result<(), StoreError> {
        match self {
            Self::Convenience(store) => store.initialize_operation_authorization(identity_id),
            #[cfg(windows)]
            Self::Hardened(store) => store.initialize_operation_authorization(identity_id),
            #[cfg(target_os = "linux")]
            Self::LinuxHardened(store) => store.initialize_operation_authorization(identity_id),
        }
    }

    fn authorize_operation(
        &self,
        scope: &OperationScope,
        prompt: AuthorizationPrompt,
        binding: &[u8],
    ) -> Result<OperationAuthorization, StoreError> {
        match self {
            Self::Convenience(store) => store.authorize_operation(scope, prompt, binding),
            #[cfg(windows)]
            Self::Hardened(store) => store.authorize_operation(scope, prompt, binding),
            #[cfg(target_os = "linux")]
            Self::LinuxHardened(store) => store.authorize_operation(scope, prompt, binding),
        }
    }

    fn get_authorized(
        &self,
        owner_id: &str,
        slot: SecretSlot,
        authorization: &OperationAuthorization,
        binding: &[u8],
    ) -> Result<Option<secrecy::SecretSlice<u8>>, StoreError> {
        match self {
            Self::Convenience(store) => {
                store.get_authorized(owner_id, slot, authorization, binding)
            }
            #[cfg(windows)]
            Self::Hardened(store) => store.get_authorized(owner_id, slot, authorization, binding),
            #[cfg(target_os = "linux")]
            Self::LinuxHardened(store) => {
                store.get_authorized(owner_id, slot, authorization, binding)
            }
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
        | Commands::Pair
        | Commands::Disconnect { .. }
        | Commands::Search(_)
        | Commands::Get(_)
        | Commands::Exec(_)
        | Commands::Inject(_)
        | Commands::Browser { .. }
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

const fn requires_version_policy(command: &Commands) -> bool {
    !matches!(
        command,
        Commands::Doctor
            | Commands::VerifyReleasePolicy { .. }
            | Commands::Security {
                command: SecurityCommand::LegacyStatus,
            }
    )
}

async fn mcp(
    service: Arc<RuntimeService<RuntimeSecretStore>>,
    profile: Option<String>,
    command: McpCommand,
) -> ExitCode {
    match command {
        McpCommand::Serve => {
            let hostname = match operating_system_hostname() {
                Ok(hostname) => hostname,
                Err(error) => return fail(error),
            };
            let connection = match OperationConnection::new() {
                Ok(connection) => connection,
                Err(error) => return fail(&error.to_string()),
            };
            let server = match palladin_mcp::native_server(service, profile, hostname, connection) {
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
        let hostname = match operating_system_hostname() {
            Ok(hostname) => hostname,
            Err(error) => return fail(error),
        };
        let connection = match OperationConnection::new() {
            Ok(connection) => connection,
            Err(error) => return fail(&error.to_string()),
        };
        let profile = match service.verify_identity(Some(profile_name), &hostname, &connection) {
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
    match service.verify_public_metadata() {
        Ok(()) => println!("public-metadata-chain: valid"),
        Err(_) => println!("public-metadata-chain: invalid"),
    }
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
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    let outcome = match service
        .connect(
            profile,
            api_key,
            host,
            args.name.as_deref(),
            args.r#type.as_deref(),
            &hostname,
            &connection,
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
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    let outcome = match service.status(profile, &hostname, &connection).await {
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

async fn pair(service: &RuntimeService<RuntimeSecretStore>, profile: Option<&str>) -> ExitCode {
    let hostname = match operating_system_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return fail(error),
    };
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    let activation_id = match pairing_activation_id() {
        Ok(activation_id) => activation_id,
        Err(error) => return fail(&error.to_string()),
    };
    let mut session = match service.open_session(
        profile,
        &hostname,
        &connection,
        OperationDescriptor::PairVaults {
            activation_id: activation_id.clone(),
        },
    ) {
        Ok(session) => session,
        Err(error) => return fail(&error.to_string()),
    };
    let candidate = match session.create_pairing_activation(&activation_id).await {
        Ok(candidate) => candidate,
        Err(error) => return fail(&error.to_string()),
    };
    println!(
        "Pairing activation: {}",
        palladin_core::terminal::shorten_identifier(&activation_id)
    );
    println!(
        "Verification code: {}",
        candidate.short_authentication_string()
    );
    println!("Approve the matching code in Palladin. Waiting for confirmation...");

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let response = match session.get_pairing_status(&activation_id).await {
            Ok(response) => response,
            Err(RuntimeError::OperationAuthorizationExpired) => {
                drop(session);
                let renewed = match service.open_session(
                    profile,
                    &hostname,
                    &connection,
                    OperationDescriptor::PairVaults {
                        activation_id: activation_id.clone(),
                    },
                ) {
                    Ok(session) => session,
                    Err(error) => return fail(&error.to_string()),
                };
                if let Err(error) = renewed.resume_pairing_polling(&activation_id) {
                    return fail(&error.to_string());
                }
                session = renewed;
                continue;
            }
            Err(error) => return fail(&error.to_string()),
        };
        if response.status == AgentPairingStatus::Pending {
            continue;
        }
        let confirmed =
            match candidate.confirm_from_relay(response, time::OffsetDateTime::now_utc()) {
                Ok(confirmed) => confirmed,
                Err(error) => return fail(&error.to_string()),
            };
        drop(session);
        let config =
            match service.persist_pairing_anchors(profile, &hostname, &connection, confirmed) {
                Ok(config) => config,
                Err(error) => return fail(&error.to_string()),
            };
        println!(
            "Pairing complete: {} vault(s) trusted.",
            config.vault_trust_anchors.len()
        );
        return ExitCode::SUCCESS;
    }
}

fn pairing_activation_id() -> Result<String, RuntimeError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| RuntimeError::RandomGenerationFailed)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes).to_string())
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
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    let descriptor = OperationDescriptor::SearchEntries {
        surface: InvocationSurface::Cli,
        query: query.to_owned(),
        cursor: args.cursor.clone(),
        page_size: args.page_size,
    };
    let session = match service.open_session(profile, &hostname, &connection, descriptor) {
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
        match args.wait.as_deref().map(parse_wait_duration).transpose() {
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
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    let descriptor = OperationDescriptor::GetCredential {
        surface: InvocationSurface::Cli,
        vault_id: args.vault_id.clone(),
        entry_id: args.entry_id.clone(),
        reason: args.reason.clone(),
        wait,
        field: args.field.clone(),
        field_id: args.field_id.clone(),
        output: CredentialOutputPolicy::CliSecretStdout,
    };
    let session = match service.open_session(profile, &hostname, &connection, descriptor) {
        Ok(session) => session,
        Err(error) => return fail(&error.to_string()),
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
        match args.wait.as_deref().map(parse_wait_duration).transpose() {
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
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    let descriptor = OperationDescriptor::ExecWithCredential {
        surface: InvocationSurface::Cli,
        vault_id: args.vault_id.clone(),
        entry_id: args.entry_id.clone(),
        reason: args.reason.clone(),
        wait,
        command: args.command.clone(),
        env_mappings: args.env_mappings.clone(),
        output: CredentialOutputPolicy::CliChildProcess,
    };
    let session = match service.open_session(profile, &hostname, &connection, descriptor) {
        Ok(session) => session,
        Err(error) => return fail(&error.to_string()),
    };
    let cancellation = signal_cancellation_token();
    let outcome = session
        .execute_with_credential(
            CredentialExecRequest {
                delivery: CredentialDeliveryRequest {
                    vault_id: &args.vault_id,
                    entry_id: &args.entry_id,
                    reason: args.reason.as_deref(),
                    wait,
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

async fn inject(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    args: InjectArgs,
) -> ExitCode {
    debug_assert!(!inject_uses_deprecated_browser_boundary(&args));
    let provider = match ProviderId::parse(args.provider.clone()) {
        Ok(provider) => provider,
        Err(error) => return fail(&error.to_string()),
    };
    if provider.as_str() != "extension" || args.provider_transport_stdio {
        return fail("only the authenticated Palladin extension provider is supported");
    }
    let form_json = match args.form_json.as_deref() {
        Some(value) if !value.is_empty() && value.len() <= 256 * 1024 => value,
        _ => {
            return fail(
                "extension Inject requires --form-json with a bounded value-free form plan",
            );
        }
    };
    let form: InjectionFormDefinition = match serde_json::from_str(form_json) {
        Ok(form) => form,
        Err(_) => return fail("the Inject form definition is invalid"),
    };
    if form.validate().is_err() {
        return fail("the Inject form definition is invalid");
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, profile, args, provider, form);
        fail("the authenticated Chrome extension provider is unavailable on this platform")
    }
    #[cfg(target_os = "macos")]
    {
        inject_extension(service, profile, args, provider, form).await
    }
}

#[cfg(target_os = "macos")]
async fn inject_extension(
    service: &RuntimeService<RuntimeSecretStore>,
    profile: Option<&str>,
    args: InjectArgs,
    provider: ProviderId,
    form: InjectionFormDefinition,
) -> ExitCode {
    let pairing = match service.browser_host_pairing() {
        Ok(pairing) => pairing,
        Err(error) => return fail(&error.to_string()),
    };
    let mut extension =
        match ExtensionClient::connect(service.repository().root(), pairing.identity()).await {
            Ok(extension) => extension,
            Err(error) => return fail(&error.to_string()),
        };
    let mut operation_nonce = [0_u8; 32];
    if getrandom::fill(&mut operation_nonce).is_err() {
        return fail("could not create an Inject transaction");
    }
    let nonce = hex::encode(operation_nonce);
    let lifecycle = match service.browser_host_lifecycle_guard_within(
        pairing.lifecycle_token(),
        palladin_cli::native_browser::OPERATION_TIMEOUT,
    ) {
        Ok(lifecycle) => lifecycle,
        Err(error) => return fail(&error.to_string()),
    };
    let prepared = match extension.prepare(&nonce).await {
        Ok(prepared) => prepared,
        Err(error) => return fail(&error.to_string()),
    };
    drop(lifecycle);
    if prepared.outcome != "ready" {
        return fail("the authenticated Palladin extension is not ready for Inject");
    }
    let current_url = match prepared.current_url.as_deref() {
        Some(current_url) => current_url,
        None => return fail("the authenticated Palladin extension returned an invalid page"),
    };

    let wait_ms = if args.no_wait {
        Some(0)
    } else {
        match args.wait.as_deref().map(parse_wait_duration).transpose() {
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
    let hostname = match operating_system_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return fail(error),
    };
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    let descriptor = OperationDescriptor::InjectCredential {
        surface: InvocationSurface::Cli,
        vault_id: args.vault_id.clone(),
        entry_id: args.entry_id.clone(),
        reason: args.reason.clone(),
        wait,
        provider: provider.as_str().to_owned(),
        output: CredentialOutputPolicy::TrustedInjectionProvider,
    };
    let session = match service.open_session(profile, &hostname, &connection, descriptor) {
        Ok(session) => session,
        Err(error) => return fail(&error.to_string()),
    };
    let cancellation = signal_cancellation_token();
    let delivery = session
        .deliver_for_inject(
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
        .await;
    let delivered = match delivery {
        Ok(CredentialDelivery::Granted(delivered)) => delivered,
        Ok(CredentialDelivery::NotGranted(access)) => {
            if let Some(message) = access_message(&access, CredentialMethod::Inject) {
                eprintln!("Error: {}", safe_terminal_text(&message));
            }
            return ExitCode::from(exit_code_for_access(&access));
        }
        Err(error) => return fail(&error.to_string()),
    };
    let parsed = match parse_secret(delivered.expose_for_authorized_operation()) {
        Ok(parsed) => parsed,
        Err(_) => return fail("the Inject credential payload is invalid"),
    };
    let target = match resolve_authenticated_injection_target(
        parsed
            .fields
            .get("urlDomain")
            .map(|domain| domain.expose_secret()),
        delivered.authenticated_domain(),
    ) {
        Ok(target) => target,
        Err(error) => return fail(&error),
    };
    if let Err(error) = target.verify_url(current_url) {
        return fail(&format!(
            "{} (expected domain {})",
            error,
            target.expected_domain()
        ));
    }
    let form_map = match session
        .resolve_form_discovery_map(target.expected_domain(), provider.as_str(), None)
        .await
    {
        Ok(Some(map)) if map.applies_to_url(current_url) => Some(map),
        Ok(_) => None,
        Err(error) if map_lookup_allows_fallback(&error) => None,
        Err(error) => return fail(&error.to_string()),
    };
    let form = match form_map
        .as_ref()
        .map(|map| &map.map.form)
        .or(Some(&form))
    {
        Some(form) => form,
        None => return fail("no verified Form Discovery Map or fallback form is available"),
    };
    let credential = match resolve_injection_credential(
        &parsed,
        delivered.authenticated_field("credential.username"),
        form,
    ) {
        Ok(credential) => credential,
        Err(error) => return fail(&error.to_string()),
    };
    let mut transaction_bytes = [0_u8; 16];
    if getrandom::fill(&mut transaction_bytes).is_err() {
        return fail("could not create an Inject transaction");
    }
    let transaction_id = hex::encode(transaction_bytes);
    let values = credential
        .fields()
        .iter()
        .map(|(entry_field_id, value)| InjectFieldValue {
            entry_field_id,
            value,
        })
        .collect();
    let forward = match session.browser_inject_forward_guard(
        service,
        pairing.lifecycle_token(),
        &delivered,
    ) {
        Ok(forward) => forward,
        Err(error) => return fail(&error.to_string()),
    };
    let monotonic_sample = match monotonic_now_ns() {
        Ok(sample) => sample,
        Err(error) => return fail(&error.to_string()),
    };
    let Some(authorization_remaining) = forward.remaining() else {
        return fail("the authenticated browser authorization expired");
    };
    let not_after_monotonic_ns =
        match monotonic_not_after_ns(monotonic_sample, authorization_remaining) {
            Ok(deadline) => deadline,
            Err(error) => return fail(&error.to_string()),
        };
    let wire = InjectRequest {
        protocol: palladin_browser_bridge::secure_transport::INJECT_PROVIDER_PROTOCOL,
        message_type: "inject",
        transaction_id: &transaction_id,
        grant_id: &delivered.grant_id,
        entry_id: &delivered.entry_id,
        expected_domain: target.expected_domain(),
        form,
        values,
    };
    let sealed = match extension.seal_inject(&wire, not_after_monotonic_ns) {
        Ok(sealed) => sealed,
        Err(error) => return fail(&error.to_string()),
    };
    drop(wire);
    drop(credential);
    drop(parsed);
    drop(delivered);
    let Some(authorization_remaining) = forward.remaining() else {
        return fail("the authenticated browser authorization expired");
    };
    let response = match extension.send_inject(sealed, authorization_remaining).await {
        Ok(response) => response,
        Err(error) => return fail(&error.to_string()),
    };
    drop(forward);
    if response.outcome != "injected" {
        if response.outcome == "stale-form-map"
            && let Some(rejected) = form_map.as_ref()
            && let Err(error) = session
                .resolve_form_discovery_map(
                    target.expected_domain(),
                    provider.as_str(),
                    Some(rejected),
                )
                .await
        {
            return fail(&format!(
                "the trusted browser provider reported a stale Form Discovery Map, but cache invalidation or refresh failed: {error}"
            ));
        }
        return fail(match response.outcome.as_str() {
            "rejected" => "the trusted browser provider did not complete Inject (outcome=rejected)",
            "no-password-field" => {
                "the trusted browser provider did not complete Inject (outcome=no-password-field)"
            }
            "no-submit-control" => {
                "the trusted browser provider did not complete Inject (outcome=no-submit-control)"
            }
            "origin-mismatch" => {
                "the trusted browser provider did not complete Inject (outcome=origin-mismatch)"
            }
            "insecure-origin" => {
                "the trusted browser provider did not complete Inject (outcome=insecure-origin)"
            }
            "ambiguous-form" => {
                "the trusted browser provider did not complete Inject (outcome=ambiguous-form)"
            }
            "provider-unavailable" => {
                "the trusted browser provider did not complete Inject (outcome=provider-unavailable)"
            }
            "stale-form-map" => {
                "the trusted browser provider did not complete Inject (outcome=stale-form-map); the cached map was invalidated and refresh was attempted for the next request"
            }
            _ => "the trusted browser provider did not complete Inject (outcome=invalid)",
        });
    }
    if form_map.is_none()
        && let Some(fallback) = open.form.as_ref()
        && session
            .submit_form_discovery_map_candidate(
                target.expected_domain(),
                &open.current_url,
                provider.as_str(),
                fallback,
            )
            .await
            .is_err()
    {
        eprintln!(
            "Warning: the value-free login form candidate could not be recorded; the completed Inject result is unchanged."
        );
    }
    eprintln!(
        "Credential injected through provider {}.",
        provider.as_str()
    );
    ExitCode::SUCCESS
}

fn map_lookup_allows_fallback(error: &RuntimeError) -> bool {
    match error {
        RuntimeError::Api(ApiError::Transport) => true,
        RuntimeError::Api(ApiError::Http(status)) => (500..=599).contains(status),
        _ => false,
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn resolve_injection_credential(
    parsed: &palladin_credential::secret::ParsedSecret,
    authenticated_username: Option<&str>,
    form: &InjectionFormDefinition,
) -> Result<InjectionCredential, palladin_browser_bridge::InjectionError> {
    form.validate()?;
    let mut values = BTreeMap::new();
    for step in &form.steps {
        for field in &step.fields {
            let value = resolve_injection_field(parsed, authenticated_username, field)?;
            values.insert(field.entry_field_id.clone(), value);
        }
    }
    InjectionCredential::from_fields(values)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn resolve_injection_field(
    parsed: &palladin_credential::secret::ParsedSecret,
    authenticated_username: Option<&str>,
    field: &InjectionFormField,
) -> Result<String, palladin_browser_bridge::InjectionError> {
    let (resolved, kind) = match field.entry_field_id.as_str() {
        "credential.username" => {
            let value = parsed
                .username
                .as_ref()
                .map(|value| value.expose_secret())
                .filter(|value| !value.is_empty())
                .or(authenticated_username)
                .ok_or(palladin_browser_bridge::InjectionError::InvalidCredential)?;
            (value.to_owned(), ResolvedKind::Text)
        }
        "credential.password" => {
            let value = parsed.password.expose_secret();
            if value.is_empty() {
                return Err(palladin_browser_bridge::InjectionError::InvalidCredential);
            }
            (value.to_owned(), ResolvedKind::Concealed)
        }
        "credential.url" => resolve_selected_field(parsed, "url", None)?,
        "credential.notes" | "notes" => resolve_selected_field(parsed, "notes", None)?,
        "credential.value" => resolve_selected_field(parsed, "value", None)?,
        "credential.totp" => resolve_selected_field(parsed, "totp", None)?,
        custom_id => resolve_selected_field(
            parsed,
            "",
            Some(custom_id.strip_prefix("custom:").unwrap_or(custom_id)),
        )?,
    };
    let compatible = matches!(
        (kind, field.control),
        (ResolvedKind::Concealed, InjectionControl::Password)
            | (
                ResolvedKind::Otp,
                InjectionControl::Otp | InjectionControl::Text | InjectionControl::Tel,
            )
            | (
                ResolvedKind::Text,
                InjectionControl::Username
                    | InjectionControl::Text
                    | InjectionControl::Email
                    | InjectionControl::Tel,
            )
    );
    if !compatible {
        return Err(palladin_browser_bridge::InjectionError::InvalidCredential);
    }
    Ok(resolved)
}

#[derive(Clone, Copy)]
#[cfg(any(target_os = "macos", all(test, unix)))]
enum ResolvedKind {
    Text,
    Concealed,
    Otp,
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn resolve_selected_field(
    parsed: &palladin_credential::secret::ParsedSecret,
    label: &str,
    field_id: Option<&str>,
) -> Result<(String, ResolvedKind), palladin_browser_bridge::InjectionError> {
    let selected = resolve_field(
        parsed,
        &FieldSelector {
            field: field_id.is_none().then(|| label.to_owned()),
            field_id: field_id.map(str::to_owned),
        },
    )
    .map_err(|_| palladin_browser_bridge::InjectionError::InvalidCredential)?;
    let kind = match &selected {
        ResolvedField::Totp { .. } => ResolvedKind::Otp,
        ResolvedField::Value { field_type, .. } => match field_type {
            ResolvedFieldType::Concealed => ResolvedKind::Concealed,
            ResolvedFieldType::WellKnown
            | ResolvedFieldType::Text
            | ResolvedFieldType::Multiline => ResolvedKind::Text,
        },
    };
    Ok((selected.expose_for_authorized_operation().to_owned(), kind))
}

fn inject_uses_deprecated_browser_boundary(args: &InjectArgs) -> bool {
    args.cdp.is_some()
        || args.page_url.is_some()
        || args.username_selector.is_some()
        || args.password_selector.is_some()
        || args.submit_selector.is_some()
        || args.no_submit
        || args.fill_only
        || args.field.is_some()
        || args.field_id.is_some()
        || args.verbose
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn resolve_authenticated_injection_target(
    grant_domain: Option<&str>,
    discovery_domain: Option<&str>,
) -> Result<InjectionTarget, String> {
    let grant_target = grant_domain
        .map(|domain| InjectionTarget::parse(domain.to_owned()))
        .transpose()
        .map_err(|error| error.to_string())?;
    let discovery_target = discovery_domain
        .map(|domain| InjectionTarget::parse(domain.to_owned()))
        .transpose()
        .map_err(|error| error.to_string())?;
    match (grant_target, discovery_target) {
        (Some(grant), Some(discovery)) if grant != discovery => {
            Err("the grant and Discovery domains do not match".to_owned())
        }
        (Some(grant), _) => Ok(grant),
        (None, Some(discovery)) => Ok(discovery),
        (None, None) => Err("the Inject credential has no authenticated domain".to_owned()),
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
    let code = match args.code {
        StaleCodeArg::LoginRejected => StaleReasonCode::LoginRejected,
        StaleCodeArg::AuthFailed => StaleReasonCode::AuthFailed,
        StaleCodeArg::Manual => StaleReasonCode::Manual,
    };
    let input = ReportCredentialStaleInput {
        vault_id: args.vault_id.trim().to_owned(),
        entry_id: args.entry_id.trim().to_owned(),
        code,
    };
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    let descriptor = OperationDescriptor::ReportCredentialStale {
        surface: InvocationSurface::Cli,
        vault_id: input.vault_id.clone(),
        entry_id: input.entry_id.clone(),
        code: stale_reason_code_name(input.code).to_owned(),
    };
    let session = match service.open_session(profile, &hostname, &connection, descriptor) {
        Ok(session) => session,
        Err(error) => return fail(&error.to_string()),
    };
    match session.report_credential_stale(&input).await {
        Ok(()) => emit_output(render_report_stale()),
        Err(error) => fail(&error.to_string()),
    }
}

const fn stale_reason_code_name(code: StaleReasonCode) -> &'static str {
    match code {
        StaleReasonCode::LoginRejected => "login_rejected",
        StaleReasonCode::AuthFailed => "auth_failed",
        StaleReasonCode::Manual => "manual",
    }
}

fn agents(
    service: &RuntimeService<RuntimeSecretStore>,
    command: AgentsCommand,
    runtime_storage_tier: &str,
) -> ExitCode {
    let hostname = match operating_system_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return fail(error),
    };
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    match agents_result(
        service,
        command,
        runtime_storage_tier,
        &hostname,
        &connection,
    ) {
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
        SecurityCommand::Upgrade => {
            let hostname = match operating_system_hostname() {
                Ok(hostname) => hostname,
                Err(error) => return fail(error),
            };
            let connection = match OperationConnection::new() {
                Ok(connection) => connection,
                Err(error) => return fail(&error.to_string()),
            };
            match service.upgrade_security(profile, &hostname, &connection) {
                Ok(outcome) => emit_output(render_security_upgrade(
                    &outcome.profile.name,
                    runtime_storage_tier,
                    outcome.migrated,
                )),
                Err(error) => fail(&error.to_string()),
            }
        }
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
    hostname: &str,
    connection: &OperationConnection,
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
            service.delete_profile(&name, hostname, connection)?;
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
    let hostname = match operating_system_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return fail(error),
    };
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    match service.purge_profile(profile, &hostname, &connection) {
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
    let hostname = match operating_system_hostname() {
        Ok(hostname) => hostname,
        Err(error) => return fail(error),
    };
    let connection = match OperationConnection::new() {
        Ok(connection) => connection,
        Err(error) => return fail(&error.to_string()),
    };
    match service.purge(&hostname, &connection) {
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

#[cfg(test)]
mod version_policy_gate_tests {
    use clap::Parser;

    use super::{Cli, requires_version_policy};

    fn command(arguments: &[&str]) -> Cli {
        Cli::try_parse_from(arguments).expect("valid command")
    }

    #[test]
    fn secret_mutations_and_purge_require_the_anti_rollback_gate() {
        for arguments in [
            &[
                "palladin",
                "--id",
                "agent",
                "disconnect",
                "--purge",
                "--confirm",
            ][..],
            &["palladin", "purge", "--confirm"][..],
            &[
                "palladin",
                "security",
                "legacy-cutover",
                "--confirm-pre-production-reset",
            ][..],
            &[
                "palladin",
                "security",
                "legacy-cleanup",
                "cutover-id",
                "--confirm",
            ][..],
            &["palladin", "browser", "install"][..],
            &["palladin", "browser", "unpair", "--confirm"][..],
        ] {
            assert!(requires_version_policy(&command(arguments).command));
        }
    }

    #[test]
    fn only_identity_free_diagnostics_bypass_the_stateful_gate() {
        assert!(!requires_version_policy(
            &command(&["palladin", "doctor"]).command
        ));
        assert!(!requires_version_policy(
            &command(&["palladin", "security", "legacy-status"]).command
        ));
    }
}

#[cfg(test)]
mod operation_descriptor_tests {
    use palladin_api::StaleReasonCode;

    use super::stale_reason_code_name;

    #[test]
    fn stale_reason_codes_use_the_api_binding_values() {
        assert_eq!(
            stale_reason_code_name(StaleReasonCode::LoginRejected),
            "login_rejected"
        );
        assert_eq!(
            stale_reason_code_name(StaleReasonCode::AuthFailed),
            "auth_failed"
        );
        assert_eq!(stale_reason_code_name(StaleReasonCode::Manual), "manual");
    }
}

#[cfg(all(test, unix))]
mod authenticated_injection_target_tests {
    use super::resolve_authenticated_injection_target;

    #[test]
    fn discovery_domain_can_bind_an_inject_grant_without_a_payload_domain() {
        let target = resolve_authenticated_injection_target(None, Some("X.COM"))
            .expect("authenticated Discovery domain");
        assert_eq!(target.expected_domain(), "x.com");
    }

    #[test]
    fn matching_grant_and_discovery_domains_are_accepted_after_normalization() {
        let target = resolve_authenticated_injection_target(Some("X.COM"), Some("x.com"))
            .expect("matching authenticated domains");
        assert_eq!(target.expected_domain(), "x.com");
    }

    #[test]
    fn mismatched_or_missing_authenticated_domains_fail_closed() {
        assert_eq!(
            resolve_authenticated_injection_target(Some("evil.test"), Some("x.com")),
            Err("the grant and Discovery domains do not match".to_owned())
        );
        assert_eq!(
            resolve_authenticated_injection_target(None, None),
            Err("the Inject credential has no authenticated domain".to_owned())
        );
    }
}

#[cfg(all(test, unix))]
mod provider_credential_tests {
    use super::{map_lookup_allows_fallback, resolve_injection_credential};
    use palladin_api::ApiError;
    use palladin_browser_bridge::secure_transport::INJECT_PROVIDER_PROTOCOL;
    use palladin_browser_bridge::{
        InjectionControl, InjectionFormDefinition, InjectionFormField, InjectionFormStep,
        InjectionSubmit, InjectionSubmitKind,
    };
    use palladin_cli::native_browser::{InjectFieldValue, InjectRequest};
    use palladin_runtime::RuntimeError;

    #[test]
    fn fallback_form_is_used_only_for_transient_map_lookup_unavailability() {
        assert!(map_lookup_allows_fallback(&RuntimeError::Api(
            ApiError::Transport
        )));
        assert!(map_lookup_allows_fallback(&RuntimeError::Api(
            ApiError::Http(503)
        )));
        assert!(!map_lookup_allows_fallback(&RuntimeError::Api(
            ApiError::Http(401)
        )));
        assert!(!map_lookup_allows_fallback(&RuntimeError::Api(
            ApiError::InvalidResponse
        )));
        assert!(!map_lookup_allows_fallback(&RuntimeError::FormMapCache));
    }

    #[test]
    fn private_provider_frame_contains_only_declared_field_values() {
        let form = InjectionFormDefinition {
            version: 1,
            steps: vec![InjectionFormStep {
                fields: vec![InjectionFormField {
                    entry_field_id: "credential.password".to_owned(),
                    selector: "#password".to_owned(),
                    control: InjectionControl::Password,
                }],
                submit: InjectionSubmit {
                    action: InjectionSubmitKind::PressEnter,
                    selector: "#password".to_owned(),
                },
                wait_for: None,
            }],
        };
        let wire = InjectRequest {
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "inject",
            transaction_id: "transaction",
            grant_id: "grant",
            entry_id: "entry",
            expected_domain: "example.com",
            form: &form,
            values: vec![InjectFieldValue {
                entry_field_id: "credential.password",
                value: "fixture-password-not-production",
            }],
        };
        let encoded = serde_json::to_value(wire).expect("provider frame");
        assert!(encoded.get("username").is_none());
        assert!(encoded.get("password").is_none());
        assert_eq!(encoded["values"][0]["entryFieldId"], "credential.password");
    }

    #[test]
    fn canonical_grant_fields_and_authenticated_discovery_username_resolve_for_inject() {
        let parsed = palladin_credential::secret::parse_secret(
            br#"{"password":"fixture-password-not-production","urlDomain":"example.com"}"#,
        )
        .expect("normalized grant");
        let form = InjectionFormDefinition {
            version: 1,
            steps: vec![InjectionFormStep {
                fields: vec![
                    InjectionFormField {
                        entry_field_id: "credential.username".to_owned(),
                        selector: "#username".to_owned(),
                        control: InjectionControl::Username,
                    },
                    InjectionFormField {
                        entry_field_id: "credential.password".to_owned(),
                        selector: "#password".to_owned(),
                        control: InjectionControl::Password,
                    },
                ],
                submit: InjectionSubmit {
                    action: InjectionSubmitKind::Click,
                    selector: "button[type=submit]".to_owned(),
                },
                wait_for: None,
            }],
        };
        let resolved = resolve_injection_credential(&parsed, Some("fixture-user"), &form)
            .expect("resolved fields");
        assert_eq!(
            resolved
                .fields()
                .get("credential.username")
                .map(String::as_str),
            Some("fixture-user")
        );
        assert_eq!(
            resolved
                .fields()
                .get("credential.password")
                .map(String::as_str),
            Some("fixture-password-not-production")
        );
    }
}
