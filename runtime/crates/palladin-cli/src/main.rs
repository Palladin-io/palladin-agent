#![forbid(unsafe_code)]

use std::io::{self, BufRead, IsTerminal, Read};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use palladin_api::AgentRegistrationResult;
use palladin_cli::{RuntimeError, RuntimeService, shorten_identifier};
use palladin_core::environment::{EnvironmentReport, EnvironmentRequirement, enforce_environment};
use palladin_core::host::ApiHost;
use palladin_core::panic::install_redacted_panic_hook;
use palladin_core::profiles::ProfileRepository;
use palladin_core::secret::OrganizationApiKey;
use palladin_platform::secure_store::{OsSecretStore, convenience_tier_description};
use zeroize::Zeroizing;

const EXIT_FAILURE: u8 = 1;
const EXIT_UNSAFE_ENVIRONMENT: u8 = 78;

#[derive(Debug, Parser)]
#[command(name = "palladin", version, about = "Palladin native Agent runtime")]
struct Cli {
    /// Local Agent profile alias.
    #[arg(long, global = true)]
    id: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check the native runtime boundary without opening Agent Identity.
    Doctor,
    /// Connect an Agent using a masked prompt or protected standard input.
    Connect(ConnectArgs),
    /// Show registration status for an Agent profile.
    Status,
    /// Manage local Agent profiles.
    Agents {
        #[command(subcommand)]
        command: AgentsCommand,
    },
    /// Explicitly remove every native profile and secret.
    Purge {
        /// Required acknowledgement; purge is never run by npm uninstall hooks.
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Debug, Args)]
struct ConnectArgs {
    /// Read the organization API key from one line of standard input.
    #[arg(long)]
    api_key_stdin: bool,
    /// Palladin API base URL.
    #[arg(long, default_value = "https://api.palladin.io")]
    host: String,
    /// Backend display name; the local profile alias remains unchanged.
    #[arg(long)]
    name: Option<String>,
    /// Agent category, for example ci, browser, or backend.
    #[arg(long)]
    r#type: Option<String>,
}

#[derive(Debug, Subcommand)]
enum AgentsCommand {
    /// List Agent profile aliases.
    List,
    /// Create a profile with a fresh native identity.
    Create {
        name: String,
        #[arg(long)]
        r#type: Option<String>,
    },
    /// Delete a non-default Agent profile.
    Delete { name: String },
    /// Change the default profile.
    SetDefault { name: String },
    /// Rename an alias without moving or rewriting secret slots.
    Rename { old_name: String, new_name: String },
}

impl Commands {
    const fn environment_requirement(&self) -> EnvironmentRequirement {
        match self {
            Self::Doctor => EnvironmentRequirement::DiagnosticOnly,
            Self::Connect(_) | Self::Status | Self::Agents { .. } | Self::Purge { .. } => {
                EnvironmentRequirement::Clean
            }
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    install_redacted_panic_hook();
    if argv_contains_api_key() {
        return fail(
            "API keys are forbidden in argv; use a masked prompt or connect --api-key-stdin",
        );
    }
    let environment = EnvironmentReport::inspect_current();
    let cli = Cli::parse();

    if enforce_environment(cli.command.environment_requirement(), &environment).is_err() {
        print_unsafe_environment(&environment);
        return ExitCode::from(EXIT_UNSAFE_ENVIRONMENT);
    }

    let root = match palladin_platform::palladin_root() {
        Ok(root) => root,
        Err(error) => return fail(&error.to_string()),
    };
    let repository = match ProfileRepository::new(root) {
        Ok(repository) => repository,
        Err(error) => return fail(&error.to_string()),
    };
    let service = RuntimeService::new(repository, OsSecretStore);

    match cli.command {
        Commands::Doctor => doctor(&environment, &service),
        Commands::Connect(args) => connect(&service, cli.id.as_deref(), args).await,
        Commands::Status => status(&service, cli.id.as_deref()).await,
        Commands::Agents { command } => agents(&service, command),
        Commands::Purge { confirm } => purge(&service, confirm),
    }
}

fn doctor(environment: &EnvironmentReport, service: &RuntimeService<OsSecretStore>) -> ExitCode {
    let platform = palladin_platform::current();
    println!("Palladin Runtime Doctor");
    println!("version: {}", env!("CARGO_PKG_VERSION"));
    println!(
        "platform: {}/{}",
        platform.operating_system, platform.architecture
    );
    println!("standalone-security-tier: {}", platform.standalone_tier);
    println!("storage-boundary: {}", convenience_tier_description());
    println!("hardened-candidate: {}", platform.hardened_candidate);
    println!("identity-opened: no");
    println!("project-runtime-dependencies: disabled");
    println!("palladin-home-override: rejected");
    println!(
        "legacy-artifacts: {}",
        if service.repository().legacy_artifacts_present() {
            "detected - run the explicit pre-production migration workflow"
        } else {
            "not-detected"
        }
    );
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
        print_unsafe_environment(environment);
        ExitCode::from(EXIT_UNSAFE_ENVIRONMENT)
    }
}

async fn connect(
    service: &RuntimeService<OsSecretStore>,
    profile: Option<&str>,
    args: ConnectArgs,
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

    println!("Security: {}", convenience_tier_description());
    match outcome.registration {
        AgentRegistrationResult::Pending { agent_id } => {
            println!("Agent registered - awaiting approval");
            println!("Agent ID: {}", shorten_identifier(&agent_id));
            println!("Approve this Agent in the Palladin panel.");
            ExitCode::SUCCESS
        }
        AgentRegistrationResult::Active { agent_id, name } => {
            println!("Agent active");
            println!("Agent ID: {}", shorten_identifier(&agent_id));
            if let Some(name) = name {
                println!("Backend name: {name}");
            }
            ExitCode::SUCCESS
        }
        AgentRegistrationResult::Deactivated { agent_id } => {
            eprintln!(
                "Error: Agent is deactivated ({})",
                shorten_identifier(&agent_id)
            );
            ExitCode::from(EXIT_FAILURE)
        }
        AgentRegistrationResult::InvalidKey => fail("API key is invalid or revoked"),
        AgentRegistrationResult::Unreachable { error } => {
            eprintln!("Warning: server unreachable ({error})");
            if outcome.config_saved {
                eprintln!("Configuration saved. Run: palladin status");
            } else {
                eprintln!("Existing working configuration was preserved.");
            }
            ExitCode::SUCCESS
        }
    }
}

async fn status(service: &RuntimeService<OsSecretStore>, profile: Option<&str>) -> ExitCode {
    let hostname = match hostname::get() {
        Ok(hostname) => hostname.to_string_lossy().into_owned(),
        Err(_) => return fail("the operating-system hostname is unavailable"),
    };
    let outcome = match service.status(profile, &hostname).await {
        Ok(outcome) => outcome,
        Err(error) => return fail(&error.to_string()),
    };
    println!("Profile: {}", outcome.profile.name);
    println!("Host: {}", outcome.config.host);
    println!("Security: {}", convenience_tier_description());
    match outcome.registration {
        AgentRegistrationResult::Pending { agent_id } => {
            println!(
                "Agent: pending approval ({})",
                shorten_identifier(&agent_id)
            );
            ExitCode::SUCCESS
        }
        AgentRegistrationResult::Active { agent_id, name } => {
            println!("Agent: active ({})", shorten_identifier(&agent_id));
            if let Some(name) = name {
                println!("Backend name: {name}");
            }
            ExitCode::SUCCESS
        }
        AgentRegistrationResult::Deactivated { agent_id } => {
            println!("Agent: deactivated ({})", shorten_identifier(&agent_id));
            ExitCode::SUCCESS
        }
        AgentRegistrationResult::InvalidKey => fail("API key is invalid or revoked"),
        AgentRegistrationResult::Unreachable { error } => {
            fail(&format!("server unreachable ({error})"))
        }
    }
}

fn agents(service: &RuntimeService<OsSecretStore>, command: AgentsCommand) -> ExitCode {
    match agents_result(service, command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&error.to_string()),
    }
}

fn agents_result(
    service: &RuntimeService<OsSecretStore>,
    command: AgentsCommand,
) -> Result<(), RuntimeError> {
    match command {
        AgentsCommand::List => {
            let registry = service.registry()?;
            if registry.agents.is_empty() {
                println!("No agents. Run: palladin agents create <name>");
            } else {
                for agent in registry.agents {
                    let marker = if agent.name == registry.default {
                        "*"
                    } else {
                        " "
                    };
                    println!("{marker} {}", agent.name);
                }
            }
            Ok(())
        }
        AgentsCommand::Create { name, r#type } => {
            let created = service.create_profile(&name, r#type)?;
            println!("Agent profile created: {}", created.name);
            println!(
                "Encryption key: {}",
                shorten_identifier(&created.encryption_public_key)
            );
            println!(
                "Signing key: {}",
                shorten_identifier(&created.signing_public_key)
            );
            println!("Security: {}", convenience_tier_description());
            println!("Next: palladin --id {} connect", created.name);
            Ok(())
        }
        AgentsCommand::Delete { name } => {
            service.delete_profile(&name)?;
            println!("Agent profile deleted: {name}");
            Ok(())
        }
        AgentsCommand::SetDefault { name } => {
            service.set_default_profile(&name)?;
            println!("Default Agent profile: {name}");
            Ok(())
        }
        AgentsCommand::Rename { old_name, new_name } => {
            service.rename_profile(&old_name, &new_name)?;
            println!("Agent profile renamed: {old_name} -> {new_name}");
            Ok(())
        }
    }
}

fn purge(service: &RuntimeService<OsSecretStore>, confirm: bool) -> ExitCode {
    if !confirm {
        return fail("purge requires --confirm and is never run automatically");
    }
    match service.purge() {
        Ok(()) => {
            println!("Native Palladin profiles and secret slots purged.");
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error.to_string()),
    }
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
    std::env::args_os().skip(1).any(|argument| {
        argument
            .to_str()
            .is_some_and(|value| value.starts_with("pl_"))
    })
}

fn fail(message: &str) -> ExitCode {
    eprintln!("Error: {message}");
    ExitCode::from(EXIT_FAILURE)
}

fn print_unsafe_environment(environment: &EnvironmentReport) {
    println!(
        "dangerous-variable-names: {}",
        environment.dangerous_names().join(",")
    );
}
